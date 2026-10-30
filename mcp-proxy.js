/**
 * Paean Cloudflare MCP server — your own MCP endpoint on a Worker.
 *
 * mcp.cloudflare.com/mcp answers 401 `realm="OAuth"`, which a browser page can
 * never satisfy. This Worker removes the middleman: it IS the MCP server, sends
 * its own CORS, and holds CF_API_TOKEN as a secret the page never sees.
 *
 * Coverage: 26 tools — accounts/zones, Workers (scripts, routes, domains),
 * KV, R2, D1, Queues, Pages, DNS, cache, rulesets/WAF, load balancers,
 * Email Routing, Access, Logpush, Turnstile, AI Gateway, user tokens, plus
 * cf_api (any API v4 path) and cf_graphql. The official remote servers wrap
 * this same REST API, so nothing is out of reach.
 *
 * Two locks: BRIDGE_TOKEN (secret, required — unset means every request is
 * refused) and ORIGIN_ALLOWLIST (var, optional).
 */

const API = 'https://api.cloudflare.com/client/v4';
const PROTOCOL = '2025-06-18';
const INFO = { name: 'paean-cloudflare-mcp', version: '2.0.0' };
const TIMEOUT = 25000;
const MAX = 60000;
const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'];

/* /__fetch: CORS-friendly read proxy for the assistant's Web fetch tool. */
const FETCH_TIMEOUT_MS = 15000;
const FETCH_MAX_BYTES = 1500000;

/* /__fetch writes: a JSON envelope, its own switch, and its own limits. */
const WRITE_METHODS = ['POST', 'PUT', 'PATCH', 'DELETE'];
const WRITE_MAX_BYTES = 512000;
const WRITE_MAX_HEADERS = 20;
const WRITE_MAX_HEADER_VALUE = 2000;

/** Headers the caller may not set: the runtime builds them, or they belong to the hop. */
const WRITE_FORBIDDEN_HEADERS = [
  'host',
  'content-length',
  'connection',
  'transfer-encoding',
  'accept-encoding',
  'cookie',
  'cookie2',
  'set-cookie',
  'cf-connecting-ip',
  'x-forwarded-for',
  'x-real-ip',
];

/* ---------- worker entry ---------- */

export default {
  /** @param {Request} request @param {Record<string, any>} env */
  async fetch(request, env) {
    const cfg = cfgOf(env);
    const origin = request.headers.get('Origin') || '';

    // Answer preflight even for a refused origin: a CORS error is clearer than
    // an opaque network error.
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: cors(origin, originOk(origin, cfg.origins)) });
    }
    if (!originOk(origin, cfg.origins)) {
      return json({ ok: false, error: 'origin not allowed: ' + (origin || '(none)') }, 403, origin);
    }

    // A separate read-only route, not an MCP tool: the app's Web fetch setting
    // only knows a URL, so this endpoint must answer a plain GET.
    const url = new URL(request.url);
    if (url.pathname.endsWith('/__fetch')) return handleFetch(request, url, cfg, origin);

    // Opening the URL prints health. Never prints a secret value.
    if (request.method !== 'POST') {
      return json(
        {
          ok: true,
          server: INFO.name,
          version: INFO.version,
          endpoint: 'POST this URL with JSON-RPC 2.0 (MCP streamable HTTP)',
          protocolVersion: PROTOCOL,
          tools: TOOLS.length,
          fetchEnabled: cfg.fetchEnabled,
          fetchWriteEnabled: cfg.writeEnabled,
          credentials: {
            bridgeTokenConfigured: Boolean(cfg.bridge),
            cloudflareTokenConfigured: Boolean(cfg.api),
            originAllowlist: cfg.origins.length ? cfg.origins : 'any (open)',
            defaultAccount: cfg.account || '(none)',
          },
        },
        200,
        origin
      );
    }

    // Fail closed: a Worker holding a Cloudflare token must never be open by luck.
    if (!cfg.bridge) {
      return rpcError(-32001, 'BRIDGE_TOKEN is not set on this Worker. Set it, then use the same value as the Token field in the app.', 500, origin);
    }
    if (!presented(request).includes(cfg.bridge)) {
      return rpcError(-32001, 'unauthorized: wrong or missing bridge token', 401, origin);
    }
    if (!cfg.api) return rpcError(-32002, 'CF_API_TOKEN is not set on this Worker.', 500, origin);

    let body;
    try {
      body = await request.json();
    } catch {
      return rpcError(-32700, 'parse error: the body is not JSON', 400, origin);
    }

    const batch = Array.isArray(body) ? body : [body];
    const replies = [];
    let session = request.headers.get('Mcp-Session-Id') || '';

    for (const msg of batch) {
      if (!msg || typeof msg !== 'object') continue;
      if (msg.id === undefined || msg.id === null) continue; // notifications get no reply
      const answer = await handle(msg, cfg);
      if (msg.method === 'initialize' && answer.result) session = crypto.randomUUID();
      replies.push(answer);
    }

    const headers = { ...cors(origin, true), 'Cache-Control': 'no-store' };
    if (session) headers['Mcp-Session-Id'] = session;

    // A pure-notification batch gets 202 with no body, per the transport spec.
    if (!replies.length) return new Response(null, { status: 202, headers });

    headers['Content-Type'] = 'application/json; charset=utf-8';
    return new Response(JSON.stringify(Array.isArray(body) ? replies : replies[0]), { status: 200, headers });
  },
};

/* ---------- fetch proxy (/__fetch) ---------- */

/**
 * GET /__fetch?url=<encoded http(s) URL>
 *
 * Read-only, answers with CORS headers, refuses private/link-local targets and
 * calls out to a redirect that lands on one. This is a convenience for the
 * assistant's Web fetch tool, not an MCP tool, so it has its own optional
 * FETCH_TOKEN lock and never touches CF_API_TOKEN.
 */
async function handleFetch(request, url, cfg, origin) {
  if (!cfg.fetchEnabled) {
    return json({ ok: false, error: 'FETCH_ENABLED=0 disables /__fetch.' }, 404, origin);
  }
  if (cfg.fetchToken && request.headers.get('X-Fetch-Token') !== cfg.fetchToken) {
    return json({ ok: false, error: 'this proxy wants X-Fetch-Token (see FETCH_TOKEN) and the request did not carry it.' }, 401, origin);
  }
  // GET reads; the four write methods write. A write carries its payload as a
  // JSON envelope, so a form post is described explicitly instead of guessed.
  const isWrite = WRITE_METHODS.indexOf(request.method) >= 0;
  if (request.method !== 'GET' && !isWrite) {
    return json(
      {
        ok: false,
        error: '/__fetch reads with GET and writes with ' + WRITE_METHODS.join(', ') + '. ' + request.method + ' is neither.',
      },
      405,
      origin
    );
  }

  const target = String(url.searchParams.get('url') || '').trim();
  if (!target) {
    return json({ ok: false, error: 'no url given. Call /__fetch?url=<encoded http(s) URL>.' }, 400, origin);
  }

  let parsed;
  try {
    parsed = new URL(target);
  } catch (err) {
    return json({ ok: false, error: 'that is not a URL: ' + target.slice(0, 200) }, 400, origin);
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return json({ ok: false, error: 'only http and https are readable; ' + parsed.protocol + ' is not' }, 400, origin);
  }
  if (isPrivateHost(parsed.hostname)) {
    return json(
      { ok: false, error: 'refused: ' + parsed.hostname + ' is a local, private or link-local address. This proxy is not a way into a private network.' },
      400,
      origin
    );
  }

  // Always present a browser UA by default: forwarding the caller's UA means a
  // programmatic client (curl, node, undici) announces itself and gets blocked.
  // X-Fetch-User-Agent or ?ua= overrides it when a specific UA is needed.
  const userAgent =
    String(request.headers.get('X-Fetch-User-Agent') || url.searchParams.get('ua') || '').trim() ||
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';
  if (/[\r\n]/.test(userAgent)) return json({ ok: false, error: 'User-Agent contains a newline' }, 400, origin);
  if (userAgent.length > 512) return json({ ok: false, error: 'User-Agent is too long' }, 400, origin);

  // A clearance cookie is the only way through a JS challenge, but it is bound
  // to the browser's IP as well as its UA, so a Worker egress IP will usually
  // still be refused. Header wins; query is a fallback for tools that can only
  // take a URL. Never echoed back in the response.
  const cookie = String(request.headers.get('X-Fetch-Cookie') || url.searchParams.get('cookie') || '').trim();
  if (/[\r\n]/.test(cookie)) return json({ ok: false, error: 'cookie contains a newline' }, 400, origin);
  if (cookie.length > 8192) return json({ ok: false, error: 'cookie is too large (max 8192 characters)' }, 400, origin);

  const referer = String(request.headers.get('X-Fetch-Referer') || '').trim();
  if (referer && !/^https?:\/\//i.test(referer)) {
    return json({ ok: false, error: 'X-Fetch-Referer must be an http(s) URL' }, 400, origin);
  }

  /** Browser-like defaults, so a target does not see a bare Worker request. */
  const requestHeaders = {
    Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'Accept-Language': String(request.headers.get('Accept-Language') || 'en-US,en;q=0.9').trim(),
    'User-Agent': userAgent,
    'sec-ch-ua': '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'none',
    'Sec-Fetch-User': '?1',
    'Upgrade-Insecure-Requests': '1',
  };
  if (cookie) requestHeaders.Cookie = cookie;
  if (referer) requestHeaders.Referer = referer;

  if (isWrite) return writeProxy(request, parsed, cfg, origin, requestHeaders);

  let res;
  try {
    res = await fetch(parsed.href, {
      method: 'GET',
      redirect: 'follow',
      headers: requestHeaders,
      signal: timeoutSignal(FETCH_TIMEOUT_MS),
    });
  } catch (err) {
    const timedOut = /timeout|aborted/i.test(String((err && err.name) || '') + ' ' + String((err && err.message) || ''));
    return json(
      {
        ok: false,
        status: 0,
        error: timedOut
          ? 'the target site did not answer within ' + Math.round(FETCH_TIMEOUT_MS / 1000) + 's. The Worker gave up so the page is not left hanging.'
          : 'the Worker could not reach ' + parsed.hostname + ': ' + String((err && err.message) || err) + '. That is a Worker-side network failure, not CORS.',
      },
      502,
      origin
    );
  }

  // Redirects are checked too: a public URL that lands on 10.0.0.5 must not
  // become a private read.
  let finalUrl = parsed.href;
  try {
    if (res.url) {
      finalUrl = res.url;
      const landed = new URL(res.url);
      if (isPrivateHost(landed.hostname)) {
        return json({ ok: false, status: 0, error: 'refused: the site redirected to ' + landed.hostname + ', a private address.' }, 400, origin);
      }
    }
  } catch (err) {
    /* an unparseable final URL is not worth failing the read over */
  }

  const contentType = String(res.headers.get('Content-Type') || '');
  let bytes;
  try {
    bytes = new Uint8Array(await res.arrayBuffer());
  } catch (err) {
    return json({ ok: false, status: res.status, error: 'the body could not be read: ' + String((err && err.message) || err) }, 502, origin);
  }

  const truncated = bytes.byteLength > FETCH_MAX_BYTES;
  const kept = truncated ? bytes.subarray(0, FETCH_MAX_BYTES) : bytes;
  const text = new TextDecoder('utf-8').decode(kept);
  const binary = /^(image|audio|video|font)\/|^application\/(zip|pdf|octet-stream|gzip)/i.test(contentType);

  return json(
    {
      ok: true,
      status: res.status,
      url: parsed.href,
      finalUrl,
      contentType,
      bytes: bytes.byteLength,
      truncated,
      binary,
      note: binary
        ? 'this is binary content decoded as text, so it is not usable as a file. Read text instead, or download the file in its own tab.'
        : truncated
          ? 'only the first ' + FETCH_MAX_BYTES + ' bytes were kept'
          : undefined,
      text,
    },
    200,
    origin
  );
}

/* ---------- /__fetch: writes ---------- */

/**
 * POST /__fetch?url=... with a JSON envelope:
 *   {"method":"POST","headers":{},"body":"...","contentType":"application/json"}
 *
 * A cross-origin POST is refused before it is sent, so a write has to leave from
 * the Worker too. It is narrower than the read: its own switch, a method
 * allowlist, a sanitised header map, a smaller body ceiling, and no retry
 * (a duplicated POST creates a second record).
 */
async function writeProxy(request, parsed, cfg, origin, baseHeaders) {
  if (!cfg.writeEnabled) {
    return json(
      {
        ok: false,
        sent: false,
        error: 'this proxy has FETCH_WRITE_ENABLED=0, so /__fetch only reads. Remove that variable to allow writes again.',
      },
      403,
      origin
    );
  }

  let envelope;
  try {
    envelope = await request.json();
  } catch (err) {
    return json(
      {
        ok: false,
        sent: false,
        error: 'a write needs a JSON envelope in the body: {"method":"POST","headers":{},"body":"...","contentType":"application/json"}. Nothing was sent.',
      },
      400,
      origin
    );
  }
  if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope)) {
    return json({ ok: false, sent: false, error: 'the write envelope must be a JSON object. Nothing was sent.' }, 400, origin);
  }

  const method = String(envelope.method || request.method || 'POST').toUpperCase();
  if (WRITE_METHODS.indexOf(method) < 0) {
    return json(
      { ok: false, sent: false, error: 'method must be one of ' + WRITE_METHODS.join(', ') + '; ' + method + ' is not. Nothing was sent.' },
      400,
      origin
    );
  }

  const checked = sanitiseWriteHeaders(envelope.headers);
  if (!checked.ok) {
    return json({ ok: false, sent: false, error: checked.error + ' Nothing was sent.' }, 400, origin);
  }

  const body = String(envelope.body == null ? '' : envelope.body);
  if (body.length > WRITE_MAX_BYTES) {
    return json(
      {
        ok: false,
        sent: false,
        error: 'the body is ' + body.length + ' characters; this route sends at most ' + WRITE_MAX_BYTES + '. Nothing was sent.',
      },
      413,
      origin
    );
  }

  const contentType = String(envelope.contentType || '').trim();
  const headers = {
    ...writeRequestHeaders(baseHeaders),
    ...(contentType ? { 'Content-Type': contentType } : {}),
    // Caller headers last: an explicit Content-Type there wins over the envelope field.
    ...checked.headers,
  };

  let res;
  try {
    res = await fetch(parsed.href, {
      method,
      redirect: 'follow',
      headers,
      body,
      signal: timeoutSignal(FETCH_TIMEOUT_MS),
    });
  } catch (err) {
    const timedOut = /timeout|aborted/i.test(String((err && err.name) || '') + ' ' + String((err && err.message) || ''));
    return json(
      {
        ok: false,
        method,
        status: 0,
        // A timeout may have been applied; a DNS/connection failure never left.
        // Guessing either way is wrong: one invites a duplicate POST, the other
        // forbids a safe retry.
        sent: timedOut ? 'unknown' : false,
        error: timedOut
          ? 'the target site did not answer within ' +
            Math.round(FETCH_TIMEOUT_MS / 1000) +
            's. The Worker gave up, so whether this write was applied is unknown — check the target before retrying.'
          : 'the Worker could not reach ' +
            parsed.hostname +
            ': ' +
            String((err && err.message) || err) +
            '. The request did not leave the Worker, so it is safe to send again.',
      },
      502,
      origin
    );
  }

  // A redirect is followed, so its target is checked too: a write must not be
  // bounced into a private network any more than a read may be.
  let finalUrl = parsed.href;
  try {
    if (res.url) {
      finalUrl = res.url;
      const landed = new URL(res.url);
      if (isPrivateHost(landed.hostname)) {
        return json(
          {
            ok: false,
            method,
            status: 0,
            sent: 'unknown',
            error: 'refused: the site redirected to ' + landed.hostname + ', a private address.',
          },
          400,
          origin
        );
      }
    }
  } catch (err) {
    /* an unparseable final URL is not worth failing the write over */
  }

  const responseType = String(res.headers.get('Content-Type') || '');
  let bytes;
  try {
    bytes = new Uint8Array(await res.arrayBuffer());
  } catch (err) {
    return json(
      {
        ok: false,
        method,
        status: res.status,
        sent: true,
        delivered: true,
        error: 'the write was sent (HTTP ' + res.status + ') but its reply could not be read: ' + String((err && err.message) || err),
      },
      502,
      origin
    );
  }

  const truncated = bytes.byteLength > FETCH_MAX_BYTES;
  const kept = truncated ? bytes.subarray(0, FETCH_MAX_BYTES) : bytes;
  const text = new TextDecoder('utf-8').decode(kept);
  const binary = /^(image|audio|video|font)\//i.test(responseType);

  return json(
    {
      ok: true,
      method,
      status: res.status,
      sent: true,
      url: parsed.href,
      finalUrl,
      contentType: responseType,
      bytes: bytes.byteLength,
      truncated,
      binary,
      sentChars: body.length,
      ua: baseHeaders['User-Agent'],
      note: binary
        ? 'the reply is binary and was decoded as text, so it is not usable here. The write itself was sent — check the target.'
        : truncated
          ? 'only the first ' + FETCH_MAX_BYTES + ' bytes of the reply were kept'
          : res.status >= 400
            ? 'the server refused the write with HTTP ' + res.status + '; its answer is in text'
            : undefined,
      text,
    },
    200,
    origin
  );
}

/**
 * Browser profile minus the parts that describe a navigation. `sec-fetch-mode:
 * navigate` and `upgrade-insecure-requests` on a POST describe something that
 * did not happen; UA, client hints and Accept-Language stay because they are
 * true of any request from the same client.
 */
function writeRequestHeaders(base) {
  const out = {};
  for (const key of Object.keys(base)) {
    const lower = key.toLowerCase();
    if (lower.indexOf('sec-fetch') === 0) continue;
    if (lower === 'upgrade-insecure-requests') continue;
    out[key] = base[key];
  }
  out.Accept = 'application/json, text/plain, */*';
  return out;
}

/** Validate caller headers instead of trusting them. */
function sanitiseWriteHeaders(raw) {
  if (raw == null) return { ok: true, headers: {} };
  if (typeof raw !== 'object' || Array.isArray(raw)) {
    return { ok: false, headers: {}, error: 'headers must be a JSON object of name/value pairs.' };
  }
  const keys = Object.keys(raw);
  if (keys.length > WRITE_MAX_HEADERS) {
    return {
      ok: false,
      headers: {},
      error: 'too many headers (' + keys.length + '); the limit is ' + WRITE_MAX_HEADERS + '.',
    };
  }
  const headers = {};
  for (const key of keys) {
    const name = String(key).trim();
    if (!name) continue;
    if (/[\r\n]/.test(name)) {
      return { ok: false, headers: {}, error: 'a header name cannot contain a newline.' };
    }
    if (WRITE_FORBIDDEN_HEADERS.indexOf(name.toLowerCase()) >= 0) {
      return {
        ok: false,
        headers: {},
        error:
          name +
          ' cannot be set by the caller: it describes this request or this connection, and the runtime builds it. Drop it.',
      };
    }
    const value = String(raw[key] == null ? '' : raw[key]);
    if (/[\r\n]/.test(value)) {
      return { ok: false, headers: {}, error: 'header ' + name + ' contains a newline, which is how a header gets injected.' };
    }
    if (value.length > WRITE_MAX_HEADER_VALUE) {
      return {
        ok: false,
        headers: {},
        error: 'header ' + name + ' is longer than ' + WRITE_MAX_HEADER_VALUE + ' characters.',
      };
    }
    headers[name] = value;
  }
  return { ok: true, headers };
}

/* ---------- host safety ---------- */

/** Loopback, private, link-local and internal names are not readable. */
function isPrivateHost(hostname) {
  const h = String(hostname || '').toLowerCase().replace(/^\[|\]$/g, '');
  if (!h) return true;
  if (h === 'localhost' || h.endsWith('.localhost')) return true;
  if (h.endsWith('.internal') || h.endsWith('.local')) return true;
  if (h === 'metadata.google.internal') return true;
  const v4 = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (v4) {
    const [a, b] = [Number(v4[1]), Number(v4[2])];
    if (a === 0 || a === 10 || a === 127) return true;
    if (a === 169 && b === 254) return true; // link-local + cloud metadata
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true; // carrier NAT
  }
  if (h === '::1' || h === '::') return true;
  if (/^fc/.test(h) || /^fd/.test(h) || /^fe80/.test(h)) return true;
  return false;
}

function timeoutSignal(ms) {
  try {
    if (typeof AbortSignal !== 'undefined' && typeof AbortSignal.timeout === 'function') return AbortSignal.timeout(ms);
  } catch (err) {
    /* fall through */
  }
  if (typeof AbortController === 'undefined') return undefined;
  const c = new AbortController();
  setTimeout(() => c.abort(), ms);
  return c.signal;
}

/* ---------- config ---------- */

function cfgOf(env) {
  const e = env || {};
  const list = (v) => String(v || '').split(/[,\s]+/).map((s) => s.trim()).filter(Boolean);
  return {
    origins: list(e.ORIGIN_ALLOWLIST),
    bridge: String(e.BRIDGE_TOKEN || '').trim(),
    api: String(e.CF_API_TOKEN || '').trim(),
    account: String(e.CF_ACCOUNT_ID || '').trim(),
    fetchEnabled: String(e.FETCH_ENABLED == null ? '1' : e.FETCH_ENABLED).trim() !== '0',
    writeEnabled: String(e.FETCH_WRITE_ENABLED == null ? '1' : e.FETCH_WRITE_ENABLED).trim() !== '0',
    fetchToken: String(e.FETCH_TOKEN || '').trim(),
  };
}

function originOk(origin, allow) {
  if (!allow.length) return true;
  if (!origin) return true; // non-browser client, nothing to spoof
  const o = origin.toLowerCase();
  return allow.some((a) => a.toLowerCase() === o || a === '*');
}

function cors(origin, allowed) {
  const h = {
    'Access-Control-Allow-Methods': 'POST, GET, PUT, PATCH, DELETE, OPTIONS',
    'Access-Control-Allow-Headers':
      'Content-Type, Accept, Authorization, X-Bridge-Token, X-Fetch-Token, X-Fetch-Cookie, X-Fetch-Referer, X-Fetch-User-Agent, Mcp-Session-Id, MCP-Protocol-Version',
    'Access-Control-Expose-Headers': 'Mcp-Session-Id, MCP-Protocol-Version, WWW-Authenticate',
    'Access-Control-Max-Age': '86400',
    Vary: 'Origin',
  };
  if (allowed) h['Access-Control-Allow-Origin'] = origin || '*';
  return h;
}

function json(obj, status, origin) {
  return new Response(JSON.stringify(obj, null, 2), {
    status: status || 200,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...cors(origin, true) },
  });
}

function rpcError(code, message, status, origin) {
  return json({ jsonrpc: '2.0', id: null, error: { code, message } }, status, origin);
}

/** The bridge token may arrive as a bearer or as an explicit header. */
function presented(request) {
  const bearer = String(request.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '').trim();
  const direct = String(request.headers.get('X-Bridge-Token') || '').trim();
  const key = String(request.headers.get('X-Api-Key') || '').trim();
  return [bearer, direct, key].filter(Boolean);
}

/* ---------- JSON-RPC ---------- */

async function handle(msg, cfg) {
  const id = msg.id;

  if (msg.method === 'initialize') {
    return {
      jsonrpc: '2.0',
      id,
      result: {
        protocolVersion: PROTOCOL,
        capabilities: { tools: { listChanged: false } },
        serverInfo: INFO,
        instructions:
          'Cloudflare account tools. Read actions are safe; create/update/delete/attach/rollback actions, cf_deploy, cf_dns writes, cf_purge, cf_kv writes and mutating cf_api calls change the account and need explicit user intent. Use cf_whoami or cf_token_scopes first if anything returns 401/403.',
      },
    };
  }
  if (msg.method === 'ping') return { jsonrpc: '2.0', id, result: {} };
  if (msg.method === 'tools/list') return { jsonrpc: '2.0', id, result: { tools: TOOLS } };

  if (msg.method === 'tools/call') {
    const params = msg.params || {};
    const name = String(params.name || '');
    if (!TOOLS.some((x) => x.name === name)) {
      return { jsonrpc: '2.0', id, error: { code: -32602, message: 'unknown tool: ' + name } };
    }
    try {
      return { jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: await runTool(name, params.arguments || {}, cfg) }] } };
    } catch (err) {
      // A tool failure is data the model should read, not a transport error.
      return { jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: 'tool failed: ' + msgOf(err) }], isError: true } };
    }
  }

  return { jsonrpc: '2.0', id, error: { code: -32601, message: 'method not found: ' + String(msg.method) } };
}

/* ---------- tool catalogue ---------- */

const S = (description) => ({ type: 'string', description });

function t(name, description, properties, required) {
  return {
    name,
    description,
    inputSchema: { type: 'object', properties: properties || {}, ...(required ? { required } : {}), additionalProperties: false },
  };
}

const TOOLS = [
  t('cf_whoami', 'Verify the stored Cloudflare token: is it valid, and which accounts can it reach? Call this first when something returns 403.', {}),
  t('cf_accounts', 'List Cloudflare accounts (id + name). Account ids are needed by the Workers, KV and Pages tools.', {}),
  t('cf_zones', 'List zones (domains): id, name, status, name_servers. Zone ids are needed by DNS, cache and ruleset calls.', {
    name: S('Optional exact domain, e.g. example.com'),
  }),
  t('cf_workers', 'List Worker scripts in an account with their last-modified time.', {
    account_id: S('Account id; defaults to CF_ACCOUNT_ID'),
  }),
  t('cf_deploy', 'Create or overwrite a Worker script from ES-module source. Writes to the account.', {
    account_id: S('Account id; defaults to CF_ACCOUNT_ID'),
    script_name: S('Worker name, e.g. my-worker'),
    source: S('Full ES module source containing `export default { fetch }`'),
    compatibility_date: S('Defaults to 2025-06-18'),
    bindings: {
      type: 'array',
      description: 'Optional plain-text bindings',
      items: { type: 'object', properties: { name: S(''), text: S('') }, required: ['name', 'text'] },
    },
  }, ['script_name', 'source']),
  t('cf_dns', 'DNS records of a zone. action=list|create|update|delete.', {
    action: { type: 'string', enum: ['list', 'create', 'update', 'delete'] },
    zone_id: S('Zone id from cf_zones'),
    record_id: S('Required for update and delete'),
    type: S('A, AAAA, CNAME, TXT, MX, ...'),
    name: S('Record name, e.g. www.example.com'),
    content: S('Record value'),
    proxied: { type: 'boolean' },
    ttl: { type: 'number', description: '1 = automatic' },
  }, ['action', 'zone_id']),
  t('cf_kv', 'KV storage. action=namespaces|list|get|put|delete-key|delete-namespace.', {
    action: { type: 'string', enum: ['namespaces', 'list', 'get', 'put', 'delete-key', 'delete-namespace'] },
    account_id: S('Account id; defaults to CF_ACCOUNT_ID'),
    namespace_id: S('Required except for action=namespaces'),
    key: S('Key name, required for get/put/delete-key'),
    value: S('Value to store, required for put'),
  }, ['action']),
  t('cf_purge', 'Purge cache for a zone: everything=true, or a list of urls.', {
    zone_id: S('Zone id from cf_zones'),
    everything: { type: 'boolean', description: 'true = purge the whole cache' },
    urls: { type: 'array', items: { type: 'string' }, description: 'Specific URLs to purge' },
  }, ['zone_id']),
  t('cf_pages', 'List Pages projects in an account with their domains and latest deployment.', {
    account_id: S('Account id; defaults to CF_ACCOUNT_ID'),
  }),
  t('cf_graphql', 'Run a Cloudflare Analytics GraphQL query (httpRequestsAdaptiveGroups, workersInvocationsAdaptive, ...).', {
    query: S('GraphQL query string'),
    variables: { type: 'object' },
  }, ['query']),
  t('cf_api', 'Escape hatch: any Cloudflare API v4 path with the stored token. This is what covers products with no named tool above.', {
    method: { type: 'string', enum: METHODS },
    path: S('Path after /client/v4, e.g. /accounts/{id}/r2/buckets'),
    body: { type: 'object', description: 'JSON body for POST/PUT/PATCH' },
  }, ['path']),

  t('cf_token_scopes', 'Inspect the stored token: verify it, then show its permission groups per resource scope.', {}),

  t('cf_r2', 'R2 buckets. action=list|create|delete.', {
    action: { type: 'string', enum: ['list', 'create', 'delete'] },
    account_id: S('Account id; defaults to CF_ACCOUNT_ID'),
    name: S('Bucket name, required for create and delete'),
    location: S('Optional location hint, e.g. apac'),
  }, ['action']),

  t('cf_d1', 'D1 databases. action=list|create|delete|query.', {
    action: { type: 'string', enum: ['list', 'create', 'delete', 'query'] },
    account_id: S('Account id; defaults to CF_ACCOUNT_ID'),
    database_id: S('Database id, required for delete and query'),
    name: S('Database name, required for create'),
    sql: S('SQL text, required for query'),
    params: { type: 'array', items: {}, description: 'Optional bound parameters for query' },
  }, ['action']),

  t('cf_queues', 'Queues. action=list|create|delete.', {
    action: { type: 'string', enum: ['list', 'create', 'delete'] },
    account_id: S('Account id; defaults to CF_ACCOUNT_ID'),
    queue_id: S('Queue id, required for delete'),
    queue_name: S('Queue name, required for create'),
  }, ['action']),

  t('cf_worker_routes', 'Zone Worker routes. action=list|create|delete.', {
    action: { type: 'string', enum: ['list', 'create', 'delete'] },
    zone_id: S('Zone id from cf_zones'),
    route_id: S('Required for delete'),
    pattern: S('Route pattern, e.g. example.com/*'),
    script: S('Worker script name for create'),
  }, ['action', 'zone_id']),

  t('cf_worker_domains', 'Workers custom domains on the account. action=list|attach|detach.', {
    action: { type: 'string', enum: ['list', 'attach', 'detach'] },
    account_id: S('Account id; defaults to CF_ACCOUNT_ID'),
    domain_id: S('Required for detach'),
    zone_id: S('Zone id for attach'),
    hostname: S('Hostname for attach, e.g. api.example.com'),
    service: S('Worker script name for attach'),
    environment: S('Worker environment, default production'),
  }, ['action']),

  t('cf_pages_deployments', 'Pages deployments. action=list|retry|rollback.', {
    action: { type: 'string', enum: ['list', 'retry', 'rollback'] },
    account_id: S('Account id; defaults to CF_ACCOUNT_ID'),
    project: S('Pages project name'),
    deployment_id: S('Required for retry and rollback'),
  }, ['action', 'project']),

  t('cf_zone_settings', 'Zone settings. action=list|get|set.', {
    action: { type: 'string', enum: ['list', 'get', 'set'] },
    zone_id: S('Zone id from cf_zones'),
    setting: S('Setting id, e.g. ssl, always_use_https'),
    value: { description: 'New value for set (string, number, or boolean)' },
  }, ['action', 'zone_id']),

  t('cf_rulesets', 'Rulesets (WAF/custom). action=list|get|create|update|delete|entrypoint, scope=account|zone.', {
    action: { type: 'string', enum: ['list', 'get', 'create', 'update', 'delete', 'entrypoint'] },
    scope: { type: 'string', enum: ['account', 'zone'] },
    account_id: S('Account id when scope=account; defaults to CF_ACCOUNT_ID'),
    zone_id: S('Zone id when scope=zone'),
    ruleset_id: S('Required for get, update, delete'),
    phase: S('Phase for entrypoint, e.g. http_request_firewall_custom'),
    body: { type: 'object', description: 'Ruleset payload for create/update/entrypoint' },
  }, ['action', 'scope']),

  t('cf_load_balancer', 'Load balancers. action=monitors|pools|list|create|update|delete.', {
    action: { type: 'string', enum: ['monitors', 'pools', 'list', 'create', 'update', 'delete'] },
    account_id: S('Account id; defaults to CF_ACCOUNT_ID'),
    zone_id: S('Zone id for list/create/update/delete'),
    id: S('Load balancer id for update/delete'),
    body: { type: 'object', description: 'Payload for create/update' },
  }, ['action']),

  t('cf_email_routing', 'Email Routing. action=rules|create-rule|delete-rule|addresses|catch-all|settings.', {
    action: { type: 'string', enum: ['rules', 'create-rule', 'delete-rule', 'addresses', 'catch-all', 'settings'] },
    zone_id: S('Zone id from cf_zones'),
    rule_id: S('Required for delete-rule'),
    body: { type: 'object', description: 'Rule payload for create-rule' },
  }, ['action', 'zone_id']),

  t('cf_access', 'Cloudflare Access apps. action=list|get|create|update|delete.', {
    action: { type: 'string', enum: ['list', 'get', 'create', 'update', 'delete'] },
    account_id: S('Account id; defaults to CF_ACCOUNT_ID'),
    app_id: S('Required for get, update, delete'),
    body: { type: 'object', description: 'App payload for create/update' },
  }, ['action']),

  t('cf_logpush', 'Logpush jobs. action=list|create|delete, scope=account|zone.', {
    action: { type: 'string', enum: ['list', 'create', 'delete'] },
    scope: { type: 'string', enum: ['account', 'zone'] },
    account_id: S('Account id when scope=account; defaults to CF_ACCOUNT_ID'),
    zone_id: S('Zone id when scope=zone'),
    job_id: S('Required for delete'),
    body: { type: 'object', description: 'Job payload for create' },
  }, ['action', 'scope']),

  t('cf_turnstile', 'Turnstile widgets. action=list|create|delete.', {
    action: { type: 'string', enum: ['list', 'create', 'delete'] },
    account_id: S('Account id; defaults to CF_ACCOUNT_ID'),
    sitekey: S('Widget sitekey, required for delete'),
    body: { type: 'object', description: 'Widget payload for create: name, domains, mode' },
  }, ['action']),

  t('cf_ai_gateway', 'AI Gateway. action=list|create|delete.', {
    action: { type: 'string', enum: ['list', 'create', 'delete'] },
    account_id: S('Account id; defaults to CF_ACCOUNT_ID'),
    gateway_id: S('Gateway id, required for delete'),
    body: { type: 'object', description: 'Gateway payload for create' },
  }, ['action']),
];

/* ---------- tool implementations ---------- */

async function runTool(name, args, cfg) {
  if (name === 'cf_whoami') {
    const verify = await cf('/user/tokens/verify', {}, cfg);
    const accounts = verify.ok ? await cf('/accounts', {}, cfg) : null;
    return out(
      [
        'token: ' + (verify.ok ? 'valid' : 'rejected'),
        'status: ' + verify.status,
        'detail: ' + clip(verify.text, 400),
        accounts ? 'accounts: ' + clip(accounts.text, 2000) : '',
      ]
        .filter(Boolean)
        .join('\n')
    );
  }

  if (name === 'cf_accounts') return out((await must(cf('/accounts', {}, cfg))).text);

  if (name === 'cf_zones') {
    const q = args.name ? '?name=' + encodeURIComponent(args.name) : '?per_page=50';
    return out((await must(cf('/zones' + q, {}, cfg))).text);
  }

  if (name === 'cf_workers') {
    return out((await must(cf('/accounts/' + acct(args, cfg) + '/workers/scripts', {}, cfg))).text);
  }

  if (name === 'cf_deploy') {
    const script = req(args, 'script_name');
    const source = String(args.source || '');
    if (!source.trim()) throw new Error('source is empty');
    const meta = { main_module: 'worker.js', compatibility_date: String(args.compatibility_date || '2025-06-18') };
    if (Array.isArray(args.bindings) && args.bindings.length) {
      meta.bindings = args.bindings
        .filter((b) => b && b.name)
        .map((b) => ({ type: 'plain_text', name: String(b.name), text: String(b.text == null ? '' : b.text) }));
    }
    // Multipart: a metadata part plus a module part named after main_module.
    const form = new FormData();
    form.append('metadata', new Blob([JSON.stringify(meta)], { type: 'application/json' }));
    form.append('worker.js', new Blob([source], { type: 'application/javascript+module' }), 'worker.js');
    const res = await cf('/accounts/' + acct(args, cfg) + '/workers/scripts/' + encodeURIComponent(script), { method: 'PUT', form }, cfg);
    return out((res.ok ? 'deployed ' + script : 'deploy failed') + '\nstatus: ' + res.status + '\ndetail: ' + clip(res.text, 3000));
  }

  if (name === 'cf_dns') {
    const zone = req(args, 'zone_id');
    const action = String(args.action || 'list');
    const base = '/zones/' + zone + '/dns_records';
    if (action === 'list') {
      const q = (args.type ? '?type=' + encodeURIComponent(args.type) : '?') + 'per_page=100';
      return out((await must(cf(base + q, {}, cfg))).text);
    }
    if (action === 'delete') return out((await must(cf(base + '/' + req(args, 'record_id'), { method: 'DELETE' }, cfg))).text);
    const body = { type: String(args.type || 'A'), name: req(args, 'name'), content: req(args, 'content') };
    if (typeof args.proxied === 'boolean') body.proxied = args.proxied;
    if (args.ttl != null) body.ttl = Number(args.ttl);
    if (action === 'create') return out((await must(cf(base, { method: 'POST', body }, cfg))).text);
    return out((await must(cf(base + '/' + req(args, 'record_id'), { method: 'PATCH', body }, cfg))).text);
  }

  if (name === 'cf_kv') {
    const account = acct(args, cfg);
    const action = String(args.action || 'namespaces');
    const root = '/accounts/' + account + '/storage/kv/namespaces';
    if (action === 'namespaces') return out((await must(cf(root, {}, cfg))).text);
    const ns = root + '/' + req(args, 'namespace_id');
    if (action === 'list') return out((await must(cf(ns + '/keys?limit=100', {}, cfg))).text);
    const key = encodeURIComponent(req(args, 'key'));
    if (action === 'get') return out((await must(cf(ns + '/values/' + key, {}, cfg))).text);
    if (action === 'put') {
      const res = await cf(ns + '/values/' + key, { method: 'PUT', raw: String(args.value == null ? '' : args.value) }, cfg);
      return out('status: ' + res.status + '\n' + clip(res.text, 500));
    }
    if (action === 'delete-key') return out((await must(cf(ns + '/values/' + key, { method: 'DELETE' }, cfg))).text);
    return out((await must(cf(ns, { method: 'DELETE' }, cfg))).text);
  }

  if (name === 'cf_purge') {
    const body = args.everything ? { purge_everything: true } : { files: Array.isArray(args.urls) ? args.urls : [] };
    if (!body.purge_everything && !body.files.length) throw new Error('pass everything=true or a non-empty urls array');
    return out((await must(cf('/zones/' + req(args, 'zone_id') + '/purge_cache', { method: 'POST', body }, cfg))).text);
  }

  if (name === 'cf_pages') {
    return out((await must(cf('/accounts/' + acct(args, cfg) + '/pages/projects', {}, cfg))).text);
  }

  if (name === 'cf_graphql') {
    const res = await fetch('https://api.cloudflare.com/client/v4/graphql', {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + cfg.api, 'Content-Type': 'application/json' },
      body: JSON.stringify({ query: String(args.query || ''), variables: args.variables || {} }),
      signal: AbortSignal.timeout(TIMEOUT),
    });
    const text = await res.text();
    return out('status: ' + res.status + '\n' + clip(text, MAX));
  }

  if (name === 'cf_api') {
    const method = String(args.method || 'GET').toUpperCase();
    if (!METHODS.includes(method)) throw new Error('method not allowed: ' + method);
    const path = String(args.path || '').trim();
    // A path, never a URL: this Worker stays pinned to api.cloudflare.com.
    if (!path.startsWith('/') || path.startsWith('//')) throw new Error('path must start with a single /');
    const res = await cf(path, { method, body: args.body }, cfg);
    return out('status: ' + res.status + '\n' + clip(res.text, MAX));
  }

  if (name === 'cf_token_scopes') {
    const verify = await cf('/user/tokens/verify', {}, cfg);
    let id = '';
    try {
      const parsed = JSON.parse(verify.text);
      id = String((parsed && parsed.result && parsed.result.id) || '');
    } catch (err) {
      id = '';
    }
    const detail = id ? await cf('/user/tokens/' + id, {}, cfg) : null;
    return out(
      'verify status: ' + verify.status + '\n' + clip(verify.text, 800) +
        (detail ? '\n\ntoken detail:\n' + clip(detail.text, 14000) : '\n\n(token id unavailable, so policies were not fetched)')
    );
  }

  if (name === 'cf_r2') {
    const base = '/accounts/' + acct(args, cfg) + '/r2/buckets';
    const action = String(args.action || 'list');
    if (action === 'list') return out((await must(cf(base, {}, cfg))).text);
    if (action === 'create') {
      const body = { name: req(args, 'name') };
      if (args.location) body.location = String(args.location);
      return out((await must(cf(base, { method: 'POST', body }, cfg))).text);
    }
    if (action === 'delete') return out((await must(cf(base + '/' + encodeURIComponent(req(args, 'name')), { method: 'DELETE' }, cfg))).text);
    throw new Error('unknown action: ' + action);
  }

  if (name === 'cf_d1') {
    const base = '/accounts/' + acct(args, cfg) + '/d1/database';
    const action = String(args.action || 'list');
    if (action === 'list') return out((await must(cf(base, {}, cfg))).text);
    if (action === 'create') return out((await must(cf(base, { method: 'POST', body: { name: req(args, 'name') } }, cfg))).text);
    const db = encodeURIComponent(req(args, 'database_id'));
    if (action === 'delete') return out((await must(cf(base + '/' + db, { method: 'DELETE' }, cfg))).text);
    if (action === 'query') {
      const body = { sql: req(args, 'sql'), params: Array.isArray(args.params) ? args.params : [] };
      return out((await must(cf(base + '/' + db + '/query', { method: 'POST', body }, cfg))).text);
    }
    throw new Error('unknown action: ' + action);
  }

  if (name === 'cf_queues') {
    const base = '/accounts/' + acct(args, cfg) + '/queues';
    const action = String(args.action || 'list');
    if (action === 'list') return out((await must(cf(base, {}, cfg))).text);
    if (action === 'create') return out((await must(cf(base, { method: 'POST', body: { queue_name: req(args, 'queue_name') } }, cfg))).text);
    if (action === 'delete') return out((await must(cf(base + '/' + encodeURIComponent(req(args, 'queue_id')), { method: 'DELETE' }, cfg))).text);
    throw new Error('unknown action: ' + action);
  }

  if (name === 'cf_worker_routes') {
    const base = '/zones/' + req(args, 'zone_id') + '/workers/routes';
    const action = String(args.action || 'list');
    if (action === 'list') return out((await must(cf(base, {}, cfg))).text);
    if (action === 'create') {
      const body = { pattern: req(args, 'pattern'), script: req(args, 'script') };
      return out((await must(cf(base, { method: 'POST', body }, cfg))).text);
    }
    if (action === 'delete') return out((await must(cf(base + '/' + encodeURIComponent(req(args, 'route_id')), { method: 'DELETE' }, cfg))).text);
    throw new Error('unknown action: ' + action);
  }

  if (name === 'cf_worker_domains') {
    const base = '/accounts/' + acct(args, cfg) + '/workers/domains';
    const action = String(args.action || 'list');
    if (action === 'list') return out((await must(cf(base, {}, cfg))).text);
    if (action === 'attach') {
      const body = {
        zone_id: req(args, 'zone_id'),
        hostname: req(args, 'hostname'),
        service: req(args, 'service'),
        environment: String(args.environment || 'production'),
      };
      return out((await must(cf(base, { method: 'PUT', body }, cfg))).text);
    }
    if (action === 'detach') return out((await must(cf(base + '/' + encodeURIComponent(req(args, 'domain_id')), { method: 'DELETE' }, cfg))).text);
    throw new Error('unknown action: ' + action);
  }

  if (name === 'cf_pages_deployments') {
    const base =
      '/accounts/' + acct(args, cfg) + '/pages/projects/' + encodeURIComponent(req(args, 'project')) + '/deployments';
    const action = String(args.action || 'list');
    if (action === 'list') return out((await must(cf(base, {}, cfg))).text);
    const id = encodeURIComponent(req(args, 'deployment_id'));
    if (action === 'retry') return out((await must(cf(base + '/' + id + '/retries', { method: 'POST' }, cfg))).text);
    if (action === 'rollback') return out((await must(cf(base + '/' + id + '/rollbacks', { method: 'POST' }, cfg))).text);
    throw new Error('unknown action: ' + action);
  }

  if (name === 'cf_zone_settings') {
    const base = '/zones/' + req(args, 'zone_id') + '/settings';
    const action = String(args.action || 'list');
    if (action === 'list') return out((await must(cf(base, {}, cfg))).text);
    const setting = encodeURIComponent(req(args, 'setting'));
    if (action === 'get') return out((await must(cf(base + '/' + setting, {}, cfg))).text);
    if (action === 'set') {
      if (args.value === undefined) throw new Error('value is required for set');
      return out((await must(cf(base + '/' + setting, { method: 'PATCH', body: { value: args.value } }, cfg))).text);
    }
    throw new Error('unknown action: ' + action);
  }

  if (name === 'cf_rulesets') {
    const action = String(args.action || 'list');
    const scope = String(args.scope || (args.zone_id ? 'zone' : 'account'));
    if (scope !== 'zone' && scope !== 'account') throw new Error('scope must be account or zone');
    const base =
      scope === 'zone'
        ? '/zones/' + req(args, 'zone_id') + '/rulesets'
        : '/accounts/' + acct(args, cfg) + '/rulesets';
    if (action === 'list') {
      const q = args.phase ? '?phase=' + encodeURIComponent(String(args.phase)) : '';
      return out((await must(cf(base + q, {}, cfg))).text);
    }
    if (action === 'entrypoint') {
      const path = base + '/phases/' + encodeURIComponent(req(args, 'phase')) + '/entrypoint';
      if (args.body === undefined) return out((await must(cf(path, {}, cfg))).text);
      return out((await must(cf(path, { method: 'PUT', body: bodyOf(args) }, cfg))).text);
    }
    const id = encodeURIComponent(req(args, 'ruleset_id'));
    if (action === 'get') return out((await must(cf(base + '/' + id, {}, cfg))).text);
    if (action === 'create') return out((await must(cf(base, { method: 'POST', body: bodyOf(args) }, cfg))).text);
    if (action === 'update') return out((await must(cf(base + '/' + id, { method: 'PUT', body: bodyOf(args) }, cfg))).text);
    if (action === 'delete') return out((await must(cf(base + '/' + id, { method: 'DELETE' }, cfg))).text);
    throw new Error('unknown action: ' + action);
  }

  if (name === 'cf_load_balancer') {
    const action = String(args.action || 'list');
    const account = acct(args, cfg);
    if (action === 'monitors') return out((await must(cf('/accounts/' + account + '/load_balancers/monitors', {}, cfg))).text);
    if (action === 'pools') return out((await must(cf('/accounts/' + account + '/load_balancers/pools', {}, cfg))).text);
    const base = '/zones/' + req(args, 'zone_id') + '/load_balancers';
    if (action === 'list') return out((await must(cf(base, {}, cfg))).text);
    if (action === 'create') return out((await must(cf(base, { method: 'POST', body: bodyOf(args) }, cfg))).text);
    const id = encodeURIComponent(req(args, 'id'));
    if (action === 'update') return out((await must(cf(base + '/' + id, { method: 'PUT', body: bodyOf(args) }, cfg))).text);
    if (action === 'delete') return out((await must(cf(base + '/' + id, { method: 'DELETE' }, cfg))).text);
    throw new Error('unknown action: ' + action);
  }

  if (name === 'cf_email_routing') {
    const base = '/zones/' + req(args, 'zone_id') + '/email/routing';
    const action = String(args.action || 'rules');
    if (action === 'rules') return out((await must(cf(base + '/rules', {}, cfg))).text);
    if (action === 'create-rule') return out((await must(cf(base + '/rules', { method: 'POST', body: bodyOf(args) }, cfg))).text);
    if (action === 'delete-rule') return out((await must(cf(base + '/rules/' + encodeURIComponent(req(args, 'rule_id')), { method: 'DELETE' }, cfg))).text);
    if (action === 'addresses') return out((await must(cf(base + '/addresses', {}, cfg))).text);
    if (action === 'catch-all') return out((await must(cf(base + '/catch_all', {}, cfg))).text);
    if (action === 'settings') return out((await must(cf(base, {}, cfg))).text);
    throw new Error('unknown action: ' + action);
  }

  if (name === 'cf_access') {
    const base = '/accounts/' + acct(args, cfg) + '/access/apps';
    const action = String(args.action || 'list');
    if (action === 'list') return out((await must(cf(base, {}, cfg))).text);
    if (action === 'create') return out((await must(cf(base, { method: 'POST', body: bodyOf(args) }, cfg))).text);
    const id = encodeURIComponent(req(args, 'app_id'));
    if (action === 'get') return out((await must(cf(base + '/' + id, {}, cfg))).text);
    if (action === 'update') return out((await must(cf(base + '/' + id, { method: 'PUT', body: bodyOf(args) }, cfg))).text);
    if (action === 'delete') return out((await must(cf(base + '/' + id, { method: 'DELETE' }, cfg))).text);
    throw new Error('unknown action: ' + action);
  }

  if (name === 'cf_logpush') {
    const action = String(args.action || 'list');
    const scope = String(args.scope || (args.zone_id ? 'zone' : 'account'));
    if (scope !== 'zone' && scope !== 'account') throw new Error('scope must be account or zone');
    const base =
      scope === 'zone'
        ? '/zones/' + req(args, 'zone_id') + '/logpush/jobs'
        : '/accounts/' + acct(args, cfg) + '/logpush/jobs';
    if (action === 'list') return out((await must(cf(base, {}, cfg))).text);
    if (action === 'create') return out((await must(cf(base, { method: 'POST', body: bodyOf(args) }, cfg))).text);
    if (action === 'delete') return out((await must(cf(base + '/' + encodeURIComponent(req(args, 'job_id')), { method: 'DELETE' }, cfg))).text);
    throw new Error('unknown action: ' + action);
  }

  if (name === 'cf_turnstile') {
    const base = '/accounts/' + acct(args, cfg) + '/challenges/widgets';
    const action = String(args.action || 'list');
    if (action === 'list') return out((await must(cf(base, {}, cfg))).text);
    if (action === 'create') return out((await must(cf(base, { method: 'POST', body: bodyOf(args) }, cfg))).text);
    if (action === 'delete') return out((await must(cf(base + '/' + encodeURIComponent(req(args, 'sitekey')), { method: 'DELETE' }, cfg))).text);
    throw new Error('unknown action: ' + action);
  }

  if (name === 'cf_ai_gateway') {
    const base = '/accounts/' + acct(args, cfg) + '/ai-gateway/gateways';
    const action = String(args.action || 'list');
    if (action === 'list') return out((await must(cf(base, {}, cfg))).text);
    if (action === 'create') return out((await must(cf(base, { method: 'POST', body: bodyOf(args) }, cfg))).text);
    if (action === 'delete') return out((await must(cf(base + '/' + encodeURIComponent(req(args, 'gateway_id')), { method: 'DELETE' }, cfg))).text);
    throw new Error('unknown action: ' + action);
  }

  throw new Error('unhandled tool: ' + name);
}

/* ---------- Cloudflare API helper ---------- */

/**
 * One Cloudflare API call. Never throws on an HTTP error status: a 403 becomes
 * readable data the model can reason about.
 * @returns {Promise<{ok:boolean, status:number, text:string}>}
 */
async function cf(path, init, cfg) {
  const opt = init || {};
  /** @type {Record<string, string>} */
  const headers = { Authorization: 'Bearer ' + cfg.api };
  let body;
  if (opt.form) {
    body = opt.form; // FormData sets its own multipart boundary
  } else if (opt.raw !== undefined) {
    headers['Content-Type'] = 'text/plain';
    body = opt.raw;
  } else if (opt.body !== undefined) {
    headers['Content-Type'] = 'application/json';
    body = JSON.stringify(opt.body);
  }

  try {
    const res = await fetch(API + path, { method: opt.method || 'GET', headers, body, signal: AbortSignal.timeout(TIMEOUT) });
    const text = await res.text();
    return { ok: res.ok, status: res.status, text };
  } catch (err) {
    const timedOut = /timeout|abort/i.test(msgOf(err));
    return {
      ok: false,
      status: timedOut ? 504 : 502,
      text: 'could not reach api.cloudflare.com: ' + (timedOut ? 'no answer within ' + Math.round(TIMEOUT / 1000) + 's' : msgOf(err)),
    };
  }
}

async function must(pending) {
  const res = await pending;
  if (!res.ok) throw new Error('Cloudflare API ' + res.status + ': ' + clip(res.text, 700));
  return res;
}

/* ---------- small helpers ---------- */

function acct(args, cfg) {
  const id = String((args && args.account_id) || cfg.account || '').trim();
  if (!id) throw new Error('account_id is required (call cf_accounts first, or set CF_ACCOUNT_ID on the Worker)');
  return id;
}

function req(args, key) {
  const v = String((args && args[key]) || '').trim();
  if (!v) throw new Error(key + ' is required');
  return v;
}

function bodyOf(args) {
  const b = args && args.body;
  if (!b || typeof b !== 'object' || Array.isArray(b)) throw new Error('body (JSON object) is required for this action');
  return b;
}

function out(text) {
  return clip(String(text == null ? '' : text), MAX);
}

function clip(text, limit) {
  const s = String(text == null ? '' : text);
  return s.length > limit ? s.slice(0, limit) + '\n...[' + (s.length - limit) + ' more characters truncated]' : s;
}

function msgOf(err) {
  return String((err && err.message) || err);
}
