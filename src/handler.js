// The TaskGarden sync service, as a pure request handler.
//
// It stores one blob and hands it back. That is the whole feature: the client
// already reconciles records and, with encryption on, seals the payload before
// it ever gets here — so this service cannot read what it holds and has no
// reason to understand it.
//
// No accounts. A single-user app does not have the problem an account system
// solves; it needs a secret, and the pairing code is that. Multiple people can
// share one instance by giving each their own code — each code is its own
// bucket, and no code can reach another's.
//
// The request handling lives here, away from node:http, so the rules that
// matter — who is let in, what a missing snapshot returns, which origins may
// call — are unit-tested rather than verified by curling a running container.

const MAX_BYTES = 8 * 1024 * 1024;
const MAX_SUBSCRIPTIONS = 10;
// One wake-up call per bucket in this window: a client in a loop must not be
// able to turn this service into a notification cannon.
const NOTIFY_GAP_MS = 5000;
const MAX_SCHEDULED = 80;
const MAX_AHEAD_MS = 8 * 24 * 3600 * 1000;
const MISSED_MS = 15 * 60 * 1000;
const lastNotify = new Map();

function bucketFor(code) {
  // The code names the file, so it must not be able to name a different one.
  // Hex only, and length-bounded: no slashes, no dots, no traversal.
  return code.replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 64);
}

/**
 * Constant-time-ish comparison. Not a defence against a local attacker with a
 * profiler, but it costs nothing and removes the trivial early-exit signal.
 */
function sameSecret(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

export function corsHeaders(origin, allowed) {
  // Only origins on the allow-list are echoed back. A wildcard would let any
  // page a browser has open talk to this service with a code it stole from
  // somewhere; the list is the point. (An app served from the same origin as
  // this service, e.g. through a reverse proxy path, needs no CORS at all.)
  const ok = allowed.includes(origin);
  return {
    'Access-Control-Allow-Origin': ok ? origin : allowed[0] || 'null',
    'Access-Control-Allow-Methods': 'GET, PUT, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Authorization, Content-Type',
    'Access-Control-Max-Age': '86400',
    Vary: 'Origin'
  };
}

/**
 * Handle one request against a storage of `{ read(bucket), write(bucket, body) }`.
 * Returns `{ status, body, headers }` — no node:http types in sight.
 */
export async function handle(req, store, { codes, origins, push = null, now = Date.now }) {
  const cors = corsHeaders(req.headers.origin, origins);

  if (req.method === 'OPTIONS') return { status: 204, headers: cors };

  const isPush = req.path.startsWith('/push/');
  if (req.path !== '/snapshot' && !(isPush && push)) {
    return { status: 404, headers: cors, body: { error: 'not found' } };
  }

  const presented = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  const code = codes.find(c => sameSecret(c, presented));
  if (!code) {
    return { status: 401, headers: cors, body: { error: 'unauthorized' } };
  }
  const bucket = bucketFor(code);

  if (isPush) return handlePush(req, store, bucket, cors, push, now);

  if (req.method === 'GET') {
    const stored = await store.read(bucket);
    // 404 means "nothing here yet", which the client turns into "this device's
    // data becomes the account". It must never be conflated with a rejected
    // code, or a wrong code would silently overwrite someone's data.
    if (stored === null || stored === undefined) {
      return { status: 404, headers: cors, body: { error: 'no snapshot yet' } };
    }
    return { status: 200, headers: cors, body: stored };
  }

  if (req.method === 'PUT') {
    if (req.body === null || req.body === undefined) {
      return { status: 400, headers: cors, body: { error: 'empty body' } };
    }
    const size = JSON.stringify(req.body).length;
    if (size > MAX_BYTES) {
      return { status: 413, headers: cors, body: { error: 'snapshot too large' } };
    }
    await store.write(bucket, req.body);
    return { status: 204, headers: cors };
  }

  return { status: 405, headers: cors, body: { error: 'method not allowed' } };
}

// Web Push without a payload: the push service only carries "something
// happened", the app's service worker shows a fixed notice. So there is no
// message encryption to get wrong, and nothing readable passes through a
// third-party push service.
async function handlePush(req, store, bucket, cors, push, now) {
  const reply = (status, body) => ({ status, headers: cors, body });
  const subsBucket = `push-${bucket}`;
  const read = async () => {
    const stored = await store.read(subsBucket);
    return Array.isArray(stored) ? stored : [];
  };
  const route = `${req.method} ${req.path}`;

  if (route === 'GET /push/key') return reply(200, { key: push.publicKey });

  if (route === 'POST /push/subscribe') {
    const sub = req.body?.subscription;
    const endpoint = sub?.endpoint;
    if (typeof endpoint !== 'string' || !/^https:\/\/[^\s/]+/.test(endpoint) || endpoint.length > 1000) {
      return reply(400, { error: 'invalid subscription' });
    }
    // One device can hold several roles ("luca,mia"): a phone that is both.
    const role = typeof req.body?.role === 'string' ? req.body.role.replace(/[^a-z,]/g, '').slice(0, 40) : '';
    const list = (await read()).filter(s => s.endpoint !== endpoint);
    list.unshift({ endpoint, keys: sub.keys || null, role });
    await store.write(subsBucket, list.slice(0, MAX_SUBSCRIPTIONS));
    return reply(204);
  }

  // How many devices are signed up for each role, so a sender can tell
  // "nobody listens" from "the message did not arrive".
  if (route === 'GET /push/status') {
    const counts = {};
    (await read()).forEach(sub => String(sub.role || '').split(',').filter(Boolean).forEach(r => { counts[r] = (counts[r] || 0) + 1; }));
    return reply(200, { devices: counts, total: (await read()).length });
  }

  if (route === 'POST /push/unsubscribe') {
    const endpoint = req.body?.endpoint;
    await store.write(subsBucket, (await read()).filter(s => s.endpoint !== endpoint));
    return reply(204);
  }

  if (route === 'POST /push/notify') {
    const t = now();
    if (t - (lastNotify.get(bucket) || 0) < NOTIFY_GAP_MS) return reply(429, { error: 'too many' });
    lastNotify.set(bucket, t);
    const role = typeof req.body?.role === 'string' ? req.body.role : '';
    const payload = cleanPayload(req.body?.payload);
    const list = await read();
    const targets = list.filter(s => hasRole(s, role) && s.endpoint !== req.body?.skip);
    const dead = new Set();
    let sent = 0;
    await Promise.all(targets.map(async (s) => {
      try {
        const status = await push.send(s, payload);
        if (status === 404 || status === 410) dead.add(s.endpoint);
        else if (status >= 200 && status < 300) sent += 1;
      } catch (e) { /* an unreachable push service is not a reason to fail the request */ }
    }));
    // A subscription the push service has forgotten is dropped, so the list does not rot.
    if (dead.size) await store.write(subsBucket, list.filter(s => !dead.has(s.endpoint)));
    return reply(200, { sent });
  }

  // The list of reminders to send later (for example "a rule starts in ten
  // minutes"). A device replaces the whole list each time it posts, so
  // changing the source of the reminders also changes what is still pending.
  if (route === 'POST /push/schedule') {
    const t = now();
    const items = (Array.isArray(req.body?.items) ? req.body.items : [])
      .map(i => ({ at: Number(i?.at), role: typeof i?.role === 'string' ? i.role.slice(0, 20) : '', payload: cleanPayload(i?.payload) }))
      .filter(i => Number.isFinite(i.at) && i.at > t && i.at < t + MAX_AHEAD_MS && i.payload)
      .sort((a, b) => a.at - b.at)
      .slice(0, MAX_SCHEDULED);
    await store.write(`sched-${bucket}`, items);
    return reply(200, { scheduled: items.length });
  }

  return reply(404, { error: 'not found' });
}

export const hasRole = (sub, role) => !role || String(sub.role || '').split(',').includes(role);

// Only a small object of short strings goes into a notification.
export function cleanPayload(p) {
  if (!p || typeof p !== 'object' || Array.isArray(p)) return null;
  const out = {};
  for (const [k, v] of Object.entries(p)) {
    if (typeof v === 'string' && /^[a-z]{1,10}$/.test(k)) out[k] = v.slice(0, 240);
  }
  return Object.keys(out).length ? out : null;
}

// Called on a timer by the server: sends what is due, drops what was missed by
// more than MISSED_MS (a server that was down must not fire last week's).
export async function runSchedule(store, buckets, push, now = Date.now) {
  let sent = 0;
  for (const bucket of buckets) {
    const items = await store.read(`sched-${bucket}`);
    if (!Array.isArray(items) || items.length === 0) continue;
    const t = now();
    const due = items.filter(i => i.at <= t);
    if (!due.length) continue;
    const subs = await store.read(`push-${bucket}`);
    const dead = new Set();
    for (const item of due.filter(i => t - i.at <= MISSED_MS)) {
      for (const sub of (Array.isArray(subs) ? subs : []).filter(x => hasRole(x, item.role))) {
        try {
          const status = await push.send(sub, item.payload);
          if (status === 404 || status === 410) dead.add(sub.endpoint);
          else if (status >= 200 && status < 300) sent += 1;
        } catch (e) { /* try again never: the next reminder is another one */ }
      }
    }
    await store.write(`sched-${bucket}`, items.filter(i => i.at > t));
    if (dead.size) await store.write(`push-${bucket}`, subs.filter(x => !dead.has(x.endpoint)));
  }
  return sent;
}

export { bucketFor, MAX_BYTES, NOTIFY_GAP_MS };
