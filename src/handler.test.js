import { beforeEach, describe, expect, it } from 'vitest';
import { bucketFor, corsHeaders, handle, runSchedule } from './handler.js';

const ORIGINS = ['https://todo.celexstrategy.com', 'https://app.example.org'];
const CODES = ['code-luca', 'code-gast'];

function memoryStore(initial = {}) {
  const data = { ...initial };
  return {
    data,
    async read(bucket) { return bucket in data ? data[bucket] : null; },
    async write(bucket, body) { data[bucket] = body; }
  };
}

const req = (over = {}) => ({
  method: 'GET',
  path: '/snapshot',
  headers: { authorization: 'Bearer code-luca', origin: ORIGINS[0] },
  body: null,
  ...over
});

describe('authorisation', () => {
  let store;
  beforeEach(() => { store = memoryStore(); });

  it('rejects a request with no code', async () => {
    const res = await handle(req({ headers: { origin: ORIGINS[0] } }), store, { codes: CODES, origins: ORIGINS });
    expect(res.status).toBe(401);
  });

  it('rejects a wrong code', async () => {
    const res = await handle(req({ headers: { authorization: 'Bearer nope', origin: ORIGINS[0] } }), store,
      { codes: CODES, origins: ORIGINS });
    expect(res.status).toBe(401);
  });

  // A rejected code and an empty account must never look alike to the client:
  // one means stop, the other means "upload yours".
  it('answers a rejected code differently from an empty account', async () => {
    const rejected = await handle(req({ headers: { authorization: 'Bearer nope' } }), store,
      { codes: CODES, origins: ORIGINS });
    const empty = await handle(req(), store, { codes: CODES, origins: ORIGINS });
    expect(rejected.status).toBe(401);
    expect(empty.status).toBe(404);
  });

  it('keeps each code in its own bucket', async () => {
    await handle(req({ method: 'PUT', body: { notes: ['von luca'] } }), store, { codes: CODES, origins: ORIGINS });
    const other = await handle(req({ headers: { authorization: 'Bearer code-gast', origin: ORIGINS[0] } }), store,
      { codes: CODES, origins: ORIGINS });
    expect(other.status).toBe(404);
  });
});

describe('storing and reading', () => {
  let store;
  beforeEach(() => { store = memoryStore(); });

  it('reports nothing stored yet as 404, which is not an error', async () => {
    expect((await handle(req(), store, { codes: CODES, origins: ORIGINS })).status).toBe(404);
  });

  it('round-trips a snapshot', async () => {
    const sealed = { sb_enc: 1, ct: 'abc', iv: 'def', kdf: {} };
    const put = await handle(req({ method: 'PUT', body: sealed }), store, { codes: CODES, origins: ORIGINS });
    expect(put.status).toBe(204);

    const get = await handle(req(), store, { codes: CODES, origins: ORIGINS });
    expect(get.status).toBe(200);
    expect(get.body).toEqual(sealed);
  });

  it('refuses an empty body rather than storing nothing over something', async () => {
    await handle(req({ method: 'PUT', body: { real: 'data' } }), store, { codes: CODES, origins: ORIGINS });
    const res = await handle(req({ method: 'PUT', body: null }), store, { codes: CODES, origins: ORIGINS });
    expect(res.status).toBe(400);

    const still = await handle(req(), store, { codes: CODES, origins: ORIGINS });
    expect(still.body).toEqual({ real: 'data' });
  });

  it('refuses an oversized snapshot', async () => {
    const huge = { blob: 'x'.repeat(9 * 1024 * 1024) };
    const res = await handle(req({ method: 'PUT', body: huge }), store, { codes: CODES, origins: ORIGINS });
    expect(res.status).toBe(413);
  });

  it('answers anything but /snapshot with 404', async () => {
    const res = await handle(req({ path: '/etc/passwd' }), store, { codes: CODES, origins: ORIGINS });
    expect(res.status).toBe(404);
  });

  it('rejects methods it does not implement', async () => {
    const res = await handle(req({ method: 'DELETE' }), store, { codes: CODES, origins: ORIGINS });
    expect(res.status).toBe(405);
  });
});

describe('bucketFor', () => {
  // The code names the file on disk, so it must not be able to name another.
  it('strips anything that could escape the data directory', () => {
    expect(bucketFor('../../etc/passwd')).toBe('etcpasswd');
    expect(bucketFor('a/b')).toBe('ab');
    expect(bucketFor('code.json')).toBe('codejson');
  });

  it('bounds the length', () => {
    expect(bucketFor('x'.repeat(200)).length).toBe(64);
  });
});

describe('cors', () => {
  it('lets every listed origin in', () => {
    for (const origin of ORIGINS) {
      expect(corsHeaders(origin, ORIGINS)['Access-Control-Allow-Origin']).toBe(origin);
    }
  });

  // A wildcard would let any page the browser has open call this service with
  // a code picked up elsewhere.
  it('never answers with a wildcard', () => {
    const headers = corsHeaders('https://boese.example', ORIGINS);
    expect(headers['Access-Control-Allow-Origin']).not.toBe('*');
    expect(headers['Access-Control-Allow-Origin']).toBe(ORIGINS[0]);
  });

  it('varies on origin so a proxy cannot cache one answer for all', () => {
    expect(corsHeaders(ORIGINS[0], ORIGINS).Vary).toBe('Origin');
  });

  it('answers the preflight without requiring a code', async () => {
    const res = await handle(req({ method: 'OPTIONS', headers: { origin: ORIGINS[0] } }), memoryStore(),
      { codes: CODES, origins: ORIGINS });
    expect(res.status).toBe(204);
  });
});

describe('push', () => {
  const sent = [];
  const push = { publicKey: 'PUB', async send(sub) { sent.push(sub.endpoint); return sub.endpoint.includes('gone') ? 410 : 201; } };
  const ctx = (over = {}) => ({ codes: CODES, origins: ORIGINS, push, now: () => 1_000_000, ...over });
  const post = (path, body, over = {}) => req({ method: 'POST', path, body, ...over });

  beforeEach(() => { sent.length = 0; });

  it('is not there when no push service is configured', async () => {
    const res = await handle(req({ path: '/push/key' }), memoryStore(), { codes: CODES, origins: ORIGINS });
    expect(res.status).toBe(404);
  });

  it('needs the code and hands out the public key', async () => {
    const store = memoryStore();
    expect((await handle(req({ path: '/push/key', headers: { origin: ORIGINS[0] } }), store, ctx())).status).toBe(401);
    const ok = await handle(req({ path: '/push/key' }), store, ctx());
    expect(ok.body).toEqual({ key: 'PUB' });
  });

  it('stores subscriptions per code, rejecting anything that is no https endpoint', async () => {
    const store = memoryStore();
    expect((await handle(post('/push/subscribe', { subscription: { endpoint: 'http://x/1' } }), store, ctx())).status).toBe(400);
    expect((await handle(post('/push/subscribe', { role: 'luca', subscription: { endpoint: 'https://push.example/1', keys: { p256dh: 'a', auth: 'b' } } }), store, ctx())).status).toBe(204);
    await handle(post('/push/subscribe', { role: 'luca', subscription: { endpoint: 'https://push.example/1' } }), store, ctx());
    expect(store.data[`push-${bucketFor('code-luca')}`]).toHaveLength(1);
    expect(store.data[`push-${bucketFor('code-gast')}`]).toBeUndefined();
  });

  it('notifies the matching subscriptions, skips the sender and drops dead ones', async () => {
    const store = memoryStore();
    const sub = (endpoint, role) => handle(post('/push/subscribe', { role, subscription: { endpoint } }), store, ctx());
    await sub('https://push.example/luca', 'luca');
    await sub('https://push.example/gone', 'luca');
    await sub('https://push.example/mia', 'mia');
    const res = await handle(post('/push/notify', { role: 'luca' }), store, ctx());
    expect(res.body).toEqual({ sent: 1 });
    expect(sent.sort()).toEqual(['https://push.example/gone', 'https://push.example/luca']);
    expect(store.data[`push-${bucketFor('code-luca')}`].map(s => s.endpoint).sort()).toEqual(['https://push.example/luca', 'https://push.example/mia']);
  });

  it('rate-limits notify per code', async () => {
    const store = memoryStore();
    await handle(post('/push/notify', {}), store, ctx({ now: () => 5_000_000 }));
    const again = await handle(post('/push/notify', {}), store, ctx({ now: () => 5_001_000 }));
    expect(again.status).toBe(429);
    const later = await handle(post('/push/notify', {}), store, ctx({ now: () => 5_010_000 }));
    expect(later.status).toBe(200);
  });

  it('hands a cleaned payload to the push sender', async () => {
    const store = memoryStore();
    const got = [];
    const p = { publicKey: 'PUB', async send(sub, payload) { got.push(payload); return 201; } };
    await handle(post('/push/subscribe', { role: 'luca', subscription: { endpoint: 'https://push.example/1' } }), store, ctx({ push: p }));
    await handle(post('/push/notify', { role: 'luca', payload: { k: 'msg', text: 'Hallo', 'bad key': 'x', n: 5 } }), store, ctx({ push: p, now: () => 50_000_000 }));
    expect(got).toEqual([{ k: 'msg', text: 'Hallo' }]);
  });

  it('schedules reminders, keeping only future, bounded, well-formed ones', async () => {
    const store = memoryStore();
    const t = 1_000_000;
    const res = await handle(post('/push/schedule', { items: [
      { at: t + 60_000, role: 'luca', payload: { k: 'rule', text: 'A' } },
      { at: t - 1, payload: { k: 'rule' } },
      { at: t + 9 * 24 * 3600 * 1000, payload: { k: 'rule' } },
      { at: t + 120_000 },
      { at: 'x', payload: { k: 'rule' } }
    ] }), store, ctx({ now: () => t }));
    expect(res.body).toEqual({ scheduled: 1 });
    expect(store.data[`sched-${bucketFor('code-luca')}`]).toHaveLength(1);
  });

  it('runSchedule sends what is due, drops what was missed, keeps the future', async () => {
    const b = bucketFor('code-luca');
    const t = 10_000_000;
    const store = memoryStore({
      [`sched-${b}`]: [
        { at: t - 20 * 60_000, role: 'luca', payload: { k: 'old' } },
        { at: t - 1000, role: 'luca', payload: { k: 'due' } },
        { at: t + 60_000, role: 'luca', payload: { k: 'later' } }
      ],
      [`push-${b}`]: [{ endpoint: 'https://push.example/1', role: 'luca' }, { endpoint: 'https://push.example/2', role: 'mia' }]
    });
    const got = [];
    const p = { async send(sub, payload) { got.push([sub.endpoint, payload.k]); return 201; } };
    expect(await runSchedule(store, [b], p, () => t)).toBe(1);
    expect(got).toEqual([['https://push.example/1', 'due']]);
    expect(store.data[`sched-${b}`].map(i => i.payload.k)).toEqual(['later']);
  });

  it('a device can hold several roles and the status counts them', async () => {
    const store = memoryStore();
    const sub = (endpoint, role) => handle(post('/push/subscribe', { role, subscription: { endpoint } }), store, ctx());
    await sub('https://push.example/phone', 'luca,mia');
    await sub('https://push.example/other', 'luca');
    const status = await handle(req({ path: '/push/status' }), store, ctx());
    expect(status.body).toEqual({ devices: { luca: 2, mia: 1 }, total: 2 });
    const got = [];
    const p = { publicKey: 'PUB', async send(s) { got.push(s.endpoint); return 201; } };
    await handle(post('/push/notify', { role: 'mia' }), store, ctx({ push: p, now: () => 70_000_000 }));
    expect(got).toEqual(['https://push.example/phone']);
  });
});
