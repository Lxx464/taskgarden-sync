import { beforeEach, describe, expect, it } from 'vitest';
import { bucketFor, corsHeaders, handle } from './handler.js';

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
