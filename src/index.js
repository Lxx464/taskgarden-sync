#!/usr/bin/env node
// node:http around handler.js, plus a file on disk. Nothing else lives here —
// the rules are in handler.js where they are unit-tested.
//
// Configuration, all through the environment:
//   SYNC_CODES    comma-separated pairing codes. Required. Each is its own
//                 bucket, so one instance can serve several people.
//   SYNC_ORIGINS  comma-separated origins allowed to call this from another
//                 origin. Defaults to the website. Not needed when the app
//                 reaches this service through its own origin (a proxy path).
//   SYNC_DATA     directory for the blobs. Default /data.
//   PORT          default 8080.
//
// TLS is not handled here. Put it behind the proxy that already terminates
// TLS for the website — the pairing code is a bearer token, and a bearer token
// over plain HTTP is a bearer token you have given away.

import { createServer } from 'node:http';
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { createPrivateKey, generateKeyPairSync, sign } from 'node:crypto';
import { join } from 'node:path';
import { handle, MAX_BYTES, bucketFor, runSchedule } from './handler.js';
import { encryptPayload } from './webpush.js';

const PORT = Number(process.env.PORT || 8080);
const DATA_DIR = process.env.SYNC_DATA || '/data';
const CODES = (process.env.SYNC_CODES || '').split(',').map(s => s.trim()).filter(Boolean);
const ORIGINS = (process.env.SYNC_ORIGINS || 'https://todo.celexstrategy.com')
  .split(',').map(s => s.trim()).filter(Boolean);

if (CODES.length === 0) {
  console.error('SYNC_CODES is empty — refusing to start an open sync service.');
  process.exit(1);
}

const fileStore = {
  async read(bucket) {
    try {
      return JSON.parse(await readFile(join(DATA_DIR, `${bucket}.json`), 'utf8'));
    } catch (e) {
      // Missing file is the normal "nothing yet" case. A corrupt one is not,
      // and must not be reported as empty — that is how a client would decide
      // to overwrite it.
      if (e.code === 'ENOENT') return null;
      throw e;
    }
  },

  async write(bucket, body) {
    const target = join(DATA_DIR, `${bucket}.json`);
    // Write beside it and rename: a process killed mid-write must not leave a
    // half-written snapshot where the only copy used to be.
    const tmp = `${target}.${process.pid}.tmp`;
    await writeFile(tmp, JSON.stringify(body), 'utf8');
    await rename(tmp, target);
  }
};

// Web Push needs a VAPID key pair so push services know who is calling. It is
// made on first start and kept in the data volume — nothing to configure.
const b64url = (buf) => Buffer.from(buf).toString('base64url');

async function loadVapid() {
  const file = join(DATA_DIR, 'vapid.json');
  let jwk;
  try {
    jwk = JSON.parse(await readFile(file, 'utf8'));
  } catch (e) {
    if (e.code !== 'ENOENT') throw e;
    jwk = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey.export({ format: 'jwk' });
    await writeFile(file, JSON.stringify(jwk), { encoding: 'utf8', mode: 0o600 });
  }
  const key = createPrivateKey({ key: jwk, format: 'jwk' });
  // The uncompressed point: 0x04 || x || y.
  const publicKey = b64url(Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url')]));
  const subject = process.env.SYNC_PUSH_SUBJECT || ORIGINS[0] || 'https://localhost';

  return {
    publicKey,
    // A wake-up call with no body. Resolves to the push service's status code.
    async send(subscription, payload = null) {
      const aud = new URL(subscription.endpoint).origin;
      const head = b64url(JSON.stringify({ typ: 'JWT', alg: 'ES256' }));
      const claims = b64url(JSON.stringify({ aud, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: subject }));
      const signature = sign('sha256', Buffer.from(`${head}.${claims}`), { key, dsaEncoding: 'ieee-p1363' });
      const headers = { Authorization: `vapid t=${head}.${claims}.${b64url(signature)}, k=${publicKey}`, TTL: '3600', Urgency: 'high' };
      let body;
      // With the subscriber's keys the text travels sealed; without them the
      // push is a plain wake-up call and the app shows its fixed notice.
      if (payload && subscription.keys?.p256dh && subscription.keys?.auth) {
        try {
          body = encryptPayload(subscription.keys, JSON.stringify(payload));
          headers['Content-Encoding'] = 'aes128gcm';
          headers['Content-Type'] = 'application/octet-stream';
        } catch (e) { body = undefined; }
      }
      const res = await fetch(subscription.endpoint, { method: 'POST', headers, body, signal: AbortSignal.timeout(10000) });
      return res.status;
    }
  };
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', chunk => {
      size += chunk.length;
      if (size > MAX_BYTES) {
        reject(Object.assign(new Error('too large'), { tooLarge: true }));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (chunks.length === 0) return resolve(null);
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      } catch (e) {
        reject(Object.assign(new Error('invalid json'), { badJson: true }));
      }
    });
    req.on('error', reject);
  });
}

const server = createServer(async (req, res) => {
  const send = ({ status, headers = {}, body }) => {
    res.writeHead(status, { ...headers, 'Content-Type': 'application/json' });
    res.end(body === undefined ? '' : JSON.stringify(body));
  };

  try {
    const url = new URL(req.url, 'http://localhost');
    let body = null;
    if (req.method === 'PUT' || req.method === 'POST') body = await readBody(req);

    send(await handle(
      { method: req.method, path: url.pathname, headers: req.headers, body },
      fileStore,
      { codes: CODES, origins: ORIGINS, push }
    ));
  } catch (e) {
    if (e.tooLarge) return send({ status: 413, body: { error: 'snapshot too large' } });
    if (e.badJson) return send({ status: 400, body: { error: 'invalid json' } });
    console.error('sync service error:', e);
    send({ status: 500, body: { error: 'internal error' } });
  }
});

await mkdir(DATA_DIR, { recursive: true });
const push = await loadVapid();
// Reminders posted through /push/schedule go out from here.
setInterval(() => {
  runSchedule(fileStore, CODES.map(bucketFor), push).catch(e => console.error('schedule error:', e));
}, 30000).unref();
server.listen(PORT, () => {
  console.log(`TaskGarden sync on :${PORT}, data in ${DATA_DIR}, ${CODES.length} code(s)`);
});
