#!/usr/bin/env node
// node:http around handler.js, plus a file on disk. Nothing else lives here —
// the rules are in handler.js where they are unit-tested.
//
// Configuration, all through the environment:
//   SYNC_CODES    comma-separated pairing codes. Required. Each is its own
//                 bucket, so one instance can serve several people.
//   SYNC_ORIGINS  comma-separated origins allowed to call this. Defaults to
//                 the website and https://localhost, which is what the Android
//                 app is since it started serving its own bundle.
//   SYNC_DATA     directory for the blobs. Default /data.
//   PORT          default 8080.
//
// TLS is not handled here. Put it behind the proxy that already terminates
// TLS for the website — the pairing code is a bearer token, and a bearer token
// over plain HTTP is a bearer token you have given away.

import { createServer } from 'node:http';
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { handle, MAX_BYTES } from './handler.js';

const PORT = Number(process.env.PORT || 8080);
const DATA_DIR = process.env.SYNC_DATA || '/data';
const CODES = (process.env.SYNC_CODES || '').split(',').map(s => s.trim()).filter(Boolean);
const ORIGINS = (process.env.SYNC_ORIGINS || 'https://todo.celexstrategy.com,https://localhost')
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
      { codes: CODES, origins: ORIGINS }
    ));
  } catch (e) {
    if (e.tooLarge) return send({ status: 413, body: { error: 'snapshot too large' } });
    if (e.badJson) return send({ status: 400, body: { error: 'invalid json' } });
    console.error('sync service error:', e);
    send({ status: 500, body: { error: 'internal error' } });
  }
});

await mkdir(DATA_DIR, { recursive: true });
server.listen(PORT, () => {
  console.log(`TaskGarden sync on :${PORT}, data in ${DATA_DIR}, ${CODES.length} code(s)`);
});
