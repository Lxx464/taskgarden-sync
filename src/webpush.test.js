import { createDecipheriv, createECDH, hkdfSync, randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { encryptPayload } from './webpush.js';

// The receiving side of RFC 8291, to prove the sealed body opens with the
// subscriber's keys and with nothing else.
function decrypt(body, uaECDH, authSecret) {
  const salt = body.subarray(0, 16);
  const idLen = body[20];
  const asPublic = body.subarray(21, 21 + idLen);
  const sealed = body.subarray(21 + idLen);
  const uaPublic = uaECDH.getPublicKey();
  const shared = uaECDH.computeSecret(asPublic);
  const keyInfo = Buffer.concat([Buffer.from('WebPush: info\0'), uaPublic, asPublic]);
  const ikm = Buffer.from(hkdfSync('sha256', shared, authSecret, keyInfo, 32));
  const cek = Buffer.from(hkdfSync('sha256', ikm, salt, Buffer.from('Content-Encoding: aes128gcm\0'), 16));
  const nonce = Buffer.from(hkdfSync('sha256', ikm, salt, Buffer.from('Content-Encoding: nonce\0'), 12));
  const d = createDecipheriv('aes-128-gcm', cek, nonce);
  d.setAuthTag(sealed.subarray(sealed.length - 16));
  const plain = Buffer.concat([d.update(sealed.subarray(0, sealed.length - 16)), d.final()]);
  expect(plain[plain.length - 1]).toBe(2);
  return plain.subarray(0, plain.length - 1).toString('utf8');
}

const subscriber = () => {
  const ecdh = createECDH('prime256v1'); ecdh.generateKeys();
  const auth = randomBytes(16);
  return { ecdh, auth, keys: { p256dh: ecdh.getPublicKey().toString('base64url'), auth: auth.toString('base64url') } };
};

describe('encryptPayload', () => {
  it('seals a message only the subscriber can open', () => {
    const s = subscriber();
    const body = encryptPayload(s.keys, JSON.stringify({ k: 'msg', text: 'Hausaufgaben, sofort 🐾' }));
    expect(JSON.parse(decrypt(body, s.ecdh, s.auth))).toEqual({ k: 'msg', text: 'Hausaufgaben, sofort 🐾' });
    const other = subscriber();
    expect(() => decrypt(body, other.ecdh, other.auth)).toThrow();
  });
  it('writes the aes128gcm header: salt, record size, key id', () => {
    const body = encryptPayload(subscriber().keys, 'x');
    expect(body.readUInt32BE(16)).toBe(4096);
    expect(body[20]).toBe(65);
    expect(body[21]).toBe(4);
  });
  it('refuses broken keys and oversized messages', () => {
    expect(() => encryptPayload({ p256dh: 'AA', auth: 'AA' }, 'x')).toThrow();
    expect(() => encryptPayload(subscriber().keys, 'x'.repeat(4100))).toThrow('payload too large');
  });
});
