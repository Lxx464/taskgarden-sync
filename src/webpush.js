// Message encryption for Web Push (RFC 8291, "aes128gcm"), with node:crypto
// only. A push service relays whatever it is given, so the text of a
// notification is sealed for the one browser that subscribed: the push service
// in between sees ciphertext.
import { createCipheriv, createECDH, hkdfSync, randomBytes } from 'node:crypto';

const RECORD_SIZE = 4096;

/**
 * @param {{ p256dh: string, auth: string }} keys  the subscription's keys (base64url)
 * @param {Buffer|string} payload  at most ~3800 bytes
 * @param {{ privateKey?: Buffer, salt?: Buffer }} [fixed]  only for tests
 * @returns {Buffer} the request body, to send with `Content-Encoding: aes128gcm`
 */
export function encryptPayload(keys, payload, fixed = {}) {
  const uaPublic = Buffer.from(keys.p256dh, 'base64url');
  const authSecret = Buffer.from(keys.auth, 'base64url');
  if (uaPublic.length !== 65 || authSecret.length < 16) throw new Error('bad subscription keys');

  const ecdh = createECDH('prime256v1');
  if (fixed.privateKey) ecdh.setPrivateKey(fixed.privateKey); else ecdh.generateKeys();
  const asPublic = ecdh.getPublicKey();
  const shared = ecdh.computeSecret(uaPublic);

  const keyInfo = Buffer.concat([Buffer.from('WebPush: info\0'), uaPublic, asPublic]);
  const ikm = Buffer.from(hkdfSync('sha256', shared, authSecret, keyInfo, 32));
  const salt = fixed.salt || randomBytes(16);
  const cek = Buffer.from(hkdfSync('sha256', ikm, salt, Buffer.from('Content-Encoding: aes128gcm\0'), 16));
  const nonce = Buffer.from(hkdfSync('sha256', ikm, salt, Buffer.from('Content-Encoding: nonce\0'), 12));

  const data = Buffer.concat([Buffer.from(payload), Buffer.from([2])]); // 0x02 closes the only record
  if (data.length > RECORD_SIZE - 17) throw new Error('payload too large');
  const cipher = createCipheriv('aes-128-gcm', cek, nonce);
  const sealed = Buffer.concat([cipher.update(data), cipher.final(), cipher.getAuthTag()]);

  const header = Buffer.alloc(21);
  salt.copy(header, 0);
  header.writeUInt32BE(RECORD_SIZE, 16);
  header.writeUInt8(asPublic.length, 20);
  return Buffer.concat([header, asPublic, sealed]);
}
