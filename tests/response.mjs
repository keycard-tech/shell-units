// Builds dev_auth response messages for the tests, well-formed and deliberately not.
// The encoder is only as general as the protocol needs; the malformed variants exist so that the
// verifier's refusals are tested rather than assumed.

import { bytesToHex, hexToBytes, sha256, secp256k1 } from '../web/dist/shvr-vendor.js';

const U8 = (...parts) => {
  const out = [];
  for (const p of parts) out.push(...(p instanceof Uint8Array ? p : [p]));
  return Uint8Array.from(out);
};

function head(major, value) {
  if (value < 24) return [U8((major << 5) | value)];
  const bytes = [];
  let v = value;
  while (v > 0) {
    bytes.unshift(v & 0xff);
    v >>>= 8;
  }
  return [U8((major << 5) | (23 + bytes.length)), U8(...bytes)];
}

const uint = (v) => U8(...head(0, v));
const bstr = (b) => U8(...head(2, b.length), b);
const tagged = (t, inner) => U8(...head(6, t), inner);

export function responseBytes({ step = 2, uid, challenge, sig, extra = [], tagDevId = true, definite = true }) {
  const map = [];
  map.push([uint(1), uint(step)]);
  map.push([uint(2), tagDevId ? tagged(37, bstr(uid)) : bstr(uid)]);
  if (challenge !== null) map.push([uint(6), bstr(challenge)]);
  if (sig !== null) map.push([uint(7), bstr(sig)]);
  for (const [k, v] of extra) map.push([uint(k), v]);

  const body = U8(...map.flat(2));
  if (definite) return U8(...head(5, map.length), body);
  return U8(0xbf, body, 0xff);
}

// digest = SHA256(uid ‖ challenge), 64-byte compact r‖s, s left exactly as signed.
export function deviceSign(privHex, uid, challenge, { forceHighS = false, forceLowS = false } = {}) {
  const digest = sha256(U8(uid, challenge));
  let sig = secp256k1.sign(digest, hexToBytes(privHex), { prehash: false, format: 'compact', lowS: false });
  const N = secp256k1.Point.Fn.ORDER;
  const s = secp256k1.Signature.fromBytes(sig);
  if ((forceHighS && !s.hasHighS()) || (forceLowS && s.hasHighS())) {
    sig = U8(sig.subarray(0, 32), hexToBytes((N - s.s).toString(16).padStart(64, '0')));
  }
  return { sig, digest };
}

export { bytesToHex, hexToBytes, sha256, uint, bstr, tagged, head };
