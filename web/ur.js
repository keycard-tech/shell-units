// UR framing as the Shell actually speaks it: `UR:DEV-AUTH/<bytewords>`.
//
// The payload is bytewords minimal: two lowercase letters per byte plus a four byte CRC-32 that both
// sides verify before reading the contents. Not base32 — digits are outside the bytewords alphabet,
// and a payload with the wrong encoding is dropped on both ends without a message, which shows up as
// a device that simply will not scan.
//
// Single-part only. A response is far below the size at which a message would ever be split, so a
// fountain decoder here would be dead code, and dead code in a verifier is worse than no code.

import { encodeBytewords, decodeBytewords, bytesToHex, hexToBytes } from './dist/shvr-vendor.js';

export const DEV_AUTH_TYPE = 'DEV-AUTH';

// The device folds the type label case-insensitively and tolerates any case in the bytewords body,
// but it emits uppercase type and lowercase body, so that is what this produces too.
export function urEncode(type, payload) {
  return `UR:${type}/${encodeBytewords(payload, 'minimal')}`;
}

export function urDecode(text, expectedType) {
  const match = /^(UR):([a-z0-9-]+)\/([a-z]+)$/i.exec(text.trim());
  if (!match) throw new Error('not a UR: expected UR:<type>/<bytewords>');
  if (match[2].toUpperCase() !== expectedType.toUpperCase()) {
    throw new Error(`expected UR:${expectedType}/, got UR:${match[2]}/`);
  }
  let payload;
  try {
    payload = decodeBytewords(match[3], 'minimal');
  } catch (err) {
    throw new Error(`bytewords payload rejected: ${err.message ?? err}`);
  }
  return payload;
}

// The framing plus the checksum, checked against an independent CRC-32 rather than against the
// library that produced it, so both sides of the wire are pinned by something other than themselves.
export function looksLikeUr(text) {
  return /^(UR):[a-z0-9-]+\/[a-z]+$/i.test(text.trim());
}

export { bytesToHex, hexToBytes, encodeBytewords, decodeBytewords };
