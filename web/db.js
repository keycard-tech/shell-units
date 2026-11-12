// SHVR database: parse, authenticate, and answer the only question it exists to answer.
//
// A row is SHA256(salt ‖ "ShellUID" ‖ uid ‖ "ShellPubKey" ‖ pubkey). The uid arrives in the device
// response and the pubkey is recovered from the signature over it, so the verifier holds both and
// nobody holding only the file holds either. See docs/format.md.

import { secp256k1, sha256, bytesToHex, hexToBytes, concatBytes } from './dist/shvr-vendor.js';
import { decodeDevAuth } from './cbor.js';
import { Refusal, NotRegistered } from './errors.js';

export { Refusal, NotRegistered };

export const MAGIC = 'SHVR';
export const FORMAT_VERSION = 1;

const HEADER_SIZE = 64;
const SIG_SIZE = 64;
const INDEX_LEN = 32;
const UID_LEN = 16;
const PUBKEY_LEN = 33;
const TAG_UID = new TextEncoder().encode('ShellUID');
const TAG_PUBKEY = new TextEncoder().encode('ShellPubKey');
const N = secp256k1.Point.Fn.ORDER;

export function rowHash(salt, uid, pubkey) {
  return sha256(concatBytes(salt, TAG_UID, uid, TAG_PUBKEY, pubkey));
}

// Rows are equal-length and sorted, so a position in the index is a position in the file and no
// offset table is needed anywhere.
export function findRow(db, hash) {
  const rows = db.rows;
  let lo = 0;
  let hi = db.rowCount - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const at = mid * INDEX_LEN;
    let cmp = 0;
    for (let i = 0; i < INDEX_LEN; i++) {
      const a = rows[at + i];
      const b = hash[i];
      if (a !== b) {
        cmp = a < b ? -1 : 1;
        break;
      }
    }
    if (cmp === 0) return mid;
    if (cmp < 0) lo = mid + 1;
    else hi = mid - 1;
  }
  return -1;
}

export function loadDatabase(buffer, verifyKey) {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  if (bytes.length < HEADER_SIZE + SIG_SIZE) throw new Refusal('file too short to be a database');

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const text = (o, n) => new TextDecoder().decode(bytes.subarray(o, o + n));

  if (text(0, 4) !== MAGIC) throw new Refusal('not an SHVR database');
  const format = view.getUint16(4, true);
  if (format !== FORMAT_VERSION) throw new Refusal(`unsupported format version ${format}`);

  const uidLen = bytes[6];
  const rowCount = view.getUint32(8, true);
  const salt = bytes.subarray(12, 28);
  const version = view.getUint32(28, true);

  // A reader that silently searched with the wrong uid framing would report "not registered" for
  // every device, which looks identical to a legitimate miss. Fail loudly instead.
  if (uidLen !== UID_LEN) throw new Refusal(`unsupported uid length ${uidLen}`);

  // Reserved bytes stay zero, so giving one a meaning is a version bump rather than a reader
  // silently reinterpreting a file an older reader accepted.
  if (bytes[7] !== 0 || bytes.subarray(32, HEADER_SIZE).some((b) => b !== 0)) {
    throw new Refusal('reserved header bytes are not zero');
  }

  const expected = HEADER_SIZE + rowCount * INDEX_LEN + SIG_SIZE;
  if (bytes.length !== expected) {
    throw new Refusal(`file is ${bytes.length} bytes, header describes ${expected}`);
  }
  if (rowCount === 0) throw new Refusal('empty row array');

  const prefix = bytes.subarray(0, bytes.length - SIG_SIZE);
  const signature = bytes.subarray(bytes.length - SIG_SIZE);
  const digest = sha256(prefix);

  // The signature is the only attestation that a row was provisioned: the device key has no
  // certificate chain, so a file that does not verify carries no information at all.
  let verified = false;
  try {
    verified = secp256k1.verify(signature, digest, hexToBytes(verifyKey), {
      prehash: false,
      lowS: false,
    });
  } catch (err) {
    throw new Refusal(`signature could not be read: ${err.message}`);
  }
  if (!verified) throw new Refusal('signature does not match the pinned key');

  const rows = bytes.subarray(HEADER_SIZE, HEADER_SIZE + rowCount * INDEX_LEN);
  for (let i = 1; i < rowCount; i++) {
    for (let j = 0; j < INDEX_LEN; j++) {
      const prev = rows[(i - 1) * INDEX_LEN + j];
      const cur = rows[i * INDEX_LEN + j];
      if (prev === cur) continue;
      if (prev > cur) throw new Refusal(`rows are not sorted at ${i}`);
      break;
    }
  }

  return { salt, version, rowCount, uidLen, rows, digest, prefix };
}

// challenge must be the 32 bytes this verifier generated, not the field of the same name in the
// response: the device overwrites that one with fresh randomness and nothing checks it.
export function verifyDeviceResponse(db, challenge, responseBytes) {
  if (challenge.length !== 32) throw new Refusal('challenge must be 32 bytes');

  const { entries, fields } = decodeDevAuth(responseBytes);
  const expected = [1, 2, 6, 7];
  if (entries.length !== expected.length || !expected.every((k) => entries.includes(k))) {
    throw new Refusal(`response fields must be exactly 1,2,6,7 — found ${entries.sort().join(',')}`);
  }
  if (fields.get(1) !== 2) throw new Refusal(`step must be 2 (device), got ${fields.get(1)}`);

  const uid = fields.get(2);
  const signature = fields.get(7);
  if (uid.length !== db.uidLen) throw new Refusal(`dev_id is ${uid.length} bytes, database expects ${db.uidLen}`);
  if (signature.length !== 64) throw new Refusal(`auth_sig is ${signature.length} bytes, expected 64`);

  let sig;
  try {
    sig = secp256k1.Signature.fromBytes(signature);
  } catch (err) {
    throw new Refusal(`signature could not be read: ${err.message}`);
  }
  if (sig.r === 0n || sig.s === 0n || sig.r >= N || sig.s >= N) throw new Refusal('signature out of range');

  if (sig.hasHighS()) sig = new secp256k1.Signature(sig.r, N - sig.s);

  const digest = sha256(concatBytes(uid, challenge));

  // recId 2 and 3 would need the nonce point's x to exceed the curve order, which happens with
  // probability about 2^-128 on this curve: two probes is the complete set.
  for (const recId of [0, 1]) {
    let pubkey;
    try {
      pubkey = sig.addRecoveryBit(recId).recoverPublicKey(digest, { prehash: false }).toBytes(true);
    } catch (err) {
      continue;
    }
    const at = findRow(db, rowHash(db.salt, uid, pubkey));
    if (at >= 0) {
      return { uid, pubkey, row: at, hex: bytesToHex(pubkey) };
    }
  }

  throw new NotRegistered('no row matches this uid and signature', bytesToHex(uid));
}
