// End-to-end checks for the SHVR verifier: file authentication, row agreement with the builder,
// the device challenge/response, and every way a response can be wrong.
//
// Run through tests/run.sh, which builds the fixtures first.

import { readFileSync } from 'node:fs';
import { secp256k1, sha256, bytesToHex, hexToBytes } from '../web/dist/shvr-vendor.js';
import { loadDatabase, verifyDeviceResponse, rowHash, findRow, Refusal, NotRegistered } from '../web/db.js';
import { responseBytes, deviceSign, uint } from './response.mjs';
import { urEncode, urDecode, encodeBytewords } from '../web/ur.js';
import { encodeDevAuthInit } from '../web/cbor.js';
import { crc32 } from 'node:zlib';

const [dbPath, keyPath, devicesPath, ...csvPaths] = process.argv.slice(2);

let passed = 0;
const failures = [];

function check(name, fn) {
  try {
    fn();
    passed++;
  } catch (err) {
    failures.push(`${name}: ${err.message}`);
  }
}

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

function expectThrows(kind, name, fn) {
  try {
    fn();
  } catch (err) {
    assert(err instanceof kind, `${name}: expected ${kind.name}, got ${err.constructor.name}: ${err.message}`);
    return;
  }
  throw new Error(`${name}: expected ${kind.name}, nothing was thrown`);
}

const readCsv = (p) =>
  readFileSync(p, 'utf8')
    .split(/\r?\n/)
    .filter((l) => l.trim())
    .map((l) => l.split(',').map((c) => c.trim().replace(/"/g, '')));

const dbKey = readFileSync(keyPath, 'utf8').trim();
const db = loadDatabase(readFileSync(dbPath), dbKey);
const devices = JSON.parse(readFileSync(devicesPath, 'utf8')).keys;

const devicesInFile = csvPaths.reduce((n, path) => n + readCsv(path).length, 0);
console.log(`rows ${db.rowCount} (${devicesInFile} devices + padding)  build ${db.version}  salt ${bytesToHex(db.salt)}`);

check('header fields', () => {
  assert(db.uidLen === 16, `uid_len should be 16, got ${db.uidLen}`);
  assert(db.rowCount > devicesInFile, `no padding: ${db.rowCount} rows for ${devicesInFile} devices`);
  assert((db.rowCount & (db.rowCount - 1)) === 0, `row count ${db.rowCount} is not a power of two`);
});

// The real factory rows cannot be exercised through a signature — nobody holds those private keys —
// but every one of them proves the builder and the verifier agree on framing, salt and layout.
let realRows = 0;
for (const csv of csvPaths) {
  for (const [uidHex, pubHex] of readCsv(csv)) {
    const at = findRow(db, rowHash(db.salt, hexToBytes(uidHex), hexToBytes(pubHex)));
    assert(at >= 0, `real row ${uidHex} not found in the database`);
    realRows++;
  }
}
passed++;
console.log(`all ${realRows} factory rows located by hash`);

const challengeOf = () => crypto.getRandomValues(new Uint8Array(32));

for (const variant of ['high-s', 'low-s', 'as-signed']) {
  let ok = 0;
  for (const dev of devices) {
    const challenge = challengeOf();
    const opts = variant === 'high-s' ? { forceHighS: true } : variant === 'low-s' ? { forceLowS: true } : {};
    const { sig } = deviceSign(dev.priv, hexToBytes(dev.uid), challenge, opts);
    const res = verifyDeviceResponse(db, challenge, responseBytes({ uid: hexToBytes(dev.uid), challenge, sig }));
    assert(bytesToHex(res.pubkey) === dev.pub, `recovered key mismatch for ${dev.uid}`);
    ok++;
  }
  passed++;
  console.log(`${variant}: ${ok}/${devices.length} devices verified`);
}

const dev = devices[0];
const uid = hexToBytes(dev.uid);
const challenge = challengeOf();
const { sig } = deviceSign(dev.priv, uid, challenge);
const good = responseBytes({ uid, challenge, sig });

check('happy path round-trips through a UR string', () => {
  const text = urEncode('DEV-AUTH', good);
  assert(text.startsWith('UR:DEV-AUTH/'), `bad UR text ${text.slice(0, 20)}`);
  const res = verifyDeviceResponse(db, challenge, urDecode(text, 'DEV-AUTH'));
  assert(bytesToHex(res.pubkey) === dev.pub, 'key mismatch');
});

check('a malleated signature still verifies, and yields the same key', () => {
  const N = secp256k1.Point.Fn.ORDER;
  const s = secp256k1.Signature.fromBytes(sig);
  const malleated = Uint8Array.from([...sig.subarray(0, 32), ...hexToBytes((N - s.s).toString(16).padStart(64, '0'))]);
  const res = verifyDeviceResponse(db, challenge, responseBytes({ uid, challenge, sig: malleated }));
  assert(bytesToHex(res.pubkey) === dev.pub, 'malleation changed the key');
});

check('replay against a different challenge is not registered', () => {
  expectThrows(NotRegistered, 'replay', () => verifyDeviceResponse(db, challengeOf(), good));
});

check('a registered uid signed by an unlisted key is not registered', () => {
  const other = crypto.getRandomValues(new Uint8Array(32));
  const c = challengeOf();
  const { sig: foreign } = deviceSign(bytesToHex(other), uid, c);
  expectThrows(NotRegistered, 'clone', () => verifyDeviceResponse(db, c, responseBytes({ uid, challenge: c, sig: foreign })));
});

check('an unlisted uid is not registered', () => {
  const ghost = hexToBytes('ffffffffffffffffffffffffffffffff');
  const c = challengeOf();
  const { sig: ghostSig } = deviceSign(devices[1].priv, ghost, c);
  expectThrows(NotRegistered, 'ghost', () => verifyDeviceResponse(db, c, responseBytes({ uid: ghost, challenge: c, sig: ghostSig })));
});

const tampered = [
  ['a reserved response key', () => responseBytes({ uid, challenge, sig, extra: [[3, uint(1)]] })],
  ['another reserved response key', () => responseBytes({ uid, challenge, sig, extra: [[5, uint(7)]] })],
  ['an unknown map key', () => responseBytes({ uid, challenge, sig, extra: [[42, uint(1)]] })],
  ['the init step instead of the device step', () => responseBytes({ step: 1, uid, challenge, sig })],
  ['a missing challenge field', () => responseBytes({ uid, challenge: null, sig })],
  ['a missing signature', () => responseBytes({ uid, challenge, sig: null })],
  ['dev_id without tag 37', () => responseBytes({ uid, challenge, sig, tagDevId: false })],
  ['dev_id truncated to the 96-bit ID', () => responseBytes({ uid: uid.subarray(0, 12), challenge, sig })],
  ['an indefinite-length map', () => responseBytes({ uid, challenge, sig, definite: false })],
  ['a signature one byte too long', () => responseBytes({ uid, challenge, sig: Uint8Array.from([...sig, 0x00]) })],
];

for (const [name, build] of tampered) {
  check(`refused: ${name}`, () => expectThrows(Refusal, name, () => verifyDeviceResponse(db, challenge, build())));
}

check('refused: a tampered row', () => {
  const bytes = Uint8Array.from(readFileSync(dbPath));
  bytes[64] ^= 0x01;
  expectThrows(Refusal, 'tampered row', () => loadDatabase(bytes, dbKey));
});

// A mutation of the header also breaks the signature, so these assert on the message: matching only
// the exception type would pass when the signature check caught it instead of the field check.
function expectRefusalSaying(pattern, fn) {
  try {
    fn();
  } catch (err) {
    assert(pattern.test(err.message), `expected ${pattern} in "${err.message}", got ${err.constructor.name}`);
    return;
  }
  throw new Error(`expected a refusal matching ${pattern}, nothing was thrown`);
}

function mutate(offset, value) {
  const bytes = Uint8Array.from(readFileSync(dbPath));
  new DataView(bytes.buffer).setUint8(offset, value);
  return bytes;
}

check('refused: a uid length this reader was not built for', () => {
  expectRefusalSaying(/uid length/, () => loadDatabase(mutate(6, 24), dbKey));
});

check('refused: an unknown format version', () => {
  const bytes = mutate(4, 2);
  expectRefusalSaying(/format version/, () => loadDatabase(bytes, dbKey));
});

check('refused: reserved header bytes set', () => {
  expectRefusalSaying(/reserved/, () => loadDatabase(mutate(7, 1), dbKey));
  expectRefusalSaying(/reserved/, () => loadDatabase(mutate(40, 1), dbKey));
});

check('refused: a different signing key', () => {
  const other = secp256k1.getPublicKey(crypto.getRandomValues(new Uint8Array(32)), true);
  expectThrows(Refusal, 'wrong pinned key', () => loadDatabase(readFileSync(dbPath), bytesToHex(other)));
});

check('refused: rows out of order', () => {
  const signingKey = readFileSync('out/dev-signing.key', 'utf8').trim();
  const rows = [rowHash(db.salt, hexToBytes(devices[0].uid), hexToBytes(devices[0].pub))];
  const second = new Uint8Array(32).fill(0x01);
  const body = Uint8Array.from([...second, ...rows]);
  const header = Uint8Array.from(readFileSync(dbPath).subarray(0, 64));
  new DataView(header.buffer).setUint32(8, 2, true);
  const prefix = Uint8Array.from([...header, ...body]);
  const signature = secp256k1.sign(sha256(prefix), hexToBytes(signingKey), { prehash: false, format: 'compact' });
  expectThrows(Refusal, 'unsorted', () => loadDatabase(Uint8Array.from([...prefix, ...signature]), dbKey));
});

// `UR:` prefix, type label to the next '/', then bytewords with a four byte CRC-32 verified before
// anything else is read. Base32 fails here without a message: digits are not in
// the bytewords alphabet, which is what a "the QR just will not scan" report looks like.
check('the challenge text follows the device framing rules', () => {
  const c = challengeOf();
  const payload = encodeDevAuthInit(c);
  const text = urEncode('DEV-AUTH', payload);
  const [header, body] = [text.slice(0, text.indexOf('/')), text.slice(text.indexOf('/') + 1)];
  assert(/^UR:DEV-AUTH$/.test(header), `header ${header}`);
  assert(/^[a-z]+$/.test(body), `body is not lowercase letters only: ${body.slice(0, 24)}`);
  assert(body.length === (payload.length + 4) * 2, `body ${body.length} != ${(payload.length + 4) * 2} (two letters per byte plus a 4 byte checksum)`);

  const bodyBytes = urDecode(text, 'DEV-AUTH');
  assert(bytesToHex(bodyBytes) === bytesToHex(payload), 'round trip lost bytes');

  // The last four bytes are a checksum; naming it without trusting the encoder means re-deriving it
  // elsewhere, so: encode the CRC-32 on its own and require it to be the tail. Equal strings prove
  // the algorithm is CRC-32 big-endian, which is what app/ur/bytewords.c computes.
  const want = (crc32(payload) >>> 0).toString(16).padStart(8, '0');
  const crcText = encodeBytewords(Uint8Array.from(Buffer.from(want, 'hex')), 'minimal').slice(0, 8);
  assert(body.endsWith(crcText), `tail ${body.slice(-8)} is not CRC-32 ${want} encoded (${crcText})`);
});


check('a base32 payload is refused, as the device refuses it', () => {
  expectThrows(Error, 'base32', () => urDecode('UR:DEV-AUTH/IBSGAYTBOJSXG42PNRSGK5DBN5ZGK5DUPBSXG2DB', 'DEV-AUTH'));
});

check('a multi-part UR is refused', () => {
  expectThrows(Error, 'multi-part', () => urDecode('UR:DEV-AUTH/1-3/oeadadamhdcxae', 'DEV-AUTH'));
});

check('a corrupted bytewords body is refused', () => {
  const c = challengeOf();
  const text = urEncode('DEV-AUTH', encodeDevAuthInit(c));
  const cut = text.length - 2;
  expectThrows(Error, 'checksum', () => urDecode(text.slice(0, cut) + (text.endsWith('lk') ? 'jl' : 'lk'), 'DEV-AUTH'));
});

check('the challenge QR is what the firmware decoder demands', () => {
  // ui_qrscan feeds this straight into cbor_decode_dev_auth, which expects a definite map with
  // step 1 and a 32 byte challenge and rejects the QR if any other field is present.
  const c = challengeOf();
  const bytes = encodeDevAuthInit(c);
  const expect = Uint8Array.from([0xa2, 0x01, 0x01, 0x06, 0x58, 0x20, ...c]);
  assert(bytes.length === expect.length, `length ${bytes.length} != ${expect.length}`);
  for (let i = 0; i < expect.length; i++) assert(bytes[i] === expect[i], `byte ${i} differs`);
});

check('a QR string round-trips through the same text a scanner returns', () => {
  const c = challengeOf();
  const lower = urEncode('DEV-AUTH', encodeDevAuthInit(c)).toLowerCase();
  const back = urDecode(lower, 'DEV-AUTH');
  assert(bytesToHex(back) === bytesToHex(encodeDevAuthInit(c)), 'case folding lost bytes');
});

check('refused: a truncated file', () => {
  expectThrows(Refusal, 'truncated', () => loadDatabase(readFileSync(dbPath).subarray(0, 4096), dbKey));
});

console.log(`\n${passed} checks passed, ${failures.length} failed`);
for (const f of failures) console.log(`FAIL ${f}`);
process.exit(failures.length ? 1 : 0);
