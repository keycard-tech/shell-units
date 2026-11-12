// Emits a CSV of synthetic devices plus their private keys, so the tests can play the part of a
// device. The real factory CSVs hold only public keys — the private half lives in each unit's
// hardware and is never exportable — so an end-to-end signature test has to bring its own keys.

import { writeFileSync } from 'node:fs';
import { secp256k1, bytesToHex, hexToBytes } from '../web/dist/shvr-vendor.js';

const N = Number(process.argv[3] || 24);
const csvPath = process.argv[2];
const keysPath = process.argv[4] || 'out/test-devices.json';

const uids = new Set();
const rows = [];
const keys = [];

while (rows.length < N) {
  // 0xff 0xff prefix keeps synthetic uids from ever colliding with a factory row in the same file.
  const uid = new Uint8Array(16);
  crypto.getRandomValues(uid);
  uid[0] = 0xff;
  uid[1] = 0xff;
  const key = bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
  const pub = secp256k1.getPublicKey(hexToBytes(key), true);
  const uidHex = bytesToHex(uid);
  if (uids.has(uidHex)) continue;
  uids.add(uidHex);
  rows.push(`${uidHex},${bytesToHex(pub)}`);
  keys.push({ uid: uidHex, priv: key, pub: bytesToHex(pub) });
}

writeFileSync(csvPath, rows.join('\r\n') + '\r\n');
writeFileSync(keysPath, JSON.stringify({ keys, saltHint: null }, null, 1));
console.log(`${rows.length} synthetic devices -> ${csvPath}, keys -> ${keysPath}`);
