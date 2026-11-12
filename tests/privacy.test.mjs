// The anonymity argument depends on lot codes and uids staying out of anything published, and the
// page, the tests and the docs are all meant to be public. That is easy to violate by pasting an
// example, so the guarantee is enforced instead of remembered: no uid, public key or lot code from
// the factory CSVs may appear anywhere else in the repository.

import { readFileSync, readdirSync, statSync } from 'node:fs';
import { relative, resolve } from 'node:path';

const ROOT = resolve(import.meta.dirname, '..');
const csvPaths = process.argv.slice(2);
const SKIP = new Set(['.git', 'node_modules', 'input-files', 'out', 'dist', '__pycache__']);

const real = new Set();
for (const path of csvPaths) {
  for (const line of readFileSync(path, 'utf8').split(/\r?\n/)) {
    for (const field of line.split(',')) {
      const value = field.trim().toLowerCase();
      if (/^[0-9a-f]{32}$|^[0-9a-f]{66}$/.test(value)) real.add(value);
    }
  }
}
if (!real.size) {
  console.error('no factory rows read; refusing to report a clean result');
  process.exit(1);
}

const offenders = [];
const walk = (dir) => {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (SKIP.has(entry.name)) continue;
    const path = resolve(dir, entry.name);
    if (entry.isDirectory()) walk(path);
    else if (entry.isFile() && !statSync(path).isSymbolicLink?.()) inspect(path);
  }
};

function inspect(path) {
  const text = readFileSync(path, 'utf8').toLowerCase();
  const shown = relative(ROOT, path);
  for (const value of real) {
    if (text.includes(value)) offenders.push(`${shown}: ${value.slice(0, 16)}…`);
  }
  // Lot codes are the sharp one: they narrow a uid to a single production run.
  const lot = text.match(/\bq\d{6}\b/g);
  if (lot) offenders.push(`${shown}: lot code ${lot[0]}`);
}

walk(ROOT);

if (offenders.length) {
  console.log(`${new Set(offenders.map((o) => o.split(':')[0])).size} files carry factory identifiers:`);
  for (const o of [...new Set(offenders)].slice(0, 12)) console.log(`  ${o}`);
  process.exit(1);
}
console.log(`ok   no factory uid, public key or lot code outside input-files/ (${real.size} values searched)`);
