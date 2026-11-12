// Drives the actual page module — index.html's element ids plus web/app.js — with no browser, so a
// click that binds to nothing, or a verdict that goes somewhere the user is not looking, fails a test
// instead of arriving as "I clicked and nothing happened".
//
// Only what app.js touches is shimmed: a registry of elements keyed by the ids in the HTML, a fetch
// that serves the built database, and the two window listeners it installs for unhandled errors.

import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

const HTML = readFileSync(resolve(import.meta.dirname, '../web/index.html'), 'utf8');
const dbPath = process.argv[2];
const devicesPath = process.argv[3];
const dbBytes = new Uint8Array(readFileSync(dbPath));
const { keys } = JSON.parse(readFileSync(devicesPath, 'utf8'));

const checks = [];
const check = (name, fn) => {
  try {
    fn();
    checks.push([true, name]);
  } catch (err) {
    checks.push([false, `${name}\n    ${String(err.message ?? err).split('\n')[0]}`]);
  }
};

class El {
  constructor(id) {
    this.id = id;
    this.value = '';
    this.textContent = '';
    this.innerHTML = '';
    this.hidden = false;
    this.className = '';
    this.listeners = {};
    this.scrolled = 0;
  }

  addEventListener(type, fn) {
    (this.listeners[type] ??= []).push(fn);
  }

  async click() {
    for (const fn of this.listeners.click ?? []) await fn({ target: this });
  }

  scrollIntoView() {
    this.scrolled++;
  }
}

const elements = new Map();
for (const id of new Set(HTML.match(/id="([^"]+)"/g).map((m) => m.slice(4, -1)))) {
  elements.set(id, new El(id));
}

// A click must not depend on where the page is scrolled: the verdict is the only feedback there is.
const status = () => elements.get('result').innerHTML;
const clicked = async (id) => {
  await elements.get(id).click();
  await new Promise((r) => setTimeout(r, 0));
};

globalThis.document = {
  getElementById: (id) => elements.get(id) ?? null,
  createElement: () => new El('created'),
};
globalThis.window = { addEventListener: () => {} };
globalThis.localStorage = { getItem: () => null, setItem: () => {} };
globalThis.fetch = async () => ({ ok: true, arrayBuffer: async () => dbBytes.buffer });

// app.js pins the release verification key in config.js, and the fixture database is signed with a
// throwaway. Rather than weaken the shipped page, the module under test gets its import specifiers
// rewritten to a fixture config; the real config.js is never edited and never under test here.
const ROOT = resolve(import.meta.dirname, '..');
const testKey = readFileSync(resolve(ROOT, 'out/test-verify-key.hex'), 'utf8').trim();
writeFileSync(
  resolve(ROOT, 'out/config.fixture.js'),
  `export const VERIFY_KEY = '${testKey}';\nexport const DB_URL = './db.bin';\n`,
);
const appSource = readFileSync(resolve(ROOT, 'web/app.js'), 'utf8')
  .replaceAll("from './", "from '../web/")
  .replace("from '../web/config.js'", "from './config.fixture.js'");
writeFileSync(resolve(ROOT, 'out/page-app.js'), appSource);

const { responseBytes, deviceSign } = await import('./response.mjs');
const { hexToBytes } = await import('../web/dist/shvr-vendor.js');
const { urEncode, DEV_AUTH_TYPE } = await import('../web/ur.js');
await import('../out/page-app.js');

check('every id the page references exists in the HTML', () => {
  const app = readFileSync(resolve(import.meta.dirname, '../web/app.js'), 'utf8');
  const referenced = [...app.matchAll(/\$\('([^']+)'\)/g)].map((m) => m[1]);
  const missing = referenced.filter((id) => !elements.has(id));
  if (missing.length) throw new Error(`no such element: ${missing.join(', ')}`);
});

check('the Verify button is bound', () => {
  const bound = [...elements.values()].filter((el) => (el.listeners.click ?? []).length);
  if (!elements.get('checkBtn').listeners.click?.length) throw new Error('checkBtn has no click handler');
  if (bound.length < 4) throw new Error(`only ${bound.length} controls have handlers`);
});

await clicked('fetchUrl');
check('loading the database is reported', () => {
  if (!status().includes('authenticates')) throw new Error(`status says: ${status().slice(0, 60)}`);
});

await clicked('startBtn');
check('starting a verification renders a QR and a challenge', () => {
  if (!elements.get('qr').innerHTML.includes('<svg')) throw new Error('no svg rendered');
  if (!/^[0-9a-f]{64}$/.test(elements.get('challengeHex').textContent)) throw new Error('no challenge shown');
  if (elements.get('session').hidden) throw new Error('session block still hidden');
});

const challenge = Uint8Array.from(Buffer.from(elements.get('challengeHex').textContent, 'hex'));
const device = keys[0];
const { sig } = deviceSign(device.priv, hexToBytes(device.uid), challenge);
// Field 6 holds the device's own random bytes, never the challenge it was handed.
const reply = responseBytes({ uid: hexToBytes(device.uid), challenge: crypto.getRandomValues(new Uint8Array(32)), sig });
const text = urEncode(DEV_AUTH_TYPE, reply);
elements.get('response').value = text;
await clicked('checkBtn');

check('verifying a real answer puts the verdict where the click was', () => {
  if (!status().includes('Device verified')) throw new Error(`status says: ${status().slice(0, 80)}`);
  if (!status().includes(device.uid)) throw new Error('verdict does not name the uid');
  if (elements.get('result').scrolled === 0) throw new Error('verdict never scrolled into view');
  if (!elements.get('echo').textContent.includes('verified')) throw new Error(`nothing echoed by the button: "${elements.get('echo').textContent}"`);
});

elements.get('response').value = 'UR:DEV-AUTH/nonsense';
await clicked('checkBtn');
check('a bad answer replaces the verdict with a refusal', () => {
  if (!/Refused|not a device auth response/i.test(status())) throw new Error(`status says: ${status().slice(0, 80)}`);
});

for (const [ok, name] of checks) console.log(`${ok ? 'ok  ' : 'FAIL'} ${name}`);
const failed = checks.filter(([ok]) => !ok).length;
console.log(`\n${checks.length - failed} page checks passed, ${failed} failed`);
process.exitCode = failed ? 1 : 0;
