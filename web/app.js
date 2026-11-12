import { qrcode, bytesToHex, hexToBytes } from './dist/shvr-vendor.js';
import { loadDatabase, verifyDeviceResponse, Refusal, NotRegistered } from './db.js';
import { urEncode, urDecode, DEV_AUTH_TYPE } from './ur.js';
import { encodeDevAuthInit } from './cbor.js';
import { VERIFY_KEY, DB_URL } from './config.js';

const $ = (id) => document.getElementById(id);

let db = null;
let challenge = null;
let scanner = null;
let lastError = null;

// The verdict box lives at the top of a page long enough that clicking Verify leaves it far off
// screen, which reads exactly like the button doing nothing. So the same call echoes one line where
// the click happened and drags the box into view; one writer, so the two can never disagree.
const VERDICT = { ok: 'verified', warn: 'not registered', bad: 'refused', neutral: '' };

function setStatus(kind, message, detail = '') {
  const box = $('result');
  box.className = `result ${kind}`;
  box.innerHTML = `<strong>${message}</strong>` + (detail ? `<pre>${esc(detail)}</pre>` : '');
  $('echo').textContent = VERDICT[kind] ? `→ ${message}` : '';
  $('echo').className = `echo ${kind}`;
  document.title = `${VERDICT[kind] ? VERDICT[kind].toUpperCase() + ' · ' : ''}Shell allowlist verifier`;
  box.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
}

function esc(text) {
  return String(text).replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));
}

// The reason a click can appear to do nothing: handleResponse is async, so a throw inside it is a
// rejected promise, and a rejected promise is silent unless something catches it. Everything the page
// can do wrong has to end up on screen, because a verifier the user cannot interrogate gets guessed at.
window.addEventListener('unhandledrejection', (event) => {
  lastError = event.reason;
  setStatus('bad', 'Unexpected error', describe(event.reason));
});
window.addEventListener('error', (event) => {
  lastError = event.error ?? event.message;
  setStatus('bad', 'Unexpected error', describe(event.error ?? event.message));
});

function describe(err) {
  if (err instanceof Error) return `${err.name}: ${err.message}\n\n${err.stack ?? ''}`;
  return String(err);
}

function dbSummary() {
  return `build ${db.version} · salt ${bytesToHex(db.salt)}`;
}

async function adoptDatabase(buffer) {
  try {
    db = loadDatabase(buffer, VERIFY_KEY);
  } catch (err) {
    db = null;
    $('dbInfo').textContent = '';
    if (err instanceof Refusal) {
      setStatus('bad', 'Database refused', err.message);
    } else {
      setStatus('bad', 'Could not read the database', String(err));
    }
    return false;
  }
  $('dbInfo').textContent = dbSummary();
  setStatus('ok', 'Database authenticates', 'The pinned key signed this file. Ready to verify a device.');
  return true;
}

// The Shell's camera needs three things the browser does not care about: a quiet zone at least four
// modules wide, integer-sized modules (a scaled SVG blurs every edge and blurring is what a fixed
// focus camera cannot recover from), and a genuinely white surround, which dark mode otherwise eats.
// So the cell size is chosen to fit a target physical size rather than letting CSS scale the result.
function renderQr(text) {
  const target = Number($('qrSize').value);
  const qr = qrcode(0, 'L');
  qr.addData(text);
  qr.make();
  const margin = 4;
  const cells = qr.getModuleCount() + margin * 2;
  const cellSize = Math.max(2, Math.floor(target / cells));
  const svg = qr.createSvgTag({ cellSize, margin, scalable: false });
  $('qr').innerHTML = svg;
  $('qrPx').textContent = `${qr.getModuleCount()} modules, ${cellSize}px each = ${cells * cellSize}px`;
}

// A challenge is single use: freshness is the only thing standing between a captured transcript and
// an accepted one, so nothing here may cache, derive or reuse it.
function newChallenge() {
  challenge = crypto.getRandomValues(new Uint8Array(32));
  renderQr(urEncode(DEV_AUTH_TYPE, encodeDevAuthInit(challenge)));
  $('challengeHex').textContent = bytesToHex(challenge);
  $('session').hidden = false;
  $('response').value = '';
  setStatus('neutral', 'Scan this QR on the Shell', 'Then bring back the QR it displays.');
}

async function handleResponse(text) {
  if (!db) return setStatus('bad', 'No database', 'Load the signed file first.');
  if (!challenge) return setStatus('bad', 'No challenge', 'Start a verification so the device answers something fresh.');

  let payload;
  try {
    payload = urDecode(text, DEV_AUTH_TYPE);
  } catch (err) {
    return setStatus('bad', 'Refused: not a device auth response', err.message);
  }

  try {
    const result = verifyDeviceResponse(db, challenge, payload);
    setStatus('ok', 'Device verified', `uid      ${bytesToHex(result.uid)}\npubkey   ${result.hex}\nrow      ${result.row}`);
    return result;
  } catch (err) {
    lastError = err;
    if (err instanceof NotRegistered) {
      return setStatus('warn', 'Not in this database', `uid ${err.uid}\n\nThe signature is well-formed but no row matches. Either the device was not provisioned, or it is not the device it claims to be.`);
    }
    if (err instanceof Refusal) {
      return setStatus('bad', 'Refused', `${err.message}\n\nresponse ${payload.length} bytes, challenge ${bytesToHex(challenge).slice(0, 16)}…, database ${db.rowCount} rows v${db.version}`);
    }
    return setStatus('bad', 'Unexpected error', String(err && err.stack ? err.stack : err));
  }
}

async function startScan() {
  if (scanner) return stopScan();
  try {
    const { jsQR } = await import('./dist/shvr-scan.js');
    const stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } });
    const video = $('video');
    video.srcObject = stream;
    await video.play();
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d', { willReadFrequently: true });
    const tick = () => {
      if (!scanner) return;
      if (video.readyState === video.HAVE_ENOUGH_DATA) {
        canvas.width = video.videoWidth;
        canvas.height = video.videoHeight;
        ctx.drawImage(video, 0, 0);
        const frame = ctx.getImageData(0, 0, canvas.width, canvas.height);
        const found = jsQR(frame.data, canvas.width, canvas.height, { inversionAttempts: 'dontInvert' });
        if (found && found.data) {
          $('response').value = found.data;
          stopScan();
          handleResponse(found.data).catch((err) => setStatus('bad', 'Unexpected error', describe(err)));
          return;
        }
      }
      scanner.raf = requestAnimationFrame(tick);
    };
    scanner = { stream, raf: requestAnimationFrame(tick) };
    $('scanBtn').textContent = 'Stop camera';
    $('video').hidden = false;
  } catch (err) {
    setStatus('bad', 'Camera unavailable', `${err}\nPaste the QR contents instead — any scanner that yields the UR text will do.`);
  }
}

function stopScan() {
  if (!scanner) return;
  cancelAnimationFrame(scanner.raf);
  scanner.stream.getTracks().forEach((t) => t.stop());
  scanner = null;
  $('scanBtn').textContent = 'Scan with camera';
  $('video').hidden = true;
}

$('file').addEventListener('change', async (event) => {
  const [file] = event.target.files;
  if (file) await adoptDatabase(new Uint8Array(await file.arrayBuffer()));
});

$('fetchUrl').addEventListener('click', async () => {
  const url = $('dbUrl').value.trim() || DB_URL;
  try {
    const res = await fetch(url, { cache: 'no-store' });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    await adoptDatabase(new Uint8Array(await res.arrayBuffer()));
  } catch (err) {
    setStatus('bad', 'Could not fetch the database', `${url}: ${err}`);
  }
});

$('startBtn').addEventListener('click', newChallenge);
$('qrSize').addEventListener('change', () => {
  localStorage.setItem('qrSize', $('qrSize').value);
  if (challenge) renderQr(urEncode(DEV_AUTH_TYPE, encodeDevAuthInit(challenge)));
});
$('qrSize').value = localStorage.getItem('qrSize') || '192';
$('checkBtn').addEventListener('click', () => handleResponse($('response').value.trim()));
$('scanBtn').addEventListener('click', startScan);
window.addEventListener('beforeunload', stopScan);

try {
  const pinned = hexToBytes(VERIFY_KEY);
  if (pinned.length !== 33) throw new Error(`expected a 33 byte compressed key, got ${pinned.length}`);
  $('pinnedKey').textContent = VERIFY_KEY;
} catch (err) {
  setStatus('bad', 'The page is not configured', `web/config.js VERIFY_KEY: ${err.message}`);
}
