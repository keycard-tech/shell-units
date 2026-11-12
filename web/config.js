// The one value that changes between a development tree and a release.
//
// Pinned rather than fetched: the file's signature is the only attestation that a (uid, key) pair was
// put there by the manufacturer, so the key cannot come from wherever the file came from.

export const VERIFY_KEY = '033dcc3ece8f9bc5a25c7ba30ddcc8c63bcdb03a562058bbb3234d6874b50f5fea';

export const DB_URL = './db.bin';
