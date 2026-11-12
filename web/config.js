// The one value that changes between a development tree and a release.
//
// Pinned rather than fetched: the file's signature is the only attestation that a (uid, key) pair was
// put there by the manufacturer, so the key cannot come from wherever the file came from.

export const VERIFY_KEY = '032ac68f2b2a500ebf1bc31f0c36e4645b24530ce6d1460e92c2d94e9a47ba550e';

export const DB_URL = './db.bin';
