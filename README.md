# Shell device allowlist

A signed, anonymised list of shipped devices and a static page that checks one device against it. No
server, no account, nothing fetched at run time beyond the file you point the page at.

Each device contributes one 32-byte row:

    SHA256(salt ‖ "ShellUID" ‖ uid ‖ "ShellPubKey" ‖ pubkey)

Computing a row needs the uid and the public key together, so the file names no device. A verifier
gets both from the device: the uid in its response, the key by recovering it from a signature over a
challenge the verifier chose.

`docs/format.md` is the specification: byte layout, verification steps, the device exchange.

## Layout

    tools/build-db.py    build and sign a database from CSV exports
    tools/shvr.py        format constants, one definition each
    tools/keycardsign.py Keycard signing for releases
    web/                 the verification page
    tests/               end-to-end checks against a built file

## Building

Tools are Python; `pyproject.toml` lists them. Release signing additionally needs the Keycard extra.

    pip install -e .            # or: pip install -e .[keycard]

Input rows are `<uid hex>,<compressed pubkey hex>`, one per device; `tools/device-csv.py` produces them
from a factory export. `-f` takes a file or a directory of CSVs, and repeats.

    python3 tools/build-db.py \
      -f input-files/ \
      -o out/db.bin -v 20261112 \
      --sign-key out/signing.key --verify-key out/verify-key.hex

| flag | |
|---|---|
| `-k`, `--keycard` | sign on a Keycard at `m/43'/60'/1581'/1397249618'/0` |
| `-s`, `--sign-key FILE` | hex secp256k1 key in a file, for development |
| `--new-key FILE` | generate a throwaway key, refuse to overwrite |
| `-d`, `--dummy-sign` | digest and zeroes where the signature goes, to compare builds unsigned |
| `--pad-to N` | padding rows; default is the next power of two above the device count |
| `--no-decoys` | no padding rows |
| `--salt HEX` | fixed salt, for reproducing a build |

Output is a 64-byte header, sorted row hashes, and a 64-byte signature over `SHA256` of everything
before it: the same convention as keycard-eth-db, so a hash-and-check tool for that format works here.

Row padding means `row_count` is not a device count. Keep batch identifiers out of the filename.

## The page

    cd web && python3 -m http.server

Load `db.bin`, press **New verification**, scan the QR on the device, then read the QR it shows back,
by camera or by pasting the `UR:DEV-AUTH/…` text. Three outcomes: **verified**, with the recovered key;
**not in this database**; and **refused** for anything malformed, tampered with or unsupported. The
last says nothing about the device and is never reported as the second.

`web/dist/*.js` are prebuilt bundles so serving needs no build step; `npm run bundle` in `web/`
rebuilds them and `web/NOTICE` names what is inside.

## Tests

    ./tests/run.sh

Synthetic devices are generated with their keys, since a real device's private key is created in
hardware and cannot be exported. The suite builds a database and checks: row location by hash,
verification over high-`s`, low-`s` and as-signed signatures, the exchange round-tripped through QR
text, replay and cloned-uid rejection, and refusals for tampering, wrong keys, unsorted rows,
truncated files, reserved response keys, missing tags and bad lengths. It also runs the page's own
click path headlessly, and fails if any uid, public key or lot code from `input-files/` appears
anywhere else in the repository.

## Release

`web/config.js` pins the verification key:

    033dcc3ece8f9bc5a25c7ba30ddcc8c63bcdb03a562058bbb3234d6874b50f5fea

Sign with a Keycard and keep it offline. A rebuild is not the same file: padding rows come from the OS
CSPRNG and the ECDSA nonce is random. Pass `--salt` and `--no-decoys` and a rebuild reproduces the
signed digest exactly, which is what a signature attests to; verifiers check a signature against the
file in front of them, never against a copy of one.
