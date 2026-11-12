"""Build a signed SHVR device database from factory CSV exports.

Each input row is `<uid hex>,<compressed pubkey hex>` — the payload of INS_GET_APP_CONF, as
produced by tools/device-csv.py. The output is a sorted array of row hashes plus a signature, and
it reveals nothing on its own: see docs/format.md.
"""

import argparse
import csv
import glob
import hashlib
import os
import re
import secrets
import struct
from datetime import datetime

from shvr import (
    FORMAT_VERSION,
    HEADER_SIZE,
    INDEX_LEN,
    MAGIC,
    PUBKEY_LEN,
    SECP256K1_N,
    SECP256K1_P,
    SIG_SIZE,
    TAG_PUBKEY,
    TAG_UID,
    UID_LEN,
)

HEX_RE = re.compile(rb"^[0-9a-f]+$")


def row_hash(salt, uid, pubkey):
    assert len(salt) == 16 and len(uid) == UID_LEN and len(pubkey) == PUBKEY_LEN
    return hashlib.sha256(salt + TAG_UID + uid + TAG_PUBKEY + pubkey).digest()


def is_valid_pubkey(pubkey):
    """Reject anything that is not a compressed point on secp256k1.

    A non-point costs nothing at verify time — recovery could never yield it — but it would sit in
    a published file unnoticed, and the device it was meant to describe fails years later with no
    way to tell that from a revoked one.
    """
    if len(pubkey) != PUBKEY_LEN or pubkey[0] not in (0x02, 0x03):
        return False
    x = int.from_bytes(pubkey[1:], "big")
    if x >= SECP256K1_P:
        return False
    y2 = (pow(x, 3, SECP256K1_P) + 7) % SECP256K1_P
    return pow(y2, (SECP256K1_P - 1) // 2, SECP256K1_P) in (0, 1)


def expand_inputs(inputs):
    """CSV files, with directories standing for every .csv directly inside them.

    A release is one or more batches, and batches arrive as a folder. Sorting keeps a build
    reproducible from the same folder contents, since the filesystem gives no order of its own.
    """
    paths = []
    for entry in inputs:
        if os.path.isdir(entry):
            found = sorted(glob.glob(os.path.join(entry, "*.csv")))
            if not found:
                raise SystemExit(f"{entry}: no .csv files inside")
            paths.extend(found)
        elif os.path.isfile(entry):
            paths.append(entry)
        else:
            raise SystemExit(f"{entry}: no such file or directory")
    if not paths:
        raise SystemExit("no input given")
    return dict.fromkeys(paths)


def read_csv(path):
    rows = []
    with open(path, "rb") as f:
        for lineno, record in enumerate(csv.reader(f.read().decode().splitlines(), quotechar=None), 1):
            if not record or all(not c.strip() for c in record):
                continue
            if len(record) != 2:
                raise SystemExit(f"{path}:{lineno}: expected 2 fields, found {len(record)}")
            uid, pubkey = (c.strip().replace('"', "") for c in record)
            uid, pubkey = uid.encode(), pubkey.encode()
            if len(uid) != UID_LEN * 2 or not HEX_RE.match(uid):
                raise SystemExit(f"{path}:{lineno}: uid must be {UID_LEN} bytes of lowercase hex")
            if len(pubkey) != PUBKEY_LEN * 2 or not HEX_RE.match(pubkey):
                raise SystemExit(f"{path}:{lineno}: pubkey must be {PUBKEY_LEN} bytes of lowercase hex")
            uid, pubkey = bytes.fromhex(uid.decode()), bytes.fromhex(pubkey.decode())
            if not is_valid_pubkey(pubkey):
                raise SystemExit(f"{path}:{lineno}: not a compressed secp256k1 point")
            rows.append((uid, pubkey))
    return rows


def make_rows(devices, salt, pad_to, rng):
    """Sorted row hashes, padded with random decoys to `pad_to` entries.

    Decoys are random, never derived: a derivable decoy is one a reader can recompute and strip,
    which would expose the true device count behind `row_count`.
    """
    rows = [row_hash(salt, uid, pubkey) for uid, pubkey in devices]
    if len(set(rows)) != len(rows):
        raise SystemExit("duplicate row hash: the same uid/pubkey pair appears twice")

    decoys = pad_to - len(rows)
    if decoys < 0:
        raise SystemExit(f"{pad_to} padding slots is fewer than the {len(rows)} devices")

    taken = set(rows)
    for _ in range(decoys):
        while True:
            d = rng(INDEX_LEN)
            if d not in taken:
                taken.add(d)
                rows.append(d)
                break

    rows.sort()
    return rows, decoys


def pack_header(row_count, salt, version):
    header = struct.pack("<4sHBB", MAGIC, FORMAT_VERSION, UID_LEN, 0)
    header += struct.pack("<I", row_count)
    header += salt
    header += struct.pack("<I", version)
    header += bytes(HEADER_SIZE - len(header))
    assert len(header) == HEADER_SIZE
    return header


def load_sign_key(path):
    with open(path) as f:
        text = "".join(line.split("#")[0] for line in f).strip()
    try:
        key = bytes.fromhex(text)
    except ValueError:
        raise SystemExit(f"{path}: expected a hex secp256k1 key")
    if len(key) != 32:
        raise SystemExit(f"{path}: expected a 32 byte key")
    return key


def sign_local(key_bytes, digest):
    from cryptography.hazmat.primitives.asymmetric import ec, utils as ec_utils
    from cryptography.hazmat.primitives import hashes

    key = ec.derive_private_key(int.from_bytes(key_bytes, "big"), ec.SECP256K1())
    der = key.sign(digest, ec.ECDSA(ec_utils.Prehashed(hashes.SHA256())))
    r, s = ec_utils.decode_dss_signature(der)
    if s > SECP256K1_N >> 1:
        s = SECP256K1_N - s
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def public_key_of(key_bytes):
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    key = ec.derive_private_key(int.from_bytes(key_bytes, "big"), ec.SECP256K1())
    return key.public_key().public_bytes(Encoding.X962, PublicFormat.CompressedPoint)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("-f", "--file", action="append", required=True,
                        help="csv file, or a directory holding them; repeatable")
    parser.add_argument("-o", "--output", required=True)
    parser.add_argument("-v", "--version", type=int, default=int(datetime.now().strftime("%Y%m%d")),
                        help="build version, YYYYMMDD")
    parser.add_argument("--salt", help="16 random bytes hex; generated if omitted")
    parser.add_argument("--pad-to", type=int, default=0,
                        help="total rows after padding, 0 selects the next power of two")
    parser.add_argument("--no-decoys", action="store_true", help="no padding rows")
    parser.add_argument("-s", "--sign-key", help="file holding a hex secp256k1 signing key")
    parser.add_argument("--new-key", metavar="FILE", help="write a throwaway signing key here")
    parser.add_argument("-k", "--keycard", action="store_true", help="sign with a Keycard")
    parser.add_argument("-d", "--dummy-sign", action="store_true",
                        help="digest and zeroes where the signature goes, to compare builds")
    parser.add_argument("--verify-key", metavar="FILE", help="write the pinned public key hex here")
    args = parser.parse_args()

    if args.salt:
        salt = bytes.fromhex(args.salt)
        if len(salt) != 16:
            raise SystemExit("--salt must be 16 bytes")
    else:
        salt = secrets.token_bytes(16)

    devices = []
    seen = {}
    for path in expand_inputs(args.file):
        for uid, pubkey in read_csv(path):
            if uid in seen:
                raise SystemExit(f"{path}: uid {uid.hex()} duplicated (also in {seen[uid]})")
            seen[uid] = path
            devices.append((uid, pubkey))
    dup_keys = len(devices) - len({p for _, p in devices})
    if dup_keys:
        raise SystemExit(f"{dup_keys} pubkeys are duplicated across inputs")

    if args.no_decoys:
        pad_to = len(devices)
    elif args.pad_to:
        pad_to = args.pad_to
    else:
        pad_to = 1 << len(devices).bit_length()

    rows, decoys = make_rows(devices, salt, pad_to, secrets.token_bytes)

    prefix = pack_header(len(rows), salt, args.version) + b"".join(rows)

    if bool(args.sign_key) + bool(args.keycard) + bool(args.dummy_sign) + bool(args.new_key) != 1:
        raise SystemExit("choose exactly one of --sign-key, --new-key, --keycard, --dummy-sign")

    key_bytes = None
    if args.new_key:
        if os.path.exists(args.new_key):
            raise SystemExit(f"{args.new_key} exists, refusing to overwrite a signing key")
        key_bytes = secrets.token_bytes(32)
        with open(args.new_key, "w") as f:
            f.write(key_bytes.hex() + "\n")
        os.chmod(args.new_key, 0o600)
    elif args.sign_key:
        key_bytes = load_sign_key(args.sign_key)

    digest = hashlib.sha256(prefix).digest()
    if key_bytes is not None:
        signature = sign_local(key_bytes, digest)
    elif args.keycard:
        from keycardsign import keycard_sign
        from shvr import KEYCARD_PATH

        signature = keycard_sign(KEYCARD_PATH, digest)
    else:
        signature = digest + bytes(32)

    if len(signature) != SIG_SIZE:
        raise SystemExit("signature must be 64 bytes")

    with open(args.output, "wb") as f:
        f.write(prefix + signature)

    if args.verify_key:
        pub = public_key_of(key_bytes) if key_bytes else None
        if pub is None:
            raise SystemExit("--verify-key needs --sign-key or --new-key")
        with open(args.verify_key, "w") as f:
            f.write(pub.hex() + "\n")

    print(f"devices   {len(devices)}")
    print(f"padding   {decoys}")
    print(f"rows      {len(rows)}")
    print(f"version   {args.version}")
    print(f"salt      {salt.hex()}")
    print(f"file      {args.output} ({len(prefix) + SIG_SIZE} bytes)")
    print(f"digest    {digest.hex()}")
    if key_bytes:
        print(f"pubkey    {public_key_of(key_bytes).hex()}")


if __name__ == "__main__":
    main()
