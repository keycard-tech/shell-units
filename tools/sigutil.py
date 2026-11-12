"""Signature helpers shared by the builder, the Keycard signer and the probe.

Everything the format needs to know about ECDSA shapes lives here: the wire form is a compact
64-byte r‖s normalised to low-S, while `cryptography` speaks DER and a card may hand back either.
"""

from cryptography.hazmat.primitives.asymmetric import ec, utils as ec_utils
from cryptography.hazmat.primitives import hashes

from shvr import SECP256K1_N


def signature_from_blob(blob):
    """(r, s) from compact 64, compact 64 with a recovery byte, or DER.

    Whatever is not one of those shapes is dumped as hex rather than guessed at: a signature
    silently mis-parsed here becomes a release that no verifier accepts, and the difference between
    those two outcomes is only visible months later.
    """
    if len(blob) in (64, 65):
        return int.from_bytes(blob[:32], "big"), int.from_bytes(blob[32:64], "big")

    if len(blob) >= 8 and blob[0] == 0x30:
        if blob[1] != len(blob) - 2:
            raise SystemExit(f"malformed DER signature ({len(blob)} bytes): {blob.hex()}")
        if blob[2] != 0x02:
            raise SystemExit(f"malformed DER signature, no r integer: {blob.hex()}")
        rlen = blob[3]
        r = int.from_bytes(blob[4:4 + rlen], "big")
        tail = 4 + rlen
        if tail + 2 > len(blob) or blob[tail] != 0x02:
            raise SystemExit(f"malformed DER signature, no s integer: {blob.hex()}")
        slen = blob[tail + 1]
        if tail + 2 + slen != len(blob):
            raise SystemExit(f"malformed DER signature, trailing bytes: {blob.hex()}")
        return r, int.from_bytes(blob[tail + 2:tail + 2 + slen], "big")

    raise SystemExit(f"{len(blob)} bytes is neither compact nor DER: {blob.hex()}")


def compact(r, s):
    """Compact 64 bytes, low-S. (r, n-s) verifies exactly where (r, s) does."""
    if not 0 < r < SECP256K1_N or not 0 < s < SECP256K1_N:
        raise SystemExit("signature component outside the group order")
    if s > SECP256K1_N >> 1:
        s = SECP256K1_N - s
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def to_der(signature):
    r, s = int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")

    def integer(x):
        b = x.to_bytes((x.bit_length() + 7) // 8 or 1, "big")
        if b[0] & 0x80:
            b = b"\x00" + b
        return b"\x02" + bytes([len(b)]) + b

    body = integer(r) + integer(s)
    return b"\x30" + bytes([len(body)]) + body


def pinned_verify_key(config_path="web/config.js"):
    """The key web/config.js pins. A release is held to it before anything is written."""
    import re

    text = open(config_path).read()
    found = re.search(r"VERIFY_KEY\s*=\s*['\"]([0-9a-fA-F]{66})['\"]", text)
    if not found:
        raise SystemExit(f"{config_path}: no 33-byte VERIFY_KEY found")
    return found.group(1).lower()


def compress_point(raw):
    """33-byte compressed form of a 33 or 65 byte secp256k1 point."""
    if len(raw) == 33 and raw[0] in (0x02, 0x03):
        return raw
    if len(raw) == 65 and raw[0] == 0x04:
        y = int.from_bytes(raw[33:], "big")
        return bytes([2 + (y & 1)]) + raw[1:33]
    raise SystemExit(f"{len(raw)} bytes is not a secp256k1 public key: {raw.hex()}")


def public_key_from_hex(hex_or_bytes):
    raw = bytes.fromhex(hex_or_bytes.strip()) if isinstance(hex_or_bytes, str) else hex_or_bytes
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), raw)


def verifies(verify_key, digest, signature):
    """True only if `signature` is by `verify_key` over `digest`, nothing else.

    Both low-S and high-S are accepted: the format stores low-S, but a reader that rejected either
    shape would fail on a file it should have accepted.
    """
    pub = public_key_from_hex(verify_key) if not hasattr(verify_key, "verify") else verify_key
    try:
        pub.verify(to_der(signature), digest, ec.ECDSA(ec_utils.Prehashed(hashes.SHA256())))
        return True
    except Exception:  # noqa: BLE001 - InvalidSignature and anything malformed is a no
        return False
