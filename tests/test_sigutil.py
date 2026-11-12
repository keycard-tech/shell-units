# Signature shapes and the builder's refusal to write what it cannot verify.
#
#   python3 tests/test_sigutil.py

import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

from cryptography.hazmat.primitives.asymmetric import ec, utils as ec_utils  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: E402

from sigutil import compact, signature_from_blob, to_der, verifies  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
KEY = ec.derive_private_key(0xC0FFEE, ec.SECP256K1())
PUB = KEY.public_key().public_bytes(Encoding.X962, PublicFormat.CompressedPoint).hex()
OTHER = ec.derive_private_key(0xBADF00D, ec.SECP256K1()).public_key().public_bytes(Encoding.X962, PublicFormat.CompressedPoint).hex()
DIGEST = hashes.Hash(hashes.SHA256())
DIGEST.update(b"shvr")
DIGEST = DIGEST.finalize()


def local_signature():
    der = KEY.sign(DIGEST, ec.ECDSA(ec_utils.Prehashed(hashes.SHA256())))
    r, s = ec_utils.decode_dss_signature(der)
    return der, r, s


def compact_round_trip():
    der, r, s = local_signature()
    assert signature_from_blob(r.to_bytes(32, "big") + s.to_bytes(32, "big")) == (r, s)


def compact_with_recovery_byte():
    der, r, s = local_signature()
    blob = r.to_bytes(32, "big") + s.to_bytes(32, "big") + b"\x00"
    assert signature_from_blob(blob) == (r, s)


def der_is_accepted():
    der, r, s = local_signature()
    assert signature_from_blob(der) == (r, s)


def compact_output_is_low_s():
    der, r, s = local_signature()
    high = (0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 - s)
    assert int.from_bytes(compact(r, high)[32:], "big") < (0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 >> 1)
    assert int.from_bytes(compact(r, s)[32:], "big") == min(s, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 - s)


def malformed_blobs_are_dumped_not_guessed():
    der, r, s = local_signature()
    for bad in [b"\x01" * 63, b"\x30" + b"\x05" + b"\x02\x20" + b"\x00" * 30, der[:-1], der + b"\x00",
                b"\x30\x44\x02\x20" + b"\x11" * 32 + b"\x03\x20" + b"\x22" * 32]:
        try:
            signature_from_blob(bad)
        except SystemExit:
            continue
        raise AssertionError(f"accepted garbage: {bad[:8].hex()}… ({len(bad)} bytes)")


def verifies_accepts_only_the_right_key_and_digest():
    der, r, s = local_signature()
    signature = compact(r, s)
    assert verifies(PUB, DIGEST, signature), "the signing key does not verify its own signature"
    assert verifies(OTHER, DIGEST, signature) is False, "a different key verified it"
    assert verifies(PUB, bytes(32), signature) is False, "a different digest verified it"


def garbage_signature_is_a_no_not_a_crash():
    assert verifies(PUB, DIGEST, b"\x00" * 64) is False


def builder_refuses_to_write_a_signature_it_cannot_verify():
    out = ROOT / "out" / "guard-test.bin"
    csv = ROOT / "out" / "guard-test.csv"
    device_pub = ec.derive_private_key(0xDA7A, ec.SECP256K1()).public_key() \
        .public_bytes(Encoding.X962, PublicFormat.CompressedPoint).hex()
    csv.write_text(f"ffff0000000000000000000000000001,{device_pub}\r\n")
    keyfile = ROOT / "out" / "guard-test.key"
    keyfile.write_text("%064x\n" % 0xC0FFEE)

    common = ["python3", "tools/build-db.py", "-f", str(csv), "-o", str(out), "-v", "20261112",
              "--sign-key", str(keyfile), "--no-decoys"]

    if out.exists():
        out.unlink()
    wrong = subprocess.run(common + ["--expect-verify-key", OTHER], capture_output=True, text=True, cwd=ROOT)
    assert wrong.returncode != 0, "a signature by the wrong key was accepted"
    assert not out.exists(), "the file was written despite the mismatch"
    assert "does not verify" in wrong.stderr + wrong.stdout, wrong.stderr[-400:]

    right = subprocess.run(common + ["--expect-verify-key", PUB], capture_output=True, text=True, cwd=ROOT)
    assert right.returncode == 0, right.stderr[-400:]
    assert out.exists(), "the matching key produced no file"

    body = out.read_bytes()
    digest = hashes.Hash(hashes.SHA256())
    digest.update(body[:-64])
    assert verifies(PUB, digest.finalize(), body[-64:]), "the written file does not verify"

    for path in (out, csv, keyfile):
        path.unlink()


tests = [
    compact_round_trip,
    compact_with_recovery_byte,
    der_is_accepted,
    compact_output_is_low_s,
    malformed_blobs_are_dumped_not_guessed,
    verifies_accepts_only_the_right_key_and_digest,
    garbage_signature_is_a_no_not_a_crash,
    builder_refuses_to_write_a_signature_it_cannot_verify,
]

failures = 0
for test in tests:
    try:
        test()
        print(f"ok   {test.__name__}")
    except Exception as exc:  # noqa: BLE001
        failures += 1
        print(f"FAIL {test.__name__}: {type(exc).__name__}: {exc}")

print(f"{len(tests) - failures} signature checks passed, {failures} failed")
sys.exit(1 if failures else 0)
