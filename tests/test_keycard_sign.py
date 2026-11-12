# Exercises the Keycard signing step without a card, by putting a fake `keycard` package in front of
# the import. Release signing cannot run against hardware in a test run, and an unexercised signer is
# how a TypeError came to surface on the first real signature.
#
# The pair/unpair symmetry gets the most attention here: a pairing left on the card occupies a slot,
# and the card is unusable by the CLI or another machine until it is released.
#
#   python3 tests/test_keycard_sign.py

import contextlib
import getpass
import io
import sys
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
PATH = "m/43'/60'/1581'/1397249618'/0"
DIGEST = bytes(range(32))
R = bytes.fromhex("4bfee9a8b1e40e63f4f00f4e3a4e0a2e7d6c0f1c7bd8f2f3e5f7a9c1d3e5f709")
S_LOW = bytes.fromhex("2f0a3c5e7d9b1f3a5c7e9d1b3f5a7c9e1d3b5f7a9c1e3d5b7f9a1c3e5d7b9011")
SLOT = 7


class Versions:
    V1 = "v1"
    V2 = "v2"


class FakeCard:
    def __init__(self, signature, version=Versions.V1, **failures):
        self.signature = signature
        self.secure_channel_version = version
        self.calls = []
        self.failures = failures

    def _fail(self, what):
        if what in self.failures:
            raise self.failures[what]

    def __enter__(self):
        self.calls.append("enter")
        return self

    def __exit__(self, *exc):
        self.calls.append("exit")
        return False

    def select(self):
        self.calls.append("select")

    def pair(self, secret):
        self.calls.append(f"pair:{secret}")
        return types.SimpleNamespace(slot=SLOT)

    def unpair(self, slot):
        self.calls.append(f"unpair:{slot}")
        self._fail("unpair")

    def open_secure_channel(self):
        self.calls.append("channel")
        self._fail("channel")

    def verify_pin(self, pin):
        self.calls.append(f"pin:{pin}")
        return pin == "123456"

    def sign_with_path(self, digest, path):
        self.calls.append(f"sign:{len(digest)}:{path}")
        self._fail("sign")
        return types.SimpleNamespace(signature=self.signature)


def run_signer(card, prompts=("123456",)):
    module = types.ModuleType("keycard")
    card_module = types.ModuleType("keycard.keycard")
    channel_module = types.ModuleType("keycard.secure_channel")
    card_module.KeyCard = lambda: card
    channel_module.SecureChannelVersion = Versions
    module.keycard = card_module
    module.secure_channel = channel_module
    sys.modules.update({
        "keycard": module,
        "keycard.keycard": card_module,
        "keycard.secure_channel": channel_module,
    })

    queue = list(prompts)
    getpass.getpass = lambda prompt="": queue.pop(0)
    sys.modules.pop("keycardsign", None)
    import keycardsign

    return keycardsign.keycard_sign(PATH, DIGEST)


def low_s(s_bytes):
    s = int.from_bytes(s_bytes, "big")
    return (N - s) if s > N // 2 else s


def run(**kwargs):
    signature = kwargs.pop("signature", R + S_LOW)
    return FakeCard(signature, **kwargs)


def signs_over_a_v1_channel():
    card = run()
    out = run_signer(card)
    assert out == R + S_LOW, f"signature changed: {out.hex()}"
    assert card.calls == [
        "enter", "select", "pair:KeycardDefaultPairing", "channel", "pin:123456",
        f"sign:32:{PATH}", f"unpair:{SLOT}", "exit",
    ], card.calls


def v2_channel_skips_pairing():
    card = run(version=Versions.V2)
    assert run_signer(card) == R + S_LOW
    assert not any(c.startswith(("pair", "unpair")) for c in card.calls), card.calls
    assert "channel" in card.calls and "exit" in card.calls, card.calls


def pairing_is_released_when_the_channel_fails():
    card = run(channel=RuntimeError("reader gone"))
    try:
        run_signer(card)
    except RuntimeError:
        pass
    else:
        raise AssertionError("expected the channel failure to propagate")
    assert f"unpair:{SLOT}" in card.calls, card.calls


def pairing_is_released_when_signing_fails():
    card = run(sign=RuntimeError("card removed mid-signature"))
    try:
        run_signer(card)
    except RuntimeError:
        pass
    else:
        raise AssertionError("expected the card failure to propagate")
    assert f"unpair:{SLOT}" in card.calls, card.calls


def pairing_is_released_when_the_pin_is_wrong_until_stopping():
    card = run()
    try:
        run_signer(card, prompts=("000000", "111111", "222222"))
    except SystemExit as exc:
        assert "blocks its PIN" in str(exc), exc
    else:
        raise AssertionError("expected a stop before the card blocks the PIN")
    assert card.calls.count("pin:222222") == 1, card.calls
    assert f"unpair:{SLOT}" in card.calls, card.calls


def one_wrong_pin_then_success():
    card = run()
    assert run_signer(card, prompts=("000000", "123456")) == R + S_LOW
    assert card.calls.count("pin:000000") == 1 and card.calls.count("pin:123456") == 1, card.calls


def high_s_is_canonicalised():
    card = run(signature=R + (N - low_s(S_LOW)).to_bytes(32, "big"))
    out = run_signer(card)
    assert low_s(out[32:]) == low_s(S_LOW), "s was not canonicalised"
    assert out[:32] == R, "r changed"


def a_slot_left_occupied_after_signing_stops_the_release():
    card = run(unpair=RuntimeError("transport error"))
    try:
        run_signer(card)
    except SystemExit as exc:
        assert "could not release the pairing" in str(exc), exc
    else:
        raise AssertionError("expected a hard stop: the signature exists but the card is still paired")


def a_failed_unpair_does_not_mask_the_real_failure():
    card = run(sign=RuntimeError("card removed"), unpair=RuntimeError("transport error"))
    stderr = io.StringIO()
    try:
        with contextlib.redirect_stderr(stderr):
            run_signer(card)
    except RuntimeError as exc:
        assert "card removed" in str(exc), f"the real failure was masked: {exc}"
    else:
        raise AssertionError("expected the card failure to propagate")
    assert "still paired" in stderr.getvalue(), stderr.getvalue()


def wrong_length_is_refused():
    _expect_stop(lambda: run_signer(run(signature=b"\x01" * 63)))


def out_of_range_components_are_refused():
    _expect_stop(lambda: run_signer(run(signature=R + N.to_bytes(32, "big"))))
    _expect_stop(lambda: run_signer(run(signature=bytes(32) + S_LOW)))


def _expect_stop(fn):
    try:
        fn()
    except SystemExit:
        return
    raise AssertionError("expected SystemExit")


tests = [
    signs_over_a_v1_channel,
    v2_channel_skips_pairing,
    one_wrong_pin_then_success,
    pairing_is_released_when_the_channel_fails,
    pairing_is_released_when_signing_fails,
    pairing_is_released_when_the_pin_is_wrong_until_stopping,
    high_s_is_canonicalised,
    a_slot_left_occupied_after_signing_stops_the_release,
    a_failed_unpair_does_not_mask_the_real_failure,
    wrong_length_is_refused,
    out_of_range_components_are_refused,
]

failures = 0
for test in tests:
    try:
        test()
        print(f"ok   {test.__name__}")
    except Exception as exc:  # noqa: BLE001 - report each failure, keep going
        failures += 1
        print(f"FAIL {test.__name__}: {type(exc).__name__}: {exc}")

print(f"{len(tests) - failures} keycard checks passed, {failures} failed")
sys.exit(1 if failures else 0)
