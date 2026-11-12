"""Sign a digest with a Keycard, for use as the production signing step of build-db.py.

The card is read over the same transport the Keycard CLI uses; `keycard` must be importable. The
derivation path convention and the 64 byte compact output match keycard-eth-db's tool, so the browser
verifier is unchanged whichever key signed a release.
"""

import getpass
import sys

from shvr import SECP256K1_N

# A card blocks its PIN after three wrong attempts and needs the PUK to unblock, so the prompt loop
# stops short of that instead of retrying forever.
MAX_PIN_ATTEMPTS = 3


def _card():
    try:
        from keycard.keycard import KeyCard
        from keycard.secure_channel import SecureChannelVersion
    except ImportError as exc:
        raise SystemExit(
            "the keycard package is required for --keycard (pip install keycard); "
            "use --sign-key with a hex key for anything that is not a release"
        ) from exc
    return KeyCard, SecureChannelVersion


def keycard_sign(path, digest, pin=None):
    KeyCard, SecureChannelVersion = _card()

    with KeyCard() as card:
        card.select()

        pairing = None
        if card.secure_channel_version == SecureChannelVersion.V1:
            pairing = card.pair("KeycardDefaultPairing")

        # Everything after the pair is inside the try: a pairing left behind occupies a slot on the
        # card, and the card is then unusable by the CLI or another machine until it is released.
        signed = False
        try:
            card.open_secure_channel()

            if pin is None:
                pin = getpass.getpass("Keycard PIN: ")
            attempts = 0
            while not card.verify_pin(pin):
                attempts += 1
                if attempts >= MAX_PIN_ATTEMPTS:
                    raise SystemExit(
                        f"{attempts} wrong PINs, stopping before the card blocks its PIN"
                    )
                pin = getpass.getpass("Wrong PIN: ")

            signature = card.sign_with_path(digest, path).signature
            signed = True
        finally:
            if pairing is not None:
                _unpair(card, pairing.slot, signed)

    if len(signature) != 64:
        raise SystemExit(f"card returned {len(signature)} bytes, expected a compact 64 byte signature")

    # (r, n-s) verifies exactly where (r, s) does, so a release carries the same signature shape
    # whether it was signed on a card or with --sign-key.
    r, s = int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
    if not 0 < r < SECP256K1_N or not 0 < s < SECP256K1_N:
        raise SystemExit("card returned a signature with r or s outside the group order")
    if s > SECP256K1_N // 2:
        s = SECP256K1_N - s
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _unpair(card, slot, signed):
    """Release the pairing slot, loudly if that is not possible.

    After a signature the artifact is already good, so a slot left occupied is the operator's problem
    to fix immediately and has to stop the run. Before a signature, whatever went wrong is the more
    useful message, so this reports and gets out of the way rather than masking it.
    """
    try:
        card.unpair(slot)
    except Exception as exc:  # noqa: BLE001 - any failure here must be surfaced, not swallowed
        if signed:
            raise SystemExit(
                f"signed, but could not release the pairing on slot {slot}: {exc}. "
                "Release it before the card is used again."
            ) from exc
        print(f"warning: could not release the pairing on slot {slot}: {exc}; the card is still paired",
              file=sys.stderr)
