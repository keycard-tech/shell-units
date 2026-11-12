"""Sign a digest with a Keycard, as the production signing step of build-db.py.

The card derives from a single master seed, so it can sign at any path and holds no key per path.
`sign_with_path` returns the derived key with the signature, which is the only way to learn which key
signed; `sigutil.verifies` against the pinned key is what decides whether a release is valid.
"""

import getpass
import sys

from sigutil import compact, compress_point, signature_from_blob

# A card blocks its PIN after three wrong attempts and needs the PUK to unblock.
MAX_PIN_ATTEMPTS = 3


def keycard_sign(path, digest, pin=None):
    """(compact low-S signature, compressed key the card derived for `path`)."""
    try:
        from keycard.keycard import KeyCard
        from keycard.secure_channel import SecureChannelVersion
    except ImportError:
        raise SystemExit("the keycard package is required for -k; use --sign-key otherwise")

    with KeyCard() as card:
        card.select()

        pairing = None
        if card.secure_channel_version == SecureChannelVersion.V1:
            pairing = card.pair("KeycardDefaultPairing")

        # Everything after the pair is guarded: a pairing left behind occupies a slot on the card.
        signed = False
        try:
            card.open_secure_channel()

            if pin is None:
                pin = getpass.getpass("Keycard PIN: ")
            attempts = 0
            while not card.verify_pin(pin):
                attempts += 1
                if attempts >= MAX_PIN_ATTEMPTS:
                    raise SystemExit(f"{attempts} wrong PINs, stopping before the card blocks its PIN")
                pin = getpass.getpass("Wrong PIN: ")

            result = card.sign_with_path(digest, path)
            signed = True
        finally:
            if pairing is not None:
                _unpair(card, pairing.slot, signed)

    signature = compact(*signature_from_blob(result.signature))
    return signature, compress_point(result.public_key) if result.public_key else None


def _unpair(card, slot, signed):
    """Release the pairing slot, loudly if that is not possible.

    After a signature the artifact is good and an occupied slot must be cleared before the card is used
    again, so that stops the run. Before a signature the original failure is the useful message.
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
