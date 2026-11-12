"""Sign a digest with a Keycard, for use as the production signing step of build-db.py.

The card is read over the same transport the Keycard CLI uses; `keycard` must be importable. The
derivation path convention and the 64 byte compact output match keycard-eth-db's tool, so the
browser verifier is unchanged whichever key signed a release.
"""

import getpass


def _card():
    try:
        from keycard.keycard import KeyCard
        from keycard.secure_channel import SecureChannelVersion
    except ImportError as exc:
        raise SystemExit(
            "the keycard package is required for --keycard (pip install keycard); "
            "use --sign-key with a hex key for anything that is not a release"
        ) from exc
    return KeyCard(), SecureChannelVersion


def keycard_sign(path, digest, pin=None):
    KeyCard, SecureChannelVersion = _card()

    with KeyCard() as card:
        card.select()

        pairing = None
        if card.secure_channel_version == SecureChannelVersion.V1:
            pairing = card.pair("KeycardDefaultPairing")
        card.open_secure_channel()

        if pin is None:
            pin = getpass.getpass("Keycard PIN: ")
        while not card.verify_pin(pin):
            pin = getpass.getpass("Wrong PIN: ")

        try:
            signature = card.sign_with_path(digest, path).signature
        finally:
            if pairing is not None:
                card.unpair(pairing.slot)

    if len(signature) != 64:
        raise SystemExit(f"card returned {len(signature)} bytes, expected a compact 64 byte signature")
    return signature
