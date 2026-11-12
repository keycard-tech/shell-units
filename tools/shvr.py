"""SHVR database format constants, shared by the builder and its tests.

One home for each value: docs/format.md explains them, this file is the definition.
"""

MAGIC = b"SHVR"
FORMAT_VERSION = 1

HEADER_SIZE = 64
SIG_SIZE = 64
# Row stride, fixed by SHA-256 and therefore not written to the file: a different hash would be a
# different format version.
INDEX_LEN = 32
# Written to the header because it describes what the device reports, and a reader hashing over the
# wrong length would answer "not registered" for every device.
UID_LEN = 16
PUBKEY_LEN = 33

SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# The row hash binds the two values a verifier holds only together: the uid comes from the
# response, the key comes out of the signature. Neither is recoverable from the file alone.
TAG_UID = b"ShellUID"
TAG_PUBKEY = b"ShellPubKey"

# appid 'SHVR' big-endian, hardened like the rest of the path. keycard-eth-db uses
KEYCARD_APPID = int.from_bytes(MAGIC, "big")
KEYCARD_PATH = f"m/43'/60'/1581'/{KEYCARD_APPID}'/0"
