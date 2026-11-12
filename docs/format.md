# Shell allowlist: file format and verification

A signed file listing every shipped device, and a client that answers one question about a device in
front of it: does the key that device just signed with appear in the file. Files are built by
`tools/build-db.py` and read by `web/`. No server in either direction.

## File format

```
0    4    magic 'SHVR'
4    2    format version, u16 LE                  = 1
6    1    uid_len, u8                             = 16
7    1    reserved, zero
8    4    row_count, u32 LE
12   16   salt                                    random per build
28   4    build version, u32 LE, YYYYMMDD
32   32   reserved, zero
   ---   64-byte header
64   N×32 row hashes, ascending
     64  signature
```

    row = SHA256(salt ‖ "ShellUID" ‖ uid ‖ "ShellPubKey" ‖ pubkey)

`uid` is `uid_len` bytes as the device reports them, `pubkey` is the 33-byte compressed key. Both tags
are fixed constants and every field is fixed length, so the concatenation is injective. Length
extension does not apply: all inputs are public.

The row is a hash of the pair, so the file identifies no device on its own. Computing a row requires
the uid and the key together, and the only party holding both is the device itself, or someone who has
opened it.

**Header.** Six fields are written; the rest of the 64 bytes are reserved and a reader refuses a file
with a reserved byte set, so giving one a meaning is a version bump rather than a silent
reinterpretation. `row_count` includes padding rows and is not a device count; do not report it as one.

`uid_len` is the one negotiated value, because it describes what the *device* reports rather than what
this file contains: a reader hashing over a uid length it did not build for would answer *not
registered* for every device, which is indistinguishable from an honest miss. It must say
*unsupported* instead. Row length needs no such field — it is the output size of SHA-256, and another
hash function would be another format version.

**Signature.** secp256k1 over `SHA256` of every byte before it, compact 64 bytes, normalised to low-S.
Signing key `m/43'/60'/1581'/1397249618'/0`, the appid being `'SHVR'` as a big-endian u32. Verification
key, compressed:

    033dcc3ece8f9bc5a25c7ba30ddcc8c63bcdb03a562058bbb3234d6874b50f5fea

Pin it. A client that takes the key from the same origin as the file gains nothing.

**Releases.** One file per release, replaced wholesale, re-downloaded whole. The salt changes every
build, so releases do not diff and there is nothing to update incrementally.

## Reading a file

1. Parse the header; refuse on magic, version, `uid_len` or a non-zero reserved byte.
2. Verify the signature over the file prefix. Before searching, and hard-stop on failure.
3. Compute the row hash, binary search over the sorted array.

The signature check is what makes a row mean anything, so a failure there is a refusal, not a miss.

## Verifying a device

The device takes a 32-byte challenge in a QR code and signs it.

**Request**, client → device, as CBOR:

```
a2 01 01 06 58 20 ‖ challenge(32)     definite map, step 1, 32-byte challenge
```

**Response**, device → client, definite map, four entries:

```
1: uint 2      step
2: tag 37 (bstr 16)   device uid, the "uuid" type — tagged, not a bare bstr
6: bstr 32     random, unchecked
7: bstr 64     r ‖ s
```

Keys 3, 4 and 5 are reserved. They are never emitted; treat their presence, or any other key, as a
refusal.

**Check.**

```
digest   = SHA256(uid ‖ challenge)              challenge = the bytes the client generated
(r, s)   = response key 7, with r, s ∈ [1, n−1]
s        = n − s if s > n/2                     canonicalise first
Q0, Q1   = recover(digest, r, s)                recIds 0 and 1
match    = SHA256(salt ‖ tags ‖ uid ‖ Q) in the file, for either candidate
```

The challenge in the response (key 6) holds device randomness and is checked against nothing; building
the digest from it rejects every device. RecIds 2 and 3 require a nonce point above the group order,
probability 2^−128, and are not implemented. Both candidates verify against the signature; only one
hashes into the file, and that candidate is the device's public key, so a successful check returns it.
Recovery implies verification, so there is no separate `verify()` call to get wrong — and a `verify()`
with library-default low-S enforcement rejects roughly half of all device signatures.

**Message framing.** `UR:DEV-AUTH/` followed by the CBOR in bytewords *minimal*: two lowercase letters
per byte, plus four bytes of CRC-32 big-endian over the payload. Decoders fold case. A payload in any
other encoding fails the checksum and is dropped by both sides without a message. Single part only: a
digit after the type label would mark a fountain part, which a verifier does not need.

**Rendering a scannable QR.** The device camera has a narrow focus range, so too large fails like too
small: draw modules at whole pixels for a fixed physical size rather than scaling with CSS. Error
correction level L, four modules of quiet zone inside the symbol, and a white surround that survives a
dark-mode page.

## Outcomes

| | |
|---|---|
| **verified** | a candidate matched; the key and the row are returned |
| **not registered** | clean parse, valid signature, no row |
| **refused** | signature, header, framing or response shape |

A refusal says nothing about the device. Collapsing the two sends an operator to retest hardware that
was never the problem.

## Sizes

`64 + 32·row_count + 64` bytes, `row_count` being the real count rounded up to a power of two:

| devices | rows | file |
|---|---|---|
| 1 000 | 1 024 | 33 KB |
| 10 000 | 16 384 | 524 KB |
| 100 000 | 131 072 | 4.2 MB |

Search is log2 of the padded row count. Two point recoveries cost about 1.2 ms and dominate the run
time of a check.

## Constants

`tools/shvr.py` is the definition of `MAGIC`, `FORMAT_VERSION`, `HEADER_SIZE`, `SIG_SIZE`, `INDEX_LEN`,
`UID_LEN`, the two row tags and the signing path.
