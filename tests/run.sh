#!/bin/sh
# Build fixtures and run the verifier tests. Requires python3 (with `cryptography`) and node.
set -e
cd "$(dirname "$0")/.."

mkdir -p out

if [ ! -f out/dev-signing.key ]; then
  echo "generating a throwaway signing key"
  python3 - "$PWD/out/dev-signing.key" <<'PY'
import os, secrets, sys
path = sys.argv[1]
with open(path, "w") as f:
    f.write(secrets.token_hex(32) + "\n")
os.chmod(path, 0o600)
PY
fi

# A directory and the files inside it must describe the same database. Pinned salt and no padding
# rows, so the only thing left that can differ is what a signature actually covers: the digest.
dir_digest=$(python3 tools/build-db.py -f input-files -o out/dir.bin -v 20261112 \
  --salt 00112233445566778899aabbccddeeff --sign-key out/dev-signing.key --no-decoys | awk '/^digest/ {print $2}')
file_digest=$(python3 tools/build-db.py -f input-files/shell-batch-0.csv -f input-files/shell-batch-1.csv \
  -o out/files.bin -v 20261112 --salt 00112233445566778899aabbccddeeff --sign-key out/dev-signing.key --no-decoys | awk '/^digest/ {print $2}')
[ "$dir_digest" = "$file_digest" ] || { echo "directory input disagrees with file input"; exit 1; }
rm -f out/dir.bin out/files.bin
echo "directory and file inputs agree"

node tests/gen-devices.mjs out/test-devices.csv 24 out/test-devices.json

python3 tools/build-db.py \
  -f out/test-devices.csv \
  -f input-files/shell-batch-0.csv \
  -f input-files/shell-batch-1.csv \
  -o out/test-db.bin \
  -v 20261112 \
  --salt 00112233445566778899aabbccddeeff \
  --sign-key out/dev-signing.key \
  --verify-key out/test-verify-key.hex

node tests/verify.test.mjs out/test-db.bin out/test-verify-key.hex out/test-devices.json \
  input-files/shell-batch-0.csv input-files/shell-batch-1.csv

node tests/page.test.mjs out/test-db.bin out/test-devices.json
node tests/privacy.test.mjs input-files/shell-batch-0.csv input-files/shell-batch-1.csv
