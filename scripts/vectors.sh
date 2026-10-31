#!/usr/bin/env bash
# Run the Python vector checker in a local venv. Step 0 of the build sequence.
set -euo pipefail
cd "$(dirname "$0")/.."
if [ ! -f spec/vectors.json ] || [ ! -f spec/verify_vectors.py ]; then
  echo "spec/vectors.json and spec/verify_vectors.py are missing: add the regenerated revision 4 fixture first" >&2
  exit 2
fi
python3 -m venv .venv
. .venv/bin/activate
pip install --quiet --upgrade pip
pip install --quiet pynacl pycryptodome
python -I spec/verify_vectors.py spec/vectors.json
