#!/usr/bin/env bash
# Run the Kavach v1 vector checker (spec/verify_vectors.py against spec/vectors.json) in a local venv
# with the pinned dependencies from spec/requirements.txt. Step 0 of the build sequence.
# Also re-checks the unchanged SS5 revision 2 baseline in spec/vectors-rev2 with its own checker.
set -euo pipefail
cd "$(dirname "$0")/.."
python3 -m venv .venv
. .venv/bin/activate
pip install --quiet --upgrade pip
pip install --quiet -r spec/requirements.txt
echo "== revision 2 baseline (spec/vectors-rev2)"
( cd spec/vectors-rev2 && python -I verify_vectors.py )
echo "== Kavach v1 fixture (spec)"
( cd spec && python -I verify_vectors.py )
