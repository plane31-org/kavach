# SS5 revision 2 vectors package (baseline)

Extracted unchanged from the embedded attachments of the SealedStream SS5 revision 2 blueprint PDF. This is the baseline Kavach v1 is measured against; it is not yet the revision 4 fixture.

| File | SHA-256 |
| --- | --- |
| README.md | 48937417d388c43fe829e25d7a02d0bb8f01ac1327d88b0e8ff1735737676816 |
| requirements.txt | 94590f7d7922f5fc984b08807f820b93020688ffefad2b7b416a06c73451524a |
| vectors.json | 1d5fd03b6e2cf059ded4495aa928c26295d315248a3216214327cd990d6a0da1 |
| verify_vectors.py | e0a1ab02c069a410fc5b21e1fc9bdc3cd26b3e6ab59841f83cadcf21ca13d8c9 |

Step 0 of the build sequence regenerated this package once as `spec/vectors.json` and `spec/verify_vectors.py` (checker derived from this one; both files sit next to this directory) with four changes, listed in Part I section 16 of `spec/Kavach-v1.md`:

1. Reset-key list lifetime 30 days instead of 24 hours (case K19 re-derived at 30 days plus one millisecond).
2. Record flag bit 0 reserved. The core record and check-in are untouched; the maximum-size record (which carried flag 1) is re-derived with flags 2, and negative vector N21 covers bit 0.
3. Type 5 retired: its document vector dropped; its wire added to the negative set as N20 `UNSUPPORTED_TYPE`.
4. Vault entry shortened to 49 bytes (snapshot pins removed); vault vectors re-derived; the transfer token is gone.

Resulting fixture hashes:

| File | SHA-256 |
| --- | --- |
| spec/vectors.json | 298e2726226234b868ec97c22dd690390b392a28d99d0c294d7ae2c25a84b7d7 |
| spec/verify_vectors.py | 9938538b2a6b77c6be3695922c527e552a7c85f8d9ca155177a69fd4404b9eb9 |

Section diff between the two `vectors.json` files: `profile`, `documents.join_intent` (removed), `negative_vectors` (N20, N21 added), `boundary_100.maximum_record_wire`, `recovery_vault`, `reset_key_management.rejected_wires.excess_lifetime`, and the wording of one `cross_checks` line. Every other section is byte-identical. `scripts/vectors.sh` runs both checkers.
