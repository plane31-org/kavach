# SS5 revision 2 vectors package (baseline)

Extracted unchanged from the embedded attachments of the SealedStream SS5 revision 2 blueprint PDF. This is the baseline Kavach v1 is measured against; it is not yet the revision 4 fixture.

| File | SHA-256 |
| --- | --- |
| README.md | 48937417d388c43fe829e25d7a02d0bb8f01ac1327d88b0e8ff1735737676816 |
| requirements.txt | 94590f7d7922f5fc984b08807f820b93020688ffefad2b7b416a06c73451524a |
| vectors.json | 1d5fd03b6e2cf059ded4495aa928c26295d315248a3216214327cd990d6a0da1 |
| verify_vectors.py | e0a1ab02c069a410fc5b21e1fc9bdc3cd26b3e6ab59841f83cadcf21ca13d8c9 |

Step 0 of the build sequence regenerates this package once as `spec/vectors.json` and `spec/verify_vectors.py` with four changes, listed in Part I section 16 of `spec/Kavach-v1.md`:

1. Reset-key list lifetime 30 days instead of 24 hours (case K19 re-derived at 30 days plus one millisecond).
2. Record flag bit 0 reserved; no byte changes because the fixture's check-in sets only bit 1.
3. Type 5 retired: its document vector, negative vectors and intent state steps dropped; a type 5 wire added to the negative set as `UNSUPPORTED_TYPE`.
4. Vault entry shortened to 49 bytes (snapshot pins removed); vault vectors re-derived.

Until that regeneration lands, `scripts/vectors.sh` reports the fixture as missing and CI skips the checker.
