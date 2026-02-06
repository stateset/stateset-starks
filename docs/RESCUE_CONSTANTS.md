# Rescue Constants

This repo uses a fixed set of Rescue-Prime constants (MDS, inverse MDS, and round constants) defined in `crates/ves-stark-primitives/src/rescue.rs`.

These constants are **frozen**: changing them changes the Rescue permutation, witness commitments, and proof verification behavior.

## Integrity Check

The unit test `test_rescue_constants_hash` in `crates/ves-stark-primitives/src/rescue.rs` hashes all constants to detect accidental edits.

Current digest (SHA-256 of all constants, serialized row-major as little-endian `u64`):

```
2936f26121c35c83d3a1922855d289ac0e6b6be4e31874cc13233239bc3adb5b
```

## Reproducibility Artifact

For auditing and external review, the constants are also exported to `docs/rescue_constants.json`.

The JSON uses **hex strings** for all values to avoid precision loss in tools that cannot represent all `u64` values exactly.

To regenerate the JSON and print the digest:

```bash
python scripts/rescue_constants.py render
```

To print the JSON to stdout:

```bash
python scripts/rescue_constants.py extract
```

