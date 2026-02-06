#!/usr/bin/env python3
"""
Extract and render the frozen Rescue-Prime constants used by this repo.

This does *not* generate constants from a spec. It parses the Rust source of
`crates/ves-stark-primitives/src/rescue.rs` and emits a JSON artifact for
auditing and reproducibility.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import sys
from pathlib import Path


DEFAULT_SRC = Path("crates/ves-stark-primitives/src/rescue.rs")
DEFAULT_OUT = Path("docs/rescue_constants.json")


def _strip_rust_comments(s: str) -> str:
    s = re.sub(r"//.*", "", s)
    s = re.sub(r"/\*.*?\*/", "", s, flags=re.S)
    return s


def _extract_rust_const_array(src_text: str, name: str):
    m = re.search(
        rf"pub const {re.escape(name)}:[^=]*=\s*(\[.*?\n\s*\]);",
        src_text,
        re.S,
    )
    if not m:
        raise ValueError(f"could not find const initializer for {name}")
    arr_src = _strip_rust_comments(m.group(1))
    return ast.literal_eval(arr_src)


def _sha256_le_u64_row_major(*arrays) -> str:
    h = hashlib.sha256()

    def upd_u64(x: int) -> None:
        if x < 0 or x >= 2**64:
            raise ValueError(f"value out of u64 range: {x}")
        h.update(int(x).to_bytes(8, "little", signed=False))

    for arr in arrays:
        # nested lists: [[...], [...], ...]
        for row in arr:
            for v in row:
                upd_u64(v)

    return h.hexdigest()


def _to_hex_strings(matrix):
    return [[f"0x{int(v):016x}" for v in row] for row in matrix]


def extract_constants(src_path: Path) -> dict:
    text = src_path.read_text(encoding="utf-8")

    mds = _extract_rust_const_array(text, "MDS")
    mds_inv = _extract_rust_const_array(text, "MDS_INV")
    round_constants = _extract_rust_const_array(text, "ROUND_CONSTANTS")

    digest = _sha256_le_u64_row_major(mds, mds_inv, round_constants)

    return {
        "format": "ves-stark-rescue-constants-v1",
        "field": "goldilocks",
        "goldilocks_prime": "0xffffffff00000001",
        "state_width": 12,
        "num_rounds": 7,
        # Use hex strings to avoid JSON number precision loss.
        "mds": _to_hex_strings(mds),
        "mds_inv": _to_hex_strings(mds_inv),
        "round_constants": _to_hex_strings(round_constants),
        "sha256_le_u64_row_major": digest,
        "source_path": str(src_path),
    }


def cmd_extract(args: argparse.Namespace) -> int:
    constants = extract_constants(Path(args.src))
    json.dump(constants, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


def cmd_render(args: argparse.Namespace) -> int:
    constants = extract_constants(Path(args.src))
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(constants, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    sys.stdout.write(constants["sha256_le_u64_row_major"] + "\n")
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="rescue_constants.py")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_extract = sub.add_parser("extract", help="Print constants JSON to stdout")
    p_extract.add_argument("--src", default=str(DEFAULT_SRC), help="Path to rescue.rs")
    p_extract.set_defaults(fn=cmd_extract)

    p_render = sub.add_parser("render", help="Write docs/rescue_constants.json and print digest")
    p_render.add_argument("--src", default=str(DEFAULT_SRC), help="Path to rescue.rs")
    p_render.add_argument("--out", default=str(DEFAULT_OUT), help="Output JSON path")
    p_render.set_defaults(fn=cmd_render)

    args = parser.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
