//! Guards `docs/VERIFICATION.md` against drift.
//!
//! The verification matrix is the audit-readiness artifact: it maps every claimed
//! security property to a named test. If a referenced test is renamed or removed,
//! the matrix would silently lie. This test parses the matrix and asserts every
//! backticked `test_*` / `prop_*` / `fuzz_*` identifier actually exists in the
//! codebase, so the matrix cannot drift from reality.

use std::fs;
use std::path::Path;

/// Recursively concatenate the contents of every `.rs` file under `dir`,
/// skipping any `target` directory.
fn collect_rs(dir: &Path, out: &mut String) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n == "target") {
                continue;
            }
            collect_rs(&path, out);
        } else if path.extension().is_some_and(|x| x == "rs") {
            if let Ok(contents) = fs::read_to_string(&path) {
                out.push_str(&contents);
                out.push('\n');
            }
        }
    }
}

#[test]
fn verification_matrix_references_existing_tests() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let matrix = fs::read_to_string(root.join("docs/VERIFICATION.md"))
        .expect("docs/VERIFICATION.md must exist");

    let mut sources = String::new();
    for sub in ["crates", "tests"] {
        collect_rs(&root.join(sub), &mut sources);
    }

    let mut missing = Vec::new();
    let mut checked = 0usize;
    // Identifiers are delimited by backticks in the Markdown.
    for token in matrix.split('`') {
        let name = token.trim();
        let is_item = name.starts_with("test_") || name.starts_with("prop_");
        let is_fuzz = name.starts_with("fuzz_");
        if !(is_item || is_fuzz) {
            continue;
        }
        // Exact identifiers only — skip wildcarded references like `test_*_rejects`.
        if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            continue;
        }

        checked += 1;
        let found = if is_fuzz {
            // Fuzz targets are bin files, not `fn` definitions.
            root.join("fuzz/fuzz_targets")
                .join(format!("{name}.rs"))
                .exists()
        } else {
            sources.contains(&format!("fn {name}"))
        };
        if !found && !missing.contains(&name.to_string()) {
            missing.push(name.to_string());
        }
    }

    assert!(
        checked > 30,
        "expected the matrix to reference many tests; found only {checked} — parser may be broken"
    );
    assert!(
        missing.is_empty(),
        "docs/VERIFICATION.md references tests that do not exist: {missing:?}"
    );
}
