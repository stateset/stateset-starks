use serde_json::{json, Value};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use uuid::Uuid;

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("ves-commerce-cli-{}", Uuid::new_v4()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn cli(args: &[&str], stdin: Option<&[u8]>) -> Output {
    let mut args = args.to_vec();
    if args.get(1).is_some_and(|c| *c == "prove" || *c == "verify") {
        args.push("--allow-amount-disclosure");
        if args[1] == "verify" {
            args.push("--allow-unsigned-approval");
        }
    }
    raw_cli(&args, stdin)
}

fn raw_cli(args: &[&str], stdin: Option<&[u8]>) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ves-stark"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Some(bytes) = stdin {
        child.stdin.take().unwrap().write_all(bytes).unwrap();
    } else {
        drop(child.stdin.take());
    }
    child.wait_with_output().unwrap()
}

#[test]
fn confidential_commands_reject_before_reading_amounts() {
    let result = raw_cli(
        &[
            "commerce",
            "prove",
            "--request",
            "missing",
            "--amount-file",
            "-",
            "--output-dir",
            "unused",
        ],
        None,
    );
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("confidential proofs are unavailable"));
    assert!(result.stdout.is_empty());
}

#[test]
fn signed_refund_cli_lifecycle_persists_and_rejects_replay() {
    use ed25519_dalek::SigningKey;
    let scratch = Scratch::new();
    let state_path = scratch.0.join("capture.json");
    let db = scratch.0.join("refunds.db");
    let bundle = scratch.0.join("refund");
    let authority_path = scratch.0.join("authority.json");
    let seed_path = scratch.0.join("seed.hex");
    let signed_path = scratch.0.join("signed.json");
    let tenant = "00000000-0000-0000-0000-000000000001";
    let store = "00000000-0000-0000-0000-000000000002";
    fs::write(
        &state_path,
        serde_json::to_vec(&json!({
            "tenantId": tenant, "storeId": store, "captureId": "cap-1", "currency": "USD",
            "decimalPlaces": 2, "captured": 10000, "refunded": 0, "version": 0
        }))
        .unwrap(),
    )
    .unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let key = SigningKey::from_bytes(&[7; 32]);
    fs::write(&seed_path, hex::encode([7; 32])).unwrap();
    fs::write(&authority_path, serde_json::to_vec(&json!({
        "keyId":"test-key", "publicKey": key.verifying_key().to_bytes(), "tenantId": tenant,
        "storeId": store, "policyVersion": 1, "notBefore": now-60, "expiresAt": now+7200, "revoked": false
    })).unwrap()).unwrap();
    let success = |args: &[&str], stdin: Option<&[u8]>| -> Value {
        let result = raw_cli(args, stdin);
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        serde_json::from_slice(&result.stdout).unwrap()
    };
    success(
        &[
            "commerce",
            "capture-import",
            "--state",
            path(&state_path),
            "--ledger",
            path(&db),
        ],
        None,
    );
    success(
        &[
            "commerce",
            "refund-prove",
            "--allow-amount-disclosure",
            "--ledger",
            path(&db),
            "--tenant-id",
            tenant,
            "--store-id",
            store,
            "--capture-id",
            "cap-1",
            "--event-id",
            "00000000-0000-0000-0000-000000000003",
            "--sequence-number",
            "1",
            "--amount-file",
            "-",
            "--output-dir",
            path(&bundle),
        ],
        Some(b"4242"),
    );
    let unsigned = bundle.join("approval.json");
    let proof = bundle.join("proof.json");
    success(
        &[
            "commerce",
            "sign-approval",
            "--approval",
            path(&unsigned),
            "--authority",
            path(&authority_path),
            "--secret-key-file",
            path(&seed_path),
            "--expires-at",
            &(now + 600).to_string(),
            "--output",
            path(&signed_path),
        ],
        None,
    );
    let apply_args = [
        "commerce",
        "refund-apply",
        "--allow-amount-disclosure",
        "--ledger",
        path(&db),
        "--proof",
        path(&proof),
        "--approval",
        path(&signed_path),
        "--authority",
        path(&authority_path),
    ];
    let execution = success(&apply_args, None);
    assert_eq!(execution["amount"], 4242);
    assert!(!raw_cli(&apply_args, None).status.success());
    let pending = success(&["commerce", "refund-pending", "--ledger", path(&db)], None);
    assert_eq!(pending.as_array().unwrap().len(), 1);
    success(
        &[
            "commerce",
            "refund-complete",
            "--ledger",
            path(&db),
            "--idempotency-key",
            execution["idempotencyKey"].as_str().unwrap(),
            "--provider-reference",
            "test-provider-1",
        ],
        None,
    );
    assert!(
        success(&["commerce", "refund-pending", "--ledger", path(&db)], None)
            .as_array()
            .unwrap()
            .is_empty()
    );
}

fn path(path: &Path) -> &str {
    path.to_str().unwrap()
}

fn write_request(dir: &Path) -> PathBuf {
    let file = dir.join("request.json");
    fs::write(&file, include_bytes!("../examples/refund-request.json")).unwrap();
    file
}

#[test]
fn prove_and_verify_commands_enforce_independent_approval() {
    let scratch = Scratch::new();
    let request = write_request(&scratch.0);
    let bundle = scratch.0.join("bundle");
    let result = cli(
        &[
            "commerce",
            "prove",
            "--request",
            path(&request),
            "--amount-file",
            "-",
            "--output-dir",
            path(&bundle),
        ],
        Some(b"4242\n"),
    );
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let summary: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(summary["proofPath"], json!(bundle.join("proof.json")));
    assert!(!String::from_utf8_lossy(&result.stderr).contains("4242"));
    let proof = bundle.join("proof.json");
    let approval = bundle.join("approval.json");
    let proof_bytes = fs::read(&proof).unwrap();
    let record: Value = serde_json::from_slice(&proof_bytes).unwrap();
    assert!(record.get("amount").is_none());
    assert!(record.get("salt").is_none());
    assert!(record["publicInputs"]["amountBindingHash"].is_null());

    // Move the approval to a separate trusted record, leaving only the proof
    // in the submission directory. Production must authenticate this storage.
    let trusted = scratch.0.join("trusted-approval.json");
    fs::rename(&approval, &trusted).unwrap();
    let verified = cli(
        &[
            "commerce",
            "verify",
            "--proof",
            "-",
            "--approval",
            path(&trusted),
        ],
        Some(&proof_bytes),
    );
    assert!(
        verified.status.success(),
        "{}",
        String::from_utf8_lossy(&verified.stderr)
    );
    let report: Value = serde_json::from_slice(&verified.stdout).unwrap();
    assert_eq!(report["valid"], true);
    assert_eq!(report["currency"], "USD");
    assert_eq!(report["cap"], 5000);

    let mut changed: Value = serde_json::from_slice(&fs::read(&trusted).unwrap()).unwrap();
    changed["request"]["currency"] = json!("EUR");
    fs::write(&trusted, serde_json::to_vec(&changed).unwrap()).unwrap();
    let rejected = cli(
        &[
            "commerce",
            "verify",
            "--proof",
            path(&proof),
            "--approval",
            path(&trusted),
        ],
        None,
    );
    assert!(!rejected.status.success());
    assert!(rejected.stdout.is_empty());

    changed["request"]["currency"] = json!("USD");
    fs::write(&trusted, serde_json::to_vec(&changed).unwrap()).unwrap();
    let mut corrupted = record;
    corrupted["proofBytes"][0] = json!(corrupted["proofBytes"][0].as_u64().unwrap() ^ 255);
    fs::write(&proof, serde_json::to_vec(&corrupted).unwrap()).unwrap();
    assert!(!cli(
        &[
            "commerce",
            "verify",
            "--proof",
            path(&proof),
            "--approval",
            path(&trusted),
        ],
        None
    )
    .status
    .success());

    // An approval cannot silently be inferred from the proof bundle.
    assert!(!cli(&["commerce", "verify", "--proof", path(&proof)], None)
        .status
        .success());
}

#[test]
fn rejects_bad_amounts_and_keeps_existing_output_untouched() {
    let scratch = Scratch::new();
    let request = write_request(&scratch.0);
    let bundle = scratch.0.join("bundle");
    for amount in ["4242.50", "-4242", "5001", "18446744073709551616"] {
        let result = cli(
            &[
                "commerce",
                "prove",
                "--request",
                path(&request),
                "--amount-file",
                "-",
                "--output-dir",
                path(&bundle),
            ],
            Some(amount.as_bytes()),
        );
        assert!(!result.status.success());
        assert!(result.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&result.stderr).contains(amount));
        assert!(!bundle.exists());
    }
    fs::create_dir(&bundle).unwrap();
    let sentinel = bundle.join("proof.json");
    fs::write(&sentinel, b"existing proof").unwrap();
    let amount = scratch.0.join("private-amount.txt");
    fs::write(&amount, b"4242").unwrap();
    let result = cli(
        &[
            "commerce",
            "prove",
            "--request",
            path(&request),
            "--amount-file",
            path(&amount),
            "--output-dir",
            path(&bundle),
        ],
        None,
    );
    assert!(!result.status.success());
    assert_eq!(fs::read(&sentinel).unwrap(), b"existing proof");
    assert!(!bundle.join("approval.json").exists());
}

#[test]
fn oversized_context_is_rejected_before_proving() {
    let scratch = Scratch::new();
    let request = scratch.0.join("oversized.json");
    fs::write(&request, vec![b' '; 16 * 1024 + 1]).unwrap();
    let bundle = scratch.0.join("bundle");
    let result = cli(
        &[
            "commerce",
            "prove",
            "--request",
            path(&request),
            "--amount-file",
            "-",
            "--output-dir",
            path(&bundle),
        ],
        None,
    );
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("byte limit"));
    assert!(!bundle.exists());
}
