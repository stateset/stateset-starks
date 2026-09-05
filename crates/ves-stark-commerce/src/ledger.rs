//! Durable disclosed refund reservation and transactional outbox.
//!
//! The database and authority configuration are trusted. Capture ingestion must be
//! authenticated externally. Remote payment execution is at-least-once: workers
//! must pass the stable idempotency key to the payment provider before marking done.

use crate::{
    approval::{ApprovalAuthority, SignedApproval},
    refund::{RefundProof, RefundState},
    CommerceError,
};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::{path::Path, time::Duration};
use uuid::Uuid;
use ves_stark_primitives::hash::Hash256;

/// Ledger failures; failed transactions do not reserve money or consume approvals.
#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    /// Cryptographic or business validation failed.
    #[error(transparent)]
    Commerce(#[from] CommerceError),
    /// Database access failed.
    #[error(transparent)]
    Database(#[from] rusqlite::Error),
    /// Stored or submitted JSON was malformed.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// An event or nonce has already been consumed.
    #[error("refund event or approval nonce already consumed")]
    AlreadyConsumed,
    /// Another refund advanced this capture state.
    #[error("capture state is missing or stale; obtain a new approval")]
    StaleState,
    /// Invalid outbox operation.
    #[error("invalid outbox operation")]
    InvalidOutbox,
    /// The database belongs to another application or an unsupported schema revision.
    #[error("not a supported StateSet refund ledger database")]
    UnsupportedSchema,
}

/// Immutable request for a payment worker. All monetary values are public.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RefundExecution {
    /// Stable key to pass to the provider on every retry.
    pub idempotency_key: String,
    /// Refund event.
    pub event_id: Uuid,
    /// Tenant scope.
    pub tenant_id: Uuid,
    /// Store scope.
    pub store_id: Uuid,
    /// Original capture identifier.
    pub capture_id: String,
    /// Refund amount in integer currency units.
    pub amount: u64,
    /// Currency code.
    pub currency: String,
    /// Monetary decimal scale.
    pub decimal_places: u8,
    /// Committed successor balance after this reservation.
    pub after_commitment: String,
}

/// SQLite ledger. Use separate connections per worker; writes serialize through
/// BEGIN IMMEDIATE and the expected state commitment is compared inside the transaction.
pub struct RefundLedger {
    connection: Connection,
}

impl RefundLedger {
    /// Open a durable ledger and initialize its schema. Never uses REPLACE for captures.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, LedgerError> {
        let mut connection = Connection::open(path)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        // Check ownership before changing journal mode or creating any tables.
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let application_id: i64 = tx.query_row("PRAGMA application_id", [], |r| r.get(0))?;
        let version: i64 = tx.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if application_id == 0 && version == 0 {
            let tables: i64 = tx.query_row("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'", [], |r| r.get(0))?;
            if tables != 0 {
                return Err(LedgerError::UnsupportedSchema);
            }
        } else if application_id != 0x53535246 || version != 1 {
            return Err(LedgerError::UnsupportedSchema);
        }
        tx.execute_batch(
            "PRAGMA application_id=1397969478; PRAGMA user_version=1;
            CREATE TABLE IF NOT EXISTS refund_captures (
                tenant TEXT NOT NULL, store TEXT NOT NULL, capture TEXT NOT NULL,
                commitment TEXT NOT NULL, state_json TEXT NOT NULL,
                PRIMARY KEY (tenant, store, capture));
            CREATE TABLE IF NOT EXISTS refund_consumptions (
                tenant TEXT NOT NULL, store TEXT NOT NULL, event TEXT NOT NULL, nonce TEXT NOT NULL,
                signed_approval TEXT NOT NULL, refund_proof TEXT NOT NULL,
                PRIMARY KEY (tenant, store, event), UNIQUE (tenant, store, nonce));
            CREATE TABLE IF NOT EXISTS refund_outbox (
                idempotency_key TEXT PRIMARY KEY, execution_json TEXT NOT NULL,
                provider_reference TEXT);",
        )?;
        tx.commit()?;
        connection.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;")?;
        Ok(Self { connection })
    }

    /// Import a captured payment from an authenticated source. Existing captures
    /// cannot be overwritten, including captures with already reserved refunds.
    pub fn register_capture(&self, state: &RefundState) -> Result<(), LedgerError> {
        let commitment = state.commitment()?;
        self.connection.execute(
            "INSERT INTO refund_captures VALUES (?1,?2,?3,?4,?5)",
            params![
                state.tenant_id.to_string(),
                state.store_id.to_string(),
                state.capture_id,
                commitment,
                serde_json::to_string(state)?
            ],
        )?;
        Ok(())
    }

    /// Load the current authenticated local capture state.
    pub fn state(
        &self,
        tenant: Uuid,
        store: Uuid,
        capture: &str,
    ) -> Result<RefundState, LedgerError> {
        let json: String = self.connection.query_row(
            "SELECT state_json FROM refund_captures WHERE tenant=?1 AND store=?2 AND capture=?3",
            params![tenant.to_string(), store.to_string(), capture],
            |row| row.get(0),
        )?;
        Ok(serde_json::from_str(&json)?)
    }

    /// Verify and atomically reserve a refund, consume its event/nonce, and enqueue execution.
    /// `now` must be trusted Unix time, not a value supplied by the submitting prover.
    /// A replay returns AlreadyConsumed; workers retry the persisted outbox request.
    pub fn apply_refund(
        &mut self,
        proof: &RefundProof,
        signed: &SignedApproval,
        authority: &ApprovalAuthority,
        now: u64,
    ) -> Result<RefundExecution, LedgerError> {
        let before = &proof.transition.before;
        let before_hash = before.commitment()?;
        proof.verify_disclosed(signed, authority, now, &before_hash)?;
        let request = &signed.terms.approval.request;
        let tenant = before.tenant_id.to_string();
        let store = before.store_id.to_string();
        let event = request.event_id.to_string();
        let nonce = signed.terms.nonce.to_string();
        let mut key_input = Vec::with_capacity(48);
        key_input.extend_from_slice(before.tenant_id.as_bytes());
        key_input.extend_from_slice(before.store_id.as_bytes());
        key_input.extend_from_slice(request.event_id.as_bytes());
        let execution = RefundExecution {
            idempotency_key: Hash256::sha256_with_domain(
                b"STATESET_REFUND_EXECUTION_V1",
                &key_input,
            )
            .to_hex(),
            event_id: request.event_id,
            tenant_id: before.tenant_id,
            store_id: before.store_id,
            capture_id: before.capture_id.clone(),
            amount: proof.transition.amount,
            currency: before.currency.clone(),
            decimal_places: before.decimal_places,
            after_commitment: proof.transition.after.commitment()?,
        };
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let consumed: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM refund_consumptions WHERE tenant=?1 AND store=?2 AND (event=?3 OR nonce=?4))",
            params![tenant, store, event, nonce], |row| row.get(0))?;
        if consumed {
            return Err(LedgerError::AlreadyConsumed);
        }
        let current: Option<String> = tx.query_row(
            "SELECT commitment FROM refund_captures WHERE tenant=?1 AND store=?2 AND capture=?3",
            params![tenant, store, before.capture_id], |row| row.get(0)).optional()?;
        if current.as_deref() != Some(before_hash.as_str()) {
            return Err(LedgerError::StaleState);
        }
        tx.execute("UPDATE refund_captures SET commitment=?4, state_json=?5 WHERE tenant=?1 AND store=?2 AND capture=?3",
            params![tenant, store, before.capture_id, execution.after_commitment, serde_json::to_string(&proof.transition.after)?])?;
        tx.execute(
            "INSERT INTO refund_consumptions VALUES (?1,?2,?3,?4,?5,?6)",
            params![
                tenant,
                store,
                event,
                nonce,
                serde_json::to_string(signed)?,
                serde_json::to_string(proof)?
            ],
        )?;
        tx.execute(
            "INSERT INTO refund_outbox (idempotency_key, execution_json) VALUES (?1,?2)",
            params![
                execution.idempotency_key,
                serde_json::to_string(&execution)?
            ],
        )?;
        tx.commit()?;
        Ok(execution)
    }

    /// Read pending execution requests. Reading does not consume them; a worker
    /// crash leaves them available for retry with the same provider idempotency key.
    pub fn pending(&self, limit: u32) -> Result<Vec<RefundExecution>, LedgerError> {
        if limit == 0 || limit > 1000 {
            return Err(LedgerError::InvalidOutbox);
        }
        let mut statement = self.connection.prepare(
            "SELECT execution_json FROM refund_outbox WHERE provider_reference IS NULL ORDER BY rowid LIMIT ?1")?;
        let rows = statement.query_map([limit], |row| row.get::<_, String>(0))?;
        rows.map(|row| Ok(serde_json::from_str(&row?)?)).collect()
    }

    /// Mark execution complete only after the provider confirms success. A retry
    /// with the same reference is idempotent; a different reference is rejected.
    pub fn mark_executed(&self, key: &str, provider_reference: &str) -> Result<(), LedgerError> {
        if provider_reference.is_empty()
            || provider_reference.len() > 256
            || provider_reference.chars().any(char::is_control)
        {
            return Err(LedgerError::InvalidOutbox);
        }
        let changed = self.connection.execute(
            "UPDATE refund_outbox SET provider_reference=?2 WHERE idempotency_key=?1 AND (provider_reference IS NULL OR provider_reference=?2)",
            params![key, provider_reference])?;
        if changed != 1 {
            return Err(LedgerError::InvalidOutbox);
        }
        Ok(())
    }
}
