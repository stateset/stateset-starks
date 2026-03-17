//! Set Chain client for anchoring STARK batch proofs
//!
//! This module provides a client for submitting batch STARK proofs to Set Chain
//! via the sequencer's anchor service.

use base64::Engine;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use ves_stark_primitives::Hash256;
use zeroize::Zeroizing;

use crate::error::{ClientError, Result};

const ZERO_REGISTRY_ADDRESS: &str = "0x0000000000000000000000000000000000000000";
const BATCH_PROOF_HASH_DOMAIN: &[u8] = b"STATESET_VES_BATCH_PROOF_HASH_V1";

fn compute_set_chain_batch_proof_hash(proof_bytes: &[u8]) -> String {
    let hash = Hash256::sha256_with_domain(BATCH_PROOF_HASH_DOMAIN, proof_bytes);
    format!("0x{}", hash.to_hex())
}

fn normalize_set_chain_batch_proof_hash(expected_hash: &str) -> String {
    let trimmed = expected_hash.trim();
    if trimmed.starts_with("0x") || trimmed.starts_with("0X") {
        trimmed.to_string()
    } else {
        format!("0x{}", trimmed)
    }
}

fn decode_fixed_hex<const N: usize>(label: &str, value: &str) -> Result<[u8; N]> {
    let trimmed = value.trim();
    let hex_value = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .ok_or_else(|| {
            ClientError::InvalidPublicInputs(format!("{label} must be 0x-prefixed hex"))
        })?;

    if hex_value.len() != N * 2 {
        return Err(ClientError::InvalidPublicInputs(format!(
            "{label} must be {} bytes of hex",
            N
        )));
    }

    let bytes = hex::decode(hex_value)
        .map_err(|e| ClientError::InvalidPublicInputs(format!("{label} is not valid hex: {e}")))?;

    bytes.try_into().map_err(|_| {
        ClientError::InvalidPublicInputs(format!("{label} must be {} bytes of hex", N))
    })
}

fn normalize_and_validate_set_chain_batch_proof_hash(expected_hash: &str) -> Result<String> {
    let normalized = normalize_set_chain_batch_proof_hash(expected_hash);
    let _ = decode_fixed_hex::<32>("expected_proof_hash", &normalized)?;
    Ok(normalized)
}

/// Set Chain configuration
#[derive(Debug, Clone)]
pub struct SetChainConfig {
    /// RPC URL for Set Chain (e.g., "https://rpc.set.stateset.network")
    pub rpc_url: String,
    /// Chain ID for Set Chain (84532001)
    pub chain_id: u64,
    /// SetRegistry contract address
    pub registry_address: String,
}

impl Default for SetChainConfig {
    fn default() -> Self {
        Self {
            rpc_url: "https://rpc.set.stateset.network".to_string(),
            chain_id: 84532001,
            // Must be replaced with the deployed SetRegistry address before use.
            registry_address: "0x0000000000000000000000000000000000000000".to_string(),
        }
    }
}

impl SetChainConfig {
    fn validate(&self) -> Result<()> {
        let address = self.registry_address.trim();

        let hex_address = address
            .strip_prefix("0x")
            .or_else(|| address.strip_prefix("0X"))
            .ok_or_else(|| {
                ClientError::InvalidPublicInputs(
                    "registry_address must be a 0x-prefixed hex string".to_string(),
                )
            })?;

        if address.eq_ignore_ascii_case(ZERO_REGISTRY_ADDRESS) {
            return Err(ClientError::InvalidPublicInputs(
                "registry_address must be non-zero".to_string(),
            ));
        }

        if hex_address.len() != 40 {
            return Err(ClientError::InvalidPublicInputs(
                "registry_address must be 20-byte hex string".to_string(),
            ));
        }

        let bytes = hex::decode(hex_address).map_err(|_| {
            ClientError::InvalidPublicInputs("registry_address is not valid hex".to_string())
        })?;

        if bytes.len() != 20 || bytes.iter().all(|byte| *byte == 0) {
            return Err(ClientError::InvalidPublicInputs(
                "registry_address must be a 20-byte non-zero hex address".to_string(),
            ));
        }

        Ok(())
    }

    /// Create a config for local development
    pub fn local() -> Self {
        Self {
            rpc_url: "http://localhost:8545".to_string(),
            chain_id: 31337,
            registry_address: "0x5FbDB2315678afecb367f032d93F642f64180aa3".to_string(),
        }
    }

    /// Create a config for testnet
    pub fn testnet() -> Self {
        Self {
            rpc_url: "https://rpc-testnet.set.stateset.network".to_string(),
            chain_id: 84532001,
            // Must be replaced with the deployed SetRegistry address before use.
            registry_address: "0x0000000000000000000000000000000000000000".to_string(),
        }
    }
}

/// STARK batch proof for Set Chain submission
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchProofSubmission {
    /// Unique batch identifier
    pub batch_id: Uuid,
    /// Tenant that owns this batch
    pub tenant_id: Uuid,
    /// Store ID for this batch
    pub store_id: Uuid,
    /// Merkle root of all events in the batch
    pub events_root: String,
    /// Previous state root (for continuity)
    pub prev_state_root: String,
    /// New state root after this batch
    pub new_state_root: String,
    /// First sequence number in batch
    pub sequence_start: u64,
    /// Last sequence number in batch
    pub sequence_end: u64,
    /// Number of events in batch
    pub event_count: u32,
    /// The STARK proof bytes (base64 encoded)
    pub proof_b64: String,
    /// Policy hash used for compliance
    pub policy_hash: String,
    /// Policy limit/threshold
    pub policy_limit: u64,
    /// Whether all events passed compliance
    pub all_compliant: bool,
}

impl BatchProofSubmission {
    /// Compute the domain-separated batch proof hash in the `0x`-prefixed
    /// form expected by the Set Chain HTTP API.
    ///
    /// Returns an error if the base64-encoded proof bytes are invalid.
    pub fn proof_hash(&self) -> Result<String> {
        let proof_bytes = base64::engine::general_purpose::STANDARD
            .decode(&self.proof_b64)
            .map_err(|e| ClientError::InvalidPublicInputs(format!("invalid proof base64: {e}")))?;
        Ok(compute_set_chain_batch_proof_hash(&proof_bytes))
    }

    /// Get proof size in bytes.
    pub fn try_proof_size(&self) -> Result<u64> {
        let proof_bytes = base64::engine::general_purpose::STANDARD
            .decode(&self.proof_b64)
            .map_err(|e| ClientError::InvalidPublicInputs(format!("invalid proof base64: {e}")))?;
        u64::try_from(proof_bytes.len()).map_err(|_| {
            ClientError::InvalidPublicInputs("proof is too large to fit in u64".to_string())
        })
    }

    /// Get proof size in bytes.
    ///
    /// Returns 0 if the base64-encoded proof is invalid.
    pub fn proof_size(&self) -> u64 {
        self.try_proof_size().unwrap_or(0)
    }

    /// Validate that the submission is internally consistent before sending it.
    pub fn validate(&self) -> Result<()> {
        let _ = decode_fixed_hex::<32>("events_root", &self.events_root)?;
        let _ = decode_fixed_hex::<32>("prev_state_root", &self.prev_state_root)?;
        let _ = decode_fixed_hex::<32>("new_state_root", &self.new_state_root)?;
        let _ = decode_fixed_hex::<32>("policy_hash", &self.policy_hash)?;

        let proof_size = self.try_proof_size()?;
        if proof_size == 0 {
            return Err(ClientError::InvalidPublicInputs(
                "proof_b64 must decode to a non-empty proof".to_string(),
            ));
        }

        let expected_event_count = self
            .sequence_end
            .checked_sub(self.sequence_start)
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| {
                ClientError::InvalidPublicInputs(
                    "sequence range overflows when computing event_count".to_string(),
                )
            })?;
        if expected_event_count != u64::from(self.event_count) {
            return Err(ClientError::InvalidPublicInputs(format!(
                "sequence range implies {} events, but event_count is {}",
                expected_event_count, self.event_count
            )));
        }

        let _ = self.proof_hash()?;
        Ok(())
    }
}

/// Response after submitting a batch proof to Set Chain
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchProofResponse {
    /// Batch ID
    pub batch_id: Uuid,
    /// Transaction hash on Set Chain
    pub tx_hash: String,
    /// Block number where the proof was anchored
    pub block_number: Option<u64>,
    /// Proof hash (domain-separated batch proof hash, `0x`-prefixed)
    pub proof_hash: String,
    /// Whether anchoring was successful
    pub success: bool,
    /// Error message if failed
    pub error: Option<String>,
}

/// Status of a batch proof on Set Chain
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchProofStatus {
    /// Batch ID
    pub batch_id: Uuid,
    /// Whether the batch has been committed
    pub batch_committed: bool,
    /// Whether the STARK proof has been committed
    pub proof_committed: bool,
    /// Transaction hash (if committed)
    pub tx_hash: Option<String>,
    /// Block number (if committed)
    pub block_number: Option<u64>,
    /// Previous state root
    pub prev_state_root: Option<String>,
    /// New state root
    pub new_state_root: Option<String>,
    /// Proof hash
    pub proof_hash: Option<String>,
    /// Policy hash
    pub policy_hash: Option<String>,
    /// Policy limit
    pub policy_limit: Option<u64>,
    /// Compliance status
    pub all_compliant: Option<bool>,
    /// Timestamp of proof submission
    pub timestamp: Option<u64>,
}

/// Batch proof verification result
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchProofVerification {
    /// Batch ID
    pub batch_id: Uuid,
    /// Whether the proof hash matches on-chain
    pub proof_hash_valid: bool,
    /// The on-chain proof hash
    pub onchain_proof_hash: String,
    /// The expected proof hash
    pub expected_proof_hash: String,
    /// Whether state roots match
    pub state_roots_valid: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StateRootResponse {
    state_root: Option<String>,
}

/// Client for submitting batch proofs to Set Chain via the sequencer
pub struct SetChainClient {
    client: reqwest::Client,
    base_url: String,
    config: SetChainConfig,
}

impl SetChainClient {
    async fn response_body_or_debug_message(response: reqwest::Response) -> String {
        response
            .text()
            .await
            .unwrap_or_else(|e| format!("<failed to read response body: {e}>"))
    }

    /// Create a new Set Chain client
    ///
    /// # Arguments
    ///
    /// * `base_url` - The base URL of the sequencer (e.g., "http://localhost:8080")
    /// * `api_key` - The API key for authentication
    /// * `config` - Set Chain configuration
    pub fn new(base_url: &str, api_key: &str, config: SetChainConfig) -> Result<Self> {
        config.validate()?;

        let base_url = base_url.trim();
        if base_url.is_empty() {
            return Err(ClientError::InvalidBaseUrl(
                "base_url must not be empty".to_string(),
            ));
        }
        reqwest::Url::parse(base_url).map_err(|e| ClientError::InvalidBaseUrl(e.to_string()))?;

        let api_key = api_key.trim();
        if api_key.is_empty() {
            return Err(ClientError::InvalidHeader(
                "api_key must not be empty".to_string(),
            ));
        }

        let key = Zeroizing::new(format!("Bearer {}", api_key));
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        let auth_value =
            HeaderValue::from_str(&key).map_err(|e| ClientError::InvalidHeader(e.to_string()))?;
        headers.insert(AUTHORIZATION, auth_value);
        // `key` is zeroed on drop here

        let client = reqwest::Client::builder()
            .default_headers(headers)
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            config,
        })
    }

    /// Create a new Set Chain client.
    ///
    /// The API key is wrapped in `Zeroizing` and will be zeroed from memory
    /// after the Authorization header has been built.
    pub fn try_new(base_url: &str, api_key: &str, config: SetChainConfig) -> Result<Self> {
        Self::new(base_url, api_key, config)
    }

    /// Create a client without authentication (for local development).
    ///
    /// Only available when the `dev` feature is enabled.
    #[cfg(feature = "dev")]
    pub fn unauthenticated(base_url: &str, config: SetChainConfig) -> Result<Self> {
        Self::try_unauthenticated(base_url, config)
    }

    /// Create a client without authentication (for local development) without panicking.
    ///
    /// Only available when the `dev` feature is enabled.
    #[cfg(feature = "dev")]
    pub fn try_unauthenticated(base_url: &str, config: SetChainConfig) -> Result<Self> {
        config.validate()?;

        let base_url = base_url.trim();
        if base_url.is_empty() {
            return Err(ClientError::InvalidBaseUrl(
                "base_url must not be empty".to_string(),
            ));
        }
        reqwest::Url::parse(base_url).map_err(|e| ClientError::InvalidBaseUrl(e.to_string()))?;

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        let client = reqwest::Client::builder()
            .default_headers(headers)
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            config,
        })
    }

    /// Get the Set Chain configuration
    pub fn config(&self) -> &SetChainConfig {
        &self.config
    }

    /// Submit a batch proof to Set Chain
    ///
    /// This submits the proof via the sequencer's anchor service, which handles
    /// the on-chain transaction to SetRegistry.
    pub async fn submit_batch_proof(
        &self,
        submission: BatchProofSubmission,
    ) -> Result<BatchProofResponse> {
        submission.validate()?;
        let url = format!(
            "{}/api/v1/anchor/batch/{}/proof",
            self.base_url, submission.batch_id
        );

        let response = self.client.post(&url).json(&submission).send().await?;

        let status = response.status();
        if status.is_success() {
            Ok(response.json().await?)
        } else if status.as_u16() == 404 {
            Err(ClientError::BatchNotFound(submission.batch_id))
        } else if status.as_u16() == 401 || status.as_u16() == 403 {
            let body = Self::response_body_or_debug_message(response).await;
            Err(ClientError::Unauthorized(body))
        } else if status.as_u16() == 409 {
            Err(ClientError::ProofAlreadyAnchored(submission.batch_id))
        } else {
            let body = Self::response_body_or_debug_message(response).await;
            Err(ClientError::ApiError {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    /// Submit a batch proof with combined batch commitment (single transaction)
    ///
    /// This is more gas-efficient as it commits the batch and proof in one transaction.
    pub async fn submit_batch_with_proof(
        &self,
        submission: BatchProofSubmission,
        proving_time_ms: u64,
    ) -> Result<BatchProofResponse> {
        submission.validate()?;
        let url = format!(
            "{}/api/v1/anchor/batch/{}/commit-with-proof",
            self.base_url, submission.batch_id
        );

        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct CombinedRequest {
            #[serde(flatten)]
            submission: BatchProofSubmission,
            proving_time_ms: u64,
        }

        let request = CombinedRequest {
            submission,
            proving_time_ms,
        };

        let response = self.client.post(&url).json(&request).send().await?;

        let status = response.status();
        if status.is_success() {
            Ok(response.json().await?)
        } else if status.as_u16() == 404 {
            Err(ClientError::BatchNotFound(request.submission.batch_id))
        } else if status.as_u16() == 401 || status.as_u16() == 403 {
            let body = Self::response_body_or_debug_message(response).await;
            Err(ClientError::Unauthorized(body))
        } else if status.as_u16() == 409 {
            Err(ClientError::BatchAlreadyCommitted(
                request.submission.batch_id,
            ))
        } else {
            let body = Self::response_body_or_debug_message(response).await;
            Err(ClientError::ApiError {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    /// Get the status of a batch proof on Set Chain
    pub async fn get_batch_proof_status(&self, batch_id: Uuid) -> Result<BatchProofStatus> {
        let url = format!("{}/api/v1/anchor/batch/{}/status", self.base_url, batch_id);

        let response = self.client.get(&url).send().await?;

        let status = response.status();
        if status.is_success() {
            Ok(response.json().await?)
        } else if status.as_u16() == 404 {
            Err(ClientError::BatchNotFound(batch_id))
        } else {
            let body = Self::response_body_or_debug_message(response).await;
            Err(ClientError::ApiError {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    /// Check if a batch has a STARK proof anchored on Set Chain
    pub async fn has_stark_proof(&self, batch_id: Uuid) -> Result<bool> {
        let status = self.get_batch_proof_status(batch_id).await?;
        Ok(status.proof_committed)
    }

    /// Verify a batch proof hash against the on-chain value
    pub async fn verify_proof_hash(
        &self,
        batch_id: Uuid,
        expected_proof_hash: &str,
    ) -> Result<BatchProofVerification> {
        let url = format!(
            "{}/api/v1/anchor/batch/{}/verify-proof",
            self.base_url, batch_id
        );

        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct VerifyRequest {
            expected_proof_hash: String,
        }

        let request = VerifyRequest {
            expected_proof_hash: normalize_and_validate_set_chain_batch_proof_hash(
                expected_proof_hash,
            )?,
        };

        let response = self.client.post(&url).json(&request).send().await?;

        let status = response.status();
        if status.is_success() {
            Ok(response.json().await?)
        } else if status.as_u16() == 404 {
            Err(ClientError::BatchNotFound(batch_id))
        } else {
            let body = Self::response_body_or_debug_message(response).await;
            Err(ClientError::ApiError {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    /// Get all batch proofs for a tenant
    pub async fn list_batch_proofs(
        &self,
        tenant_id: Uuid,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> Result<Vec<BatchProofStatus>> {
        let mut url = format!(
            "{}/api/v1/anchor/tenant/{}/batch-proofs",
            self.base_url, tenant_id
        );

        let mut query_params = vec![];
        if let Some(l) = limit {
            query_params.push(format!("limit={}", l));
        }
        if let Some(o) = offset {
            query_params.push(format!("offset={}", o));
        }
        if !query_params.is_empty() {
            url = format!("{}?{}", url, query_params.join("&"));
        }

        let response = self.client.get(&url).send().await?;

        let status = response.status();
        if status.is_success() {
            Ok(response.json().await?)
        } else {
            let body = Self::response_body_or_debug_message(response).await;
            Err(ClientError::ApiError {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    /// Get the latest committed state root for a tenant
    pub async fn get_latest_state_root(&self, tenant_id: Uuid) -> Result<Option<String>> {
        let url = format!(
            "{}/api/v1/anchor/tenant/{}/state-root",
            self.base_url, tenant_id
        );

        let response = self.client.get(&url).send().await?;

        let status = response.status();
        if status.is_success() {
            let resp: StateRootResponse = response.json().await?;
            Ok(resp.state_root)
        } else if status.as_u16() == 404 {
            Ok(None)
        } else {
            let body = Self::response_body_or_debug_message(response).await;
            Err(ClientError::ApiError {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    /// Create a batch proof submission from a BatchProof
    ///
    /// Prefer `BatchSubmissionBuilder` for readability.
    #[allow(clippy::too_many_arguments)]
    pub fn create_submission(
        batch_id: Uuid,
        tenant_id: Uuid,
        store_id: Uuid,
        events_root: [u8; 32],
        prev_state_root: [u8; 32],
        new_state_root: [u8; 32],
        sequence_start: u64,
        sequence_end: u64,
        event_count: u32,
        proof_bytes: &[u8],
        policy_hash: [u8; 32],
        policy_limit: u64,
        all_compliant: bool,
    ) -> BatchProofSubmission {
        BatchProofSubmission {
            batch_id,
            tenant_id,
            store_id,
            events_root: format!("0x{}", hex::encode(events_root)),
            prev_state_root: format!("0x{}", hex::encode(prev_state_root)),
            new_state_root: format!("0x{}", hex::encode(new_state_root)),
            sequence_start,
            sequence_end,
            event_count,
            proof_b64: base64::engine::general_purpose::STANDARD.encode(proof_bytes),
            policy_hash: format!("0x{}", hex::encode(policy_hash)),
            policy_limit,
            all_compliant,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_chain_config_default() {
        let config = SetChainConfig::default();
        assert_eq!(config.chain_id, 84532001);
        assert!(config.rpc_url.contains("stateset.network"));
    }

    #[test]
    fn test_set_chain_config_zero_registry_is_rejected() {
        let config = SetChainConfig::testnet();
        assert!(SetChainClient::try_new("http://localhost:8080", "test_key", config).is_err());
    }

    #[test]
    fn test_set_chain_client_rejects_invalid_base_url() {
        let config = SetChainConfig::local();
        assert!(SetChainClient::new("", "test_key", config.clone()).is_err());
        assert!(SetChainClient::new("::::", "test_key", config.clone()).is_err());
    }

    #[test]
    fn test_set_chain_client_rejects_empty_api_key() {
        let config = SetChainConfig::local();
        assert!(SetChainClient::new("http://localhost:8080", "", config.clone()).is_err());
        assert!(SetChainClient::new("http://localhost:8080", "   ", config).is_err());
    }

    #[test]
    fn test_set_chain_config_default_is_rejected() {
        let config = SetChainConfig::default();
        assert!(SetChainClient::try_new("http://localhost:8080", "test_key", config).is_err());
    }

    #[test]
    fn test_set_chain_config_local() {
        let config = SetChainConfig::local();
        assert_eq!(config.chain_id, 31337);
        assert!(config.rpc_url.contains("localhost"));
    }

    #[test]
    fn test_client_creation() {
        let config = SetChainConfig::local();
        let _client = SetChainClient::try_new("http://localhost:8080", "test_key", config).unwrap();
    }

    #[cfg(feature = "dev")]
    #[test]
    fn test_unauthenticated_client() {
        let config = SetChainConfig::local();
        let _client = SetChainClient::try_unauthenticated("http://localhost:8080", config).unwrap();
    }

    #[test]
    fn test_batch_proof_submission() {
        let submission = BatchProofSubmission {
            batch_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            store_id: Uuid::new_v4(),
            events_root: format!("0x{}", "11".repeat(32)),
            prev_state_root: format!("0x{}", "22".repeat(32)),
            new_state_root: format!("0x{}", "33".repeat(32)),
            sequence_start: 1,
            sequence_end: 10,
            event_count: 10,
            proof_b64: base64::engine::general_purpose::STANDARD.encode(b"test proof"),
            policy_hash: format!("0x{}", "44".repeat(32)),
            policy_limit: 10000,
            all_compliant: true,
        };

        submission.validate().unwrap();
        assert_eq!(
            submission.proof_hash().unwrap(),
            compute_set_chain_batch_proof_hash(b"test proof")
        );
        assert_eq!(submission.proof_size(), 10);
        assert_eq!(submission.try_proof_size().unwrap(), 10);
    }

    #[test]
    fn test_normalize_set_chain_batch_proof_hash_adds_prefix() {
        assert_eq!(
            normalize_set_chain_batch_proof_hash("abcd"),
            "0xabcd".to_string()
        );
        assert_eq!(
            normalize_set_chain_batch_proof_hash("0xabcd"),
            "0xabcd".to_string()
        );
    }

    #[test]
    fn test_normalize_and_validate_set_chain_batch_proof_hash_rejects_invalid_hex() {
        assert!(normalize_and_validate_set_chain_batch_proof_hash("xyz").is_err());
        assert!(normalize_and_validate_set_chain_batch_proof_hash("0x12").is_err());
    }

    #[test]
    fn test_create_submission() {
        let submission = SetChainClient::create_submission(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            [0u8; 32],
            [1u8; 32],
            [2u8; 32],
            1,
            10,
            10,
            b"proof bytes",
            [3u8; 32],
            10000,
            true,
        );

        assert!(submission.events_root.starts_with("0x"));
        assert!(submission.prev_state_root.starts_with("0x"));
        assert!(submission.new_state_root.starts_with("0x"));
        assert!(submission.policy_hash.starts_with("0x"));
        assert!(!submission.proof_b64.is_empty());
        submission.validate().unwrap();
    }

    #[test]
    fn test_batch_proof_submission_validate_rejects_sequence_mismatch() {
        let mut submission = SetChainClient::create_submission(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            [0u8; 32],
            [1u8; 32],
            [2u8; 32],
            1,
            10,
            10,
            b"proof bytes",
            [3u8; 32],
            10000,
            true,
        );
        submission.event_count = 9;

        assert!(submission.validate().is_err());
    }

    #[test]
    fn test_batch_proof_submission_validate_rejects_invalid_roots() {
        let mut submission = SetChainClient::create_submission(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            [0u8; 32],
            [1u8; 32],
            [2u8; 32],
            1,
            10,
            10,
            b"proof bytes",
            [3u8; 32],
            10000,
            true,
        );
        submission.prev_state_root = "0x1234".to_string();

        assert!(submission.validate().is_err());
    }

    #[test]
    fn test_batch_proof_submission_validate_rejects_invalid_proof_base64() {
        let mut submission = SetChainClient::create_submission(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            [0u8; 32],
            [1u8; 32],
            [2u8; 32],
            1,
            10,
            10,
            b"proof bytes",
            [3u8; 32],
            10000,
            true,
        );
        submission.proof_b64 = "***not-base64***".to_string();

        assert!(submission.validate().is_err());
        assert_eq!(submission.proof_size(), 0);
        assert!(submission.try_proof_size().is_err());
    }

    #[test]
    fn test_state_root_response_deserializes_camel_case() {
        let response: StateRootResponse = serde_json::from_value(serde_json::json!({
            "stateRoot": "0x1234"
        }))
        .unwrap();

        assert_eq!(response.state_root.as_deref(), Some("0x1234"));
    }
}
