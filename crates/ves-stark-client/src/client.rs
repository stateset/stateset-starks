//! Sequencer HTTP client

use base64::Engine;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use uuid::Uuid;
use ves_stark_air::policy::Policy;
use zeroize::Zeroizing;

use crate::error::{ClientError, Result};
use crate::types::*;

/// HTTP client for the StateSet sequencer
pub struct SequencerClient {
    client: reqwest::Client,
    base_url: String,
}

impl SequencerClient {
    fn policy_params_for_limit(policy_id: &str, policy_limit: u64) -> Result<serde_json::Value> {
        match policy_id {
            "aml.threshold" => Ok(AmlThresholdParams::new(policy_limit).to_json()),
            "order_total.cap" => Ok(OrderTotalCapParams::new(policy_limit).to_json()),
            _ => Err(ClientError::InvalidPublicInputs(format!(
                "unsupported policy id for limit-based helper: {policy_id}"
            ))),
        }
    }

    async fn response_body_or_debug_message(response: reqwest::Response) -> String {
        response
            .text()
            .await
            .unwrap_or_else(|e| format!("<failed to read response body: {e}>"))
    }

    /// Create a new sequencer client from the `STATESET_API_KEY` environment variable.
    ///
    /// # Arguments
    ///
    /// * `base_url` - The base URL of the sequencer (e.g., "http://localhost:8080")
    pub fn from_env(base_url: &str) -> Result<Self> {
        let api_key = std::env::var("STATESET_API_KEY").map_err(|_| {
            ClientError::InvalidHeader("STATESET_API_KEY environment variable not set".to_string())
        })?;
        Self::new(base_url, &api_key)
    }

    /// Create a new sequencer client.
    ///
    /// # Arguments
    ///
    /// * `base_url` - The base URL of the sequencer (e.g., "http://localhost:8080")
    /// * `api_key` - The API key for authentication
    pub fn new(base_url: &str, api_key: &str) -> Result<Self> {
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

        let key = Zeroizing::new(format!("ApiKey {}", api_key));
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
        })
    }

    /// Create a new sequencer client.
    ///
    /// The API key is wrapped in `Zeroizing` and will be zeroed from memory
    /// after the Authorization header has been built.
    pub fn try_new(base_url: &str, api_key: &str) -> Result<Self> {
        Self::new(base_url, api_key)
    }

    /// Create a client without authentication (for local development).
    ///
    /// Only available when the `dev` feature is enabled.
    #[cfg(feature = "dev")]
    pub fn unauthenticated(base_url: &str) -> Result<Self> {
        Self::try_unauthenticated(base_url)
    }

    /// Create a client without authentication (for local development) without panicking.
    ///
    /// Only available when the `dev` feature is enabled.
    #[cfg(feature = "dev")]
    pub fn try_unauthenticated(base_url: &str) -> Result<Self> {
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
        })
    }

    /// Get public inputs for a limit-based policy.
    ///
    /// Supported policy ids:
    /// - `aml.threshold`
    /// - `order_total.cap`
    pub async fn get_public_inputs(
        &self,
        event_id: Uuid,
        policy_id: &str,
        policy_limit: u64,
    ) -> Result<PublicInputsResponse> {
        self.get_public_inputs_with_params(
            event_id,
            policy_id,
            Self::policy_params_for_limit(policy_id, policy_limit)?,
        )
        .await
    }

    /// Get public inputs for an event with the specified policy and parameters.
    pub async fn get_public_inputs_with_params(
        &self,
        event_id: Uuid,
        policy_id: &str,
        policy_params: serde_json::Value,
    ) -> Result<PublicInputsResponse> {
        let url = format!(
            "{}/api/v1/ves/compliance/{}/inputs",
            self.base_url, event_id
        );

        let request = PublicInputsRequest {
            policy_id: policy_id.to_string(),
            policy_params,
        };

        let response = self.client.post(&url).json(&request).send().await?;

        let status = response.status();
        if status.is_success() {
            Ok(response.json().await?)
        } else if status.as_u16() == 404 {
            Err(ClientError::EventNotFound(event_id))
        } else if status.as_u16() == 401 || status.as_u16() == 403 {
            let body = Self::response_body_or_debug_message(response).await;
            Err(ClientError::Unauthorized(body))
        } else {
            let body = Self::response_body_or_debug_message(response).await;
            Err(ClientError::ApiError {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    /// Get public inputs for a limit-based policy and validate the sequencer-provided hash.
    pub async fn get_public_inputs_validated(
        &self,
        event_id: Uuid,
        policy_id: &str,
        policy_limit: u64,
    ) -> Result<ves_stark_primitives::public_inputs::CompliancePublicInputs> {
        let resp = self
            .get_public_inputs(event_id, policy_id, policy_limit)
            .await?;
        resp.validate_and_parse_public_inputs()
    }

    /// Get public inputs for an agent.authorization.v1 policy.
    pub async fn get_authorization_public_inputs(
        &self,
        event_id: Uuid,
        max_total: u64,
        intent_hash: &str,
    ) -> Result<PublicInputsResponse> {
        self.get_public_inputs_with_params(
            event_id,
            "agent.authorization.v1",
            AgentAuthorizationParams::new(max_total, intent_hash)?.to_json(),
        )
        .await
    }

    /// Get public inputs for an agent.authorization.v1 policy from a receipt.
    pub async fn get_authorization_public_inputs_for_receipt(
        &self,
        max_total: u64,
        receipt: &ves_stark_primitives::CommerceAuthorizationReceipt,
    ) -> Result<PublicInputsResponse> {
        self.get_authorization_public_inputs(receipt.event_id, max_total, &receipt.intent_hash)
            .await
    }

    /// Get public inputs for an agent.authorization.v1 policy and validate the sequencer hash.
    pub async fn get_authorization_public_inputs_validated(
        &self,
        event_id: Uuid,
        max_total: u64,
        intent_hash: &str,
    ) -> Result<ves_stark_primitives::public_inputs::CompliancePublicInputs> {
        let resp = self
            .get_authorization_public_inputs(event_id, max_total, intent_hash)
            .await?;
        resp.validate_and_parse_public_inputs()
    }

    /// Get public inputs for an agent.authorization.v1 policy from a receipt and validate the
    /// sequencer hash.
    pub async fn get_authorization_public_inputs_validated_for_receipt(
        &self,
        max_total: u64,
        receipt: &ves_stark_primitives::CommerceAuthorizationReceipt,
    ) -> Result<ves_stark_primitives::public_inputs::CompliancePublicInputs> {
        let resp = self
            .get_authorization_public_inputs_for_receipt(max_total, receipt)
            .await?;
        resp.validate_and_parse_public_inputs()
    }

    /// Get public inputs for an agent.authorization.v1 policy from a receipt, validate the
    /// sequencer hash, and bind both the receipt hash and the implied payload amount binding
    /// locally.
    pub async fn get_authorization_public_inputs_bound_for_receipt(
        &self,
        max_total: u64,
        receipt: &ves_stark_primitives::CommerceAuthorizationReceipt,
    ) -> Result<ves_stark_primitives::public_inputs::CompliancePublicInputs> {
        let inputs = self
            .get_authorization_public_inputs_validated_for_receipt(max_total, receipt)
            .await?;
        inputs
            .bind_amount_and_authorization_receipt(receipt)
            .map_err(|e| ClientError::InvalidPublicInputs(format!("{e}")))
    }

    /// Get public inputs for an agent.authorization.v1 policy from a receipt, validate the
    /// sequencer hash, and bind both the canonical payload amount binding and receipt hash
    /// locally.
    pub async fn get_authorization_public_inputs_canonical_for_receipt(
        &self,
        max_total: u64,
        receipt: &ves_stark_primitives::CommerceAuthorizationReceipt,
    ) -> Result<ves_stark_primitives::public_inputs::CompliancePublicInputs> {
        self.get_authorization_public_inputs_bound_for_receipt(max_total, receipt)
            .await
    }

    /// Get public inputs and validate that the sequencer-provided hash matches the
    /// canonical hash computed locally. Returns canonical typed inputs on success.
    pub async fn get_public_inputs_validated_with_params(
        &self,
        event_id: Uuid,
        policy_id: &str,
        policy_params: serde_json::Value,
    ) -> Result<ves_stark_primitives::public_inputs::CompliancePublicInputs> {
        let resp = self
            .get_public_inputs_with_params(event_id, policy_id, policy_params)
            .await?;
        resp.validate_and_parse_public_inputs()
    }

    /// Submit a compliance proof
    pub async fn submit_proof(&self, submission: ProofSubmission) -> Result<SubmitProofResponse> {
        submission.validate()?;

        let url = format!(
            "{}/api/v1/ves/compliance/{}/proofs",
            self.base_url, submission.event_id
        );

        let proof_b64 = base64::engine::general_purpose::STANDARD.encode(&submission.proof_bytes);

        let request = SubmitProofRequest {
            proof_type: "stark".to_string(),
            proof_version: ves_stark_verifier::PROOF_VERSION,
            policy_id: submission.policy_id,
            policy_params: submission.policy_params,
            proof_b64,
            witness_commitment: WitnessCommitment::Hex(
                ves_stark_primitives::public_inputs::witness_commitment_u64_to_hex(
                    &submission.witness_commitment,
                ),
            ),
            public_inputs: submission
                .public_inputs
                .as_ref()
                .map(serde_json::to_value)
                .transpose()?,
        };

        let response = self.client.post(&url).json(&request).send().await?;

        let status = response.status();
        if status.is_success() {
            Ok(response.json().await?)
        } else if status.as_u16() == 404 {
            Err(ClientError::EventNotFound(submission.event_id))
        } else if status.as_u16() == 401 || status.as_u16() == 403 {
            let body = Self::response_body_or_debug_message(response).await;
            Err(ClientError::Unauthorized(body))
        } else if status.as_u16() == 409 {
            let body = Self::response_body_or_debug_message(response).await;
            Err(ClientError::ApiError {
                status: 409,
                message: format!("Proof conflict: {}", body),
            })
        } else {
            let body = Self::response_body_or_debug_message(response).await;
            Err(ClientError::ApiError {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    /// Submit a canonical `agent.authorization.v1` proof bundle.
    pub async fn submit_agent_authorization_bundle(
        &self,
        bundle: &AgentAuthorizationProofBundle,
    ) -> Result<SubmitProofResponse> {
        self.submit_proof(bundle.to_submission()?).await
    }

    /// Submit a canonical payload-bound compliance proof bundle.
    pub async fn submit_compliance_bundle(
        &self,
        bundle: &ComplianceProofBundle,
    ) -> Result<SubmitProofResponse> {
        self.submit_proof(bundle.to_submission()?).await
    }

    /// List all proofs for an event
    pub async fn list_proofs(&self, event_id: Uuid) -> Result<ListProofsResponse> {
        let url = format!(
            "{}/api/v1/ves/compliance/{}/proofs",
            self.base_url, event_id
        );

        let response = self.client.get(&url).send().await?;

        let status = response.status();
        if status.is_success() {
            Ok(response.json().await?)
        } else if status.as_u16() == 404 {
            Err(ClientError::EventNotFound(event_id))
        } else {
            let body = Self::response_body_or_debug_message(response).await;
            Err(ClientError::ApiError {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    /// Get a specific proof by ID
    pub async fn get_proof(&self, proof_id: Uuid) -> Result<ProofDetails> {
        let url = format!(
            "{}/api/v1/ves/compliance/proofs/{}",
            self.base_url, proof_id
        );

        let response = self.client.get(&url).send().await?;

        let status = response.status();
        if status.is_success() {
            Ok(response.json().await?)
        } else if status.as_u16() == 404 {
            Err(ClientError::ProofNotFound(proof_id))
        } else {
            let body = Self::response_body_or_debug_message(response).await;
            Err(ClientError::ApiError {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    /// Verify a proof
    pub async fn verify_proof(&self, proof_id: Uuid) -> Result<VerifyResponse> {
        let url = format!(
            "{}/api/v1/ves/compliance/proofs/{}/verify",
            self.base_url, proof_id
        );

        let response = self.client.get(&url).send().await?;

        let status = response.status();
        if status.is_success() {
            Ok(response.json().await?)
        } else if status.as_u16() == 404 {
            Err(ClientError::ProofNotFound(proof_id))
        } else {
            let body = Self::response_body_or_debug_message(response).await;
            Err(ClientError::ApiError {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    /// Generate and submit a proof for an event
    ///
    /// This is a convenience method that:
    /// 1. Creates a witness from the amount and public inputs
    /// 2. Generates a STARK proof
    /// 3. Builds a canonical payload-bound proof bundle
    /// 4. Submits the derived proof submission to the sequencer
    pub fn prove_compliance_bundle(
        &self,
        amount: u64,
        policy_limit: u64,
        public_inputs: &ves_stark_primitives::public_inputs::CompliancePublicInputs,
    ) -> Result<ComplianceProofBundle> {
        use ves_stark_prover::{ComplianceProver, ComplianceWitness};

        let policy =
            Policy::from_public_inputs(&public_inputs.policy_id, &public_inputs.policy_params)
                .map_err(|e| {
                    ClientError::InvalidPublicInputs(format!("invalid public inputs policy: {e}"))
                })?;

        if policy.limit() != policy_limit {
            return Err(ClientError::InvalidPublicInputs(format!(
                "Policy limit mismatch for policy {}: expected {}, got {}",
                public_inputs.policy_id,
                policy.limit(),
                policy_limit
            )));
        }

        let witness = ComplianceWitness::try_new(amount, public_inputs.clone())
            .map_err(|e| ClientError::InvalidPublicInputs(format!("{e}")))?;
        let prover = ComplianceProver::with_policy(policy);
        let proof = prover
            .prove(&witness)
            .map_err(|e| ClientError::ProofGeneration(format!("{e}")))?;
        let binding = public_inputs
            .payload_amount_binding(amount)
            .map_err(|e| ClientError::InvalidPublicInputs(format!("{e}")))?;

        ComplianceProofBundle::new(&proof, public_inputs, &binding)
    }

    /// Generate a canonical `agent.authorization.v1` proof bundle from public inputs and a
    /// delegated-commerce receipt.
    pub fn prove_agent_authorization_bundle(
        &self,
        max_total: u64,
        receipt: &ves_stark_primitives::CommerceAuthorizationReceipt,
        public_inputs: &ves_stark_primitives::public_inputs::CompliancePublicInputs,
    ) -> Result<AgentAuthorizationProofBundle> {
        use ves_stark_prover::{ComplianceProver, ComplianceWitness};

        let policy =
            Policy::from_public_inputs(&public_inputs.policy_id, &public_inputs.policy_params)
                .map_err(|e| {
                    ClientError::InvalidPublicInputs(format!("invalid public inputs policy: {e}"))
                })?;

        if policy.policy_id() != "agent.authorization.v1" {
            return Err(ClientError::InvalidPublicInputs(format!(
                "Policy mismatch for authorization bundle: expected agent.authorization.v1, got {}",
                public_inputs.policy_id
            )));
        }
        if policy.limit() != max_total {
            return Err(ClientError::InvalidPublicInputs(format!(
                "Policy limit mismatch for policy {}: expected {}, got {}",
                public_inputs.policy_id,
                policy.limit(),
                max_total
            )));
        }

        public_inputs
            .validate_authorization_receipt(receipt)
            .map_err(|e| ClientError::InvalidPublicInputs(format!("{e}")))?;

        let witness = ComplianceWitness::try_new(receipt.amount, public_inputs.clone())
            .map_err(|e| ClientError::InvalidPublicInputs(format!("{e}")))?;
        let prover = ComplianceProver::with_policy(policy);
        let proof = prover
            .prove(&witness)
            .map_err(|e| ClientError::ProofGeneration(format!("{e}")))?;
        let binding = public_inputs
            .payload_amount_binding(receipt.amount)
            .map_err(|e| ClientError::InvalidPublicInputs(format!("{e}")))?;

        AgentAuthorizationProofBundle::new(&proof, public_inputs, &binding, receipt)
    }

    /// Generate and submit a proof for an event.
    pub async fn prove_and_submit(
        &self,
        event_id: Uuid,
        amount: u64,
        policy_limit: u64,
        public_inputs: &ves_stark_primitives::public_inputs::CompliancePublicInputs,
    ) -> Result<SubmitProofResponse> {
        if public_inputs.event_id != event_id {
            return Err(ClientError::InvalidPublicInputs(format!(
                "event_id mismatch: submission targets {}, but public inputs are for {}",
                event_id, public_inputs.event_id
            )));
        }
        let bundle = self.prove_compliance_bundle(amount, policy_limit, public_inputs)?;
        self.submit_compliance_bundle(&bundle).await
    }

    /// Generate and submit an `agent.authorization.v1` proof bundle for a delegated-commerce
    /// receipt.
    pub async fn prove_agent_authorization_and_submit(
        &self,
        max_total: u64,
        receipt: &ves_stark_primitives::CommerceAuthorizationReceipt,
        public_inputs: &ves_stark_primitives::public_inputs::CompliancePublicInputs,
    ) -> Result<SubmitProofResponse> {
        let bundle = self.prove_agent_authorization_bundle(max_total, receipt, public_inputs)?;
        self.submit_agent_authorization_bundle(&bundle).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ves_stark_primitives::public_inputs::{
        compute_policy_hash, CompliancePublicInputs, PolicyParams,
    };
    use ves_stark_primitives::{CommerceAuthorizationReceipt, CommerceExecution, CommerceIntent};

    #[test]
    fn test_client_creation() {
        let _client = SequencerClient::try_new("http://localhost:8080", "test_key").unwrap();
    }

    #[test]
    fn test_client_creation_rejects_invalid_base_url() {
        assert!(SequencerClient::new("", "test_key").is_err());
        assert!(SequencerClient::new("::::", "test_key").is_err());
    }

    #[test]
    fn test_client_creation_rejects_empty_api_key() {
        assert!(SequencerClient::new("http://localhost:8080", "").is_err());
        assert!(SequencerClient::new("http://localhost:8080", "   ").is_err());
    }

    #[cfg(feature = "dev")]
    #[test]
    fn test_unauthenticated_client() {
        let _client = SequencerClient::try_unauthenticated("http://localhost:8080").unwrap();
    }

    #[test]
    fn test_aml_threshold_params() {
        let params = AmlThresholdParams::new(10000);
        let json = params.to_json();
        assert_eq!(json["threshold"], 10000);
    }

    #[test]
    fn test_order_total_cap_params() {
        let params = OrderTotalCapParams::new(10000);
        let json = params.to_json();
        assert_eq!(json["cap"], 10000);
    }

    #[test]
    fn test_policy_params_for_limit_supports_cap() {
        let json = SequencerClient::policy_params_for_limit("order_total.cap", 10000).unwrap();
        assert_eq!(json["cap"], 10000);
    }

    #[test]
    fn test_policy_params_for_limit_rejects_unknown_policy() {
        assert!(SequencerClient::policy_params_for_limit("unknown.policy", 10000).is_err());
    }

    #[test]
    fn test_proof_submission() {
        let event_id = Uuid::new_v4();
        let submission =
            ProofSubmission::aml_threshold(event_id, 10000, vec![1, 2, 3, 4], [0, 0, 0, 0]);
        assert_eq!(submission.policy_id, "aml.threshold");
        assert_eq!(submission.event_id, event_id);
    }

    #[test]
    fn test_order_total_cap_proof_submission() {
        let event_id = Uuid::new_v4();
        let submission =
            ProofSubmission::order_total_cap(event_id, 10000, vec![1, 2, 3, 4], [0, 0, 0, 0]);
        assert_eq!(submission.policy_id, "order_total.cap");
        assert_eq!(submission.event_id, event_id);
    }

    #[test]
    fn test_prove_compliance_bundle_binds_amount_artifact() {
        let threshold = 10_000u64;
        let params = PolicyParams::threshold(threshold);
        let policy_hash = compute_policy_hash("aml.threshold", &params).unwrap();
        let inputs = CompliancePublicInputs {
            event_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            store_id: Uuid::new_v4(),
            sequence_number: 1,
            payload_kind: 1,
            payload_plain_hash: "a".repeat(64),
            payload_cipher_hash: "b".repeat(64),
            event_signing_hash: "c".repeat(64),
            policy_id: "aml.threshold".to_string(),
            policy_params: params,
            policy_hash: policy_hash.to_hex(),
            witness_commitment: None,
            authorization_receipt_hash: None,
            amount_binding_hash: None,
        };

        let client = SequencerClient::new("http://localhost:8080", "test_key").unwrap();
        let bundle = client
            .prove_compliance_bundle(5_000, threshold, &inputs)
            .unwrap();

        assert!(bundle.public_inputs.witness_commitment.is_some());
        assert!(bundle.public_inputs.amount_binding_hash.is_some());
        assert_eq!(bundle.amount_binding.amount, 5_000);
    }

    fn sample_authorization_receipt() -> CommerceAuthorizationReceipt {
        let intent = CommerceIntent {
            intent_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            store_id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            delegation_id: Uuid::new_v4(),
            currency: "USD".to_string(),
            max_total: 25_000,
            merchant: Some("Acme Market".to_string()),
            payee: Some("settlement@stateset.app".to_string()),
            allowed_skus: vec!["sku-a".to_string()],
            allowed_categories: vec!["produce".to_string()],
            shipping_country: Some("US".to_string()),
            expires_at: 1_900_000_000,
            nonce: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
        };
        let execution = CommerceExecution {
            event_id: Uuid::new_v4(),
            sequence_number: 7,
            currency: "USD".to_string(),
            amount: 5_000,
            merchant: "Acme Market".to_string(),
            payee: "settlement@stateset.app".to_string(),
            sku_ids: vec!["sku-a".to_string()],
            category_ids: vec!["produce".to_string()],
            shipping_country: Some("US".to_string()),
            executed_at: 1_800_000_000,
        };
        intent.authorize_execution(&execution).unwrap()
    }

    fn sample_authorization_inputs(
        max_total: u64,
        receipt: &CommerceAuthorizationReceipt,
    ) -> CompliancePublicInputs {
        let params = PolicyParams::agent_authorization(max_total, &receipt.intent_hash).unwrap();
        let policy_hash = compute_policy_hash("agent.authorization.v1", &params).unwrap();

        CompliancePublicInputs {
            event_id: receipt.event_id,
            tenant_id: receipt.tenant_id,
            store_id: receipt.store_id,
            sequence_number: receipt.sequence_number,
            payload_kind: 1,
            payload_plain_hash: "a".repeat(64),
            payload_cipher_hash: "b".repeat(64),
            event_signing_hash: "c".repeat(64),
            policy_id: "agent.authorization.v1".to_string(),
            policy_params: params,
            policy_hash: policy_hash.to_hex(),
            witness_commitment: None,
            authorization_receipt_hash: None,
            amount_binding_hash: None,
        }
    }

    #[test]
    fn test_prove_agent_authorization_bundle_binds_receipt_and_amount_artifact() {
        let receipt = sample_authorization_receipt();
        let inputs = sample_authorization_inputs(25_000, &receipt);
        let client = SequencerClient::new("http://localhost:8080", "test_key").unwrap();

        let bundle = client
            .prove_agent_authorization_bundle(25_000, &receipt, &inputs)
            .unwrap();

        assert!(bundle.public_inputs.witness_commitment.is_some());
        assert!(bundle.public_inputs.amount_binding_hash.is_some());
        assert_eq!(
            bundle.public_inputs.authorization_receipt_hash,
            Some(receipt.receipt_hash.clone())
        );
        assert_eq!(bundle.amount_binding.amount, receipt.amount);
    }
}
