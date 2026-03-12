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
            public_inputs: None, // Let the sequencer compute canonical inputs
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
    /// 3. Submits the proof to the sequencer
    pub async fn prove_and_submit(
        &self,
        event_id: Uuid,
        amount: u64,
        policy_limit: u64,
        public_inputs: &ves_stark_primitives::public_inputs::CompliancePublicInputs,
    ) -> Result<SubmitProofResponse> {
        use ves_stark_prover::{ComplianceProver, ComplianceWitness};

        if public_inputs.event_id != event_id {
            return Err(ClientError::InvalidPublicInputs(format!(
                "event_id mismatch: submission targets {}, but public inputs are for {}",
                event_id, public_inputs.event_id
            )));
        }

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

        // Create witness
        let witness = ComplianceWitness::new(amount, public_inputs.clone());
        let prover = ComplianceProver::with_policy(policy);

        // Generate proof
        let proof = prover
            .prove(&witness)
            .map_err(|e| ClientError::ProofGeneration(format!("{e}")))?;

        // Submit proof
        let submission = ProofSubmission {
            event_id,
            policy_id: public_inputs.policy_id.clone(),
            policy_params: public_inputs.policy_params.to_json_value(),
            proof_bytes: proof.proof_bytes,
            witness_commitment: proof.witness_commitment,
        };
        self.submit_proof(submission).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
