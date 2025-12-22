//! Sequencer HTTP client

use base64::Engine;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use uuid::Uuid;

use crate::error::{ClientError, Result};
use crate::types::*;

/// HTTP client for the StateSet sequencer
pub struct SequencerClient {
    client: reqwest::Client,
    base_url: String,
}

impl SequencerClient {
    /// Create a new sequencer client
    ///
    /// # Arguments
    ///
    /// * `base_url` - The base URL of the sequencer (e.g., "http://localhost:8080")
    /// * `api_key` - The API key for authentication
    pub fn new(base_url: &str, api_key: &str) -> Self {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", api_key)).unwrap(),
        );

        let client = reqwest::Client::builder()
            .default_headers(headers)
            .build()
            .expect("Failed to build HTTP client");

        Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }

    /// Create a client without authentication (for local development)
    pub fn unauthenticated(base_url: &str) -> Self {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        let client = reqwest::Client::builder()
            .default_headers(headers)
            .build()
            .expect("Failed to build HTTP client");

        Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }

    /// Get public inputs for an event with the specified policy
    pub async fn get_public_inputs(
        &self,
        event_id: Uuid,
        policy_id: &str,
        threshold: u64,
    ) -> Result<PublicInputsResponse> {
        let url = format!(
            "{}/api/v1/ves/compliance/{}/inputs",
            self.base_url, event_id
        );

        let request = PublicInputsRequest {
            policy_id: policy_id.to_string(),
            policy_params: AmlThresholdParams::new(threshold).to_json(),
        };

        let response = self.client.post(&url).json(&request).send().await?;

        let status = response.status();
        if status.is_success() {
            Ok(response.json().await?)
        } else if status.as_u16() == 404 {
            Err(ClientError::EventNotFound(event_id))
        } else if status.as_u16() == 401 || status.as_u16() == 403 {
            let body = response.text().await.unwrap_or_default();
            Err(ClientError::Unauthorized(body))
        } else {
            let body = response.text().await.unwrap_or_default();
            Err(ClientError::ApiError {
                status: status.as_u16(),
                message: body,
            })
        }
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
            proof_version: 1,
            policy_id: submission.policy_id,
            policy_params: submission.policy_params,
            proof_b64,
            public_inputs: None, // Let the sequencer compute canonical inputs
        };

        let response = self.client.post(&url).json(&request).send().await?;

        let status = response.status();
        if status.is_success() {
            Ok(response.json().await?)
        } else if status.as_u16() == 404 {
            Err(ClientError::EventNotFound(submission.event_id))
        } else if status.as_u16() == 401 || status.as_u16() == 403 {
            let body = response.text().await.unwrap_or_default();
            Err(ClientError::Unauthorized(body))
        } else if status.as_u16() == 409 {
            let body = response.text().await.unwrap_or_default();
            Err(ClientError::ApiError {
                status: 409,
                message: format!("Proof conflict: {}", body),
            })
        } else {
            let body = response.text().await.unwrap_or_default();
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
            let body = response.text().await.unwrap_or_default();
            Err(ClientError::ApiError {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    /// Get a specific proof by ID
    pub async fn get_proof(&self, proof_id: Uuid) -> Result<ProofDetails> {
        let url = format!("{}/api/v1/ves/compliance/proofs/{}", self.base_url, proof_id);

        let response = self.client.get(&url).send().await?;

        let status = response.status();
        if status.is_success() {
            Ok(response.json().await?)
        } else if status.as_u16() == 404 {
            Err(ClientError::ProofNotFound(proof_id))
        } else {
            let body = response.text().await.unwrap_or_default();
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
            let body = response.text().await.unwrap_or_default();
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
        threshold: u64,
        public_inputs: &ves_stark_primitives::public_inputs::CompliancePublicInputs,
    ) -> Result<SubmitProofResponse> {
        use ves_stark_air::policies::aml_threshold::AmlThresholdPolicy;
        use ves_stark_prover::{ComplianceProver, ComplianceWitness};

        // Create witness
        let witness = ComplianceWitness::new(amount, public_inputs.clone());

        // Create prover
        let policy = AmlThresholdPolicy::new(threshold);
        let prover = ComplianceProver::new(policy);

        // Generate proof
        let proof = prover
            .prove(&witness)
            .map_err(|e| ClientError::ProofGeneration(format!("{:?}", e)))?;

        // Submit proof
        let submission = ProofSubmission::aml_threshold(event_id, threshold, proof.proof_bytes);
        self.submit_proof(submission).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let _client = SequencerClient::new("http://localhost:8080", "test_key");
    }

    #[test]
    fn test_unauthenticated_client() {
        let _client = SequencerClient::unauthenticated("http://localhost:8080");
    }

    #[test]
    fn test_aml_threshold_params() {
        let params = AmlThresholdParams::new(10000);
        let json = params.to_json();
        assert_eq!(json["threshold"], 10000);
    }

    #[test]
    fn test_proof_submission() {
        let event_id = Uuid::new_v4();
        let submission = ProofSubmission::aml_threshold(event_id, 10000, vec![1, 2, 3, 4]);
        assert_eq!(submission.policy_id, "aml.threshold");
        assert_eq!(submission.event_id, event_id);
    }
}
