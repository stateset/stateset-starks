//! `ProofSubmission`: what a client sends to the sequencer, and its validation.

use super::*;

/// Proof submission helper
#[derive(Debug, Clone)]
pub struct ProofSubmission {
    /// VES event the proof attests to.
    pub event_id: Uuid,
    /// Policy identifier, e.g. `aml.threshold`.
    pub policy_id: String,
    /// Policy parameters as canonical JSON; the shape depends on `policy_id`.
    pub policy_params: serde_json::Value,
    /// Serialized STARK proof.
    pub proof_bytes: Vec<u8>,
    /// Rescue commitment to the salted witness, as four field elements.
    pub witness_commitment: [u64; 4],
    /// Canonical public inputs, when the sequencer stored them.
    pub public_inputs: Option<CompliancePublicInputs>,
}

impl ProofSubmission {
    /// Create a new proof submission for the aml.threshold policy
    pub fn aml_threshold(
        event_id: Uuid,
        threshold: u64,
        proof_bytes: Vec<u8>,
        witness_commitment: [u64; 4],
    ) -> Self {
        Self {
            event_id,
            policy_id: "aml.threshold".to_string(),
            policy_params: AmlThresholdParams::new(threshold).to_json(),
            proof_bytes,
            witness_commitment,
            public_inputs: None,
        }
    }

    /// Create a new proof submission for the order_total.cap policy
    pub fn order_total_cap(
        event_id: Uuid,
        cap: u64,
        proof_bytes: Vec<u8>,
        witness_commitment: [u64; 4],
    ) -> Self {
        Self {
            event_id,
            policy_id: "order_total.cap".to_string(),
            policy_params: OrderTotalCapParams::new(cap).to_json(),
            proof_bytes,
            witness_commitment,
            public_inputs: None,
        }
    }

    /// Create a new proof submission for the agent.authorization.v1 policy
    pub fn agent_authorization(
        event_id: Uuid,
        max_total: u64,
        intent_hash: &str,
        proof_bytes: Vec<u8>,
        witness_commitment: [u64; 4],
    ) -> Result<Self> {
        let params = AgentAuthorizationParams::new(max_total, intent_hash)?;
        Ok(Self {
            event_id,
            policy_id: "agent.authorization.v1".to_string(),
            policy_params: params.to_json(),
            proof_bytes,
            witness_commitment,
            public_inputs: None,
        })
    }

    /// Create a new proof submission for the agent.authorization.v1 policy from a receipt.
    pub fn agent_authorization_for_receipt(
        max_total: u64,
        receipt: &CommerceAuthorizationReceipt,
        proof_bytes: Vec<u8>,
        witness_commitment: [u64; 4],
    ) -> Result<Self> {
        let params = AgentAuthorizationParams::from_receipt(max_total, receipt)?;
        Ok(Self {
            event_id: receipt.event_id,
            policy_id: "agent.authorization.v1".to_string(),
            policy_params: params.to_json(),
            proof_bytes,
            witness_commitment,
            public_inputs: None,
        })
    }

    /// Attach canonical public inputs to the submission after validating they match.
    pub fn with_public_inputs(mut self, public_inputs: CompliancePublicInputs) -> Result<Self> {
        validate_submission_public_inputs(
            self.event_id,
            &self.policy_id,
            &self.policy_params,
            &self.witness_commitment,
            &public_inputs,
        )?;
        self.public_inputs = Some(public_inputs);
        Ok(self)
    }

    /// Attach canonical public inputs bound to an authorization receipt and its implied payload
    /// amount binding.
    pub fn with_bound_authorization_receipt(
        self,
        public_inputs: &CompliancePublicInputs,
        receipt: &CommerceAuthorizationReceipt,
    ) -> Result<Self> {
        let bound = public_inputs
            .bind_amount_and_authorization_receipt(receipt)
            .map_err(|e| ClientError::InvalidPublicInputs(format!("{e}")))?;
        self.with_public_inputs(bound)
    }

    /// Attach canonical public inputs bound to both the authorization receipt hash and the
    /// canonical payload amount binding implied by `receipt.amount`.
    pub fn with_amount_and_authorization_receipt(
        self,
        public_inputs: &CompliancePublicInputs,
        receipt: &CommerceAuthorizationReceipt,
    ) -> Result<Self> {
        self.with_bound_authorization_receipt(public_inputs, receipt)
    }

    /// Attach canonical public inputs bound to both a payload amount binding and an
    /// authorization receipt.
    pub fn with_payload_amount_binding_and_authorization_receipt(
        self,
        public_inputs: &CompliancePublicInputs,
        binding: &PayloadAmountBinding,
        receipt: &CommerceAuthorizationReceipt,
    ) -> Result<Self> {
        let bound = public_inputs
            .bind_payload_amount_binding_and_authorization_receipt(binding, receipt)
            .map_err(|e| ClientError::InvalidPublicInputs(format!("{e}")))?;
        self.with_public_inputs(bound)
    }

    /// Attach payload amount-bound canonical public inputs to the submission.
    pub fn with_payload_amount_binding(
        self,
        public_inputs: &CompliancePublicInputs,
        binding: &PayloadAmountBinding,
    ) -> Result<Self> {
        let bound = public_inputs
            .bind_payload_amount_binding(binding)
            .map_err(|e| ClientError::InvalidPublicInputs(format!("{e}")))?;
        self.with_public_inputs(bound)
    }

    /// Validate the submission before sending it over the wire.
    pub fn validate(&self) -> Result<()> {
        if let Some(public_inputs) = self.public_inputs.as_ref() {
            validate_submission_public_inputs(
                self.event_id,
                &self.policy_id,
                &self.policy_params,
                &self.witness_commitment,
                public_inputs,
            )?;
        }
        Ok(())
    }
}
