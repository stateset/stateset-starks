//! Proof bundles: self-describing, hash-bound envelopes for a proof plus its inputs.

use super::*;

/// Version of the canonical compliance proof bundle format.
pub const COMPLIANCE_PROOF_BUNDLE_VERSION: u32 = 1;
/// Domain separator for canonical compliance bundle hashing.
pub const DOMAIN_COMPLIANCE_PROOF_BUNDLE_HASH: &[u8] =
    b"STATESET_VES_COMPLIANCE_PROOF_BUNDLE_HASH_V1";

/// Canonical transport artifact for a payload-bound compliance proof.
///
/// This bundles proof bytes, proof metadata, payload amount-bound public inputs, and the canonical
/// payload amount binding into a single locally verifiable artifact for any supported policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceProofBundle {
    /// Bundle format version.
    pub version: u32,
    /// Proof system type.
    pub proof_type: String,
    /// Wire-format proof version.
    pub proof_version: u32,
    /// Base64-encoded proof bytes.
    pub proof_b64: String,
    /// Domain-separated proof hash.
    pub proof_hash: String,
    /// Proof metadata captured at proving time.
    pub metadata: ProofMetadata,
    /// Witness commitment binding the private amount to the proof.
    pub witness_commitment: [u64; 4],
    /// Hex form of the witness commitment for JSON-safe transport.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// The same commitment, hex-encoded. Prefer this form on JSON APIs:
    /// JavaScript numbers cannot represent a `u64` exactly.
    pub witness_commitment_hex: Option<String>,
    /// Canonical amount-bound public inputs.
    pub public_inputs: CompliancePublicInputs,
    /// Canonical sequencer public-input hash for `public_inputs`.
    pub public_inputs_hash: String,
    /// Full local public-input hash for `public_inputs`, including `witnessCommitment`.
    pub bound_public_inputs_hash: String,
    /// Canonical payload-derived amount binding.
    pub amount_binding: PayloadAmountBinding,
    /// Domain-separated canonical bundle hash.
    pub bundle_hash: String,
}

impl ComplianceProofBundle {
    /// Create a canonical compliance proof bundle from a generated proof, public inputs, and a
    /// canonical payload amount binding.
    pub fn new(
        proof: &ComplianceProof,
        public_inputs: &CompliancePublicInputs,
        amount_binding: &PayloadAmountBinding,
    ) -> Result<Self> {
        validate_bundle_proof_artifact(
            &proof.proof_bytes,
            &proof.proof_hash,
            &proof.metadata,
            &proof.witness_commitment,
            proof.witness_commitment_hex.as_deref(),
        )?;

        let normalized_binding = amount_binding
            .normalized()
            .map_err(|e| ClientError::InvalidProofBundle(format!("invalid amount binding: {e}")))?;
        normalized_binding
            .validate()
            .map_err(|e| ClientError::InvalidProofBundle(format!("invalid amount binding: {e}")))?;

        let bound_public_inputs = public_inputs
            .bind_payload_amount_binding(&normalized_binding)
            .map_err(|e| ClientError::InvalidProofBundle(format!("{e}")))?;
        let public_inputs_hash = bound_public_inputs
            .compute_hash()
            .map_err(|e| ClientError::InvalidProofBundle(format!("{e}")))?
            .to_hex();
        let bound_public_inputs_hash = bound_public_inputs
            .compute_bound_hash()
            .map_err(|e| ClientError::InvalidProofBundle(format!("{e}")))?
            .to_hex();

        let mut bundle = Self {
            version: COMPLIANCE_PROOF_BUNDLE_VERSION,
            proof_type: "stark".to_string(),
            proof_version: ves_stark_verifier::PROOF_VERSION,
            proof_b64: base64::engine::general_purpose::STANDARD.encode(&proof.proof_bytes),
            proof_hash: proof.proof_hash.clone(),
            metadata: proof.metadata.clone(),
            witness_commitment: proof.witness_commitment,
            witness_commitment_hex: Some(witness_commitment_u64_to_hex(&proof.witness_commitment)),
            public_inputs: bound_public_inputs,
            public_inputs_hash,
            bound_public_inputs_hash,
            amount_binding: normalized_binding,
            bundle_hash: String::new(),
        };
        bundle.bundle_hash = bundle.compute_hash_hex()?;
        bundle.validate()?;
        Ok(bundle)
    }

    /// Decode the raw proof bytes from the bundle.
    pub fn proof_bytes(&self) -> Result<Vec<u8>> {
        base64::engine::general_purpose::STANDARD
            .decode(&self.proof_b64)
            .map_err(|e| ClientError::InvalidProofBundle(format!("invalid proof_b64: {e}")))
    }

    /// Canonical JSON representation of the bundle payload excluding `bundle_hash`.
    pub fn canonical_json(&self) -> Result<String> {
        canonical_json(&serde_json::json!({
            "amountBinding": self.amount_binding,
            "metadata": self.metadata,
            "proofB64": self.proof_b64,
            "proofHash": self.proof_hash,
            "proofType": self.proof_type,
            "proofVersion": self.proof_version,
            "publicInputs": self.public_inputs,
            "publicInputsHash": self.public_inputs_hash,
            "boundPublicInputsHash": self.bound_public_inputs_hash,
            "version": self.version,
            "witnessCommitment": self.witness_commitment,
            "witnessCommitmentHex": self.witness_commitment_hex,
        }))
        .map_err(|e| ClientError::InvalidProofBundle(format!("failed to canonicalize bundle: {e}")))
    }

    /// Domain-separated canonical bundle hash.
    pub fn compute_hash(&self) -> Result<Hash256> {
        let canonical = self.canonical_json()?;
        Ok(Hash256::sha256_with_domain(
            DOMAIN_COMPLIANCE_PROOF_BUNDLE_HASH,
            canonical.as_bytes(),
        ))
    }

    /// Domain-separated canonical bundle hash as lowercase hex.
    pub fn compute_hash_hex(&self) -> Result<String> {
        Ok(self.compute_hash()?.to_hex())
    }

    /// Validate the bundle invariants without running STARK verification.
    pub fn validate(&self) -> Result<()> {
        if self.version != COMPLIANCE_PROOF_BUNDLE_VERSION {
            return Err(ClientError::InvalidProofBundle(format!(
                "unsupported bundle version {}",
                self.version
            )));
        }
        if self.proof_type != "stark" {
            return Err(ClientError::InvalidProofBundle(format!(
                "unsupported proof type {}",
                self.proof_type
            )));
        }
        if self.proof_version == 0 {
            return Err(ClientError::InvalidProofBundle(
                "proof_version must be greater than zero".to_string(),
            ));
        }

        let proof_bytes = self.proof_bytes()?;
        validate_bundle_proof_artifact(
            &proof_bytes,
            &self.proof_hash,
            &self.metadata,
            &self.witness_commitment,
            self.witness_commitment_hex.as_deref(),
        )?;

        let normalized_binding = self
            .amount_binding
            .normalized()
            .map_err(|e| ClientError::InvalidProofBundle(format!("invalid amount binding: {e}")))?;
        normalized_binding
            .validate()
            .map_err(|e| ClientError::InvalidProofBundle(format!("invalid amount binding: {e}")))?;

        self.public_inputs
            .to_field_elements()
            .map_err(|e| ClientError::InvalidProofBundle(format!("{e}")))?;

        let policy_hash_valid = self
            .public_inputs
            .validate_policy_hash()
            .map_err(|e| ClientError::InvalidProofBundle(format!("{e}")))?;
        if !policy_hash_valid {
            return Err(ClientError::InvalidProofBundle(
                "public_inputs policyHash does not match canonical policy params".to_string(),
            ));
        }

        let bound_commitment = self
            .public_inputs
            .witness_commitment_u64()
            .map_err(|e| ClientError::InvalidProofBundle(format!("{e}")))?
            .ok_or_else(|| {
                ClientError::InvalidProofBundle(
                    "public_inputs is missing witnessCommitment".to_string(),
                )
            })?;
        if bound_commitment != self.witness_commitment {
            return Err(ClientError::InvalidProofBundle(
                "public_inputs witnessCommitment does not match bundle witness commitment"
                    .to_string(),
            ));
        }

        let amount_binding_hash = self
            .public_inputs
            .amount_binding_hash
            .as_deref()
            .ok_or_else(|| {
                ClientError::InvalidProofBundle(
                    "public_inputs is missing amountBindingHash".to_string(),
                )
            })?;
        if amount_binding_hash != normalized_binding.binding_hash {
            return Err(ClientError::InvalidProofBundle(
                "public_inputs amountBindingHash does not match amount binding".to_string(),
            ));
        }

        self.public_inputs
            .validate_payload_amount_binding(&normalized_binding)
            .map_err(|e| ClientError::InvalidProofBundle(format!("{e}")))?;

        let expected_public_inputs_hash = self
            .public_inputs
            .compute_hash()
            .map_err(|e| ClientError::InvalidProofBundle(format!("{e}")))?
            .to_hex();
        if self.public_inputs_hash != expected_public_inputs_hash {
            return Err(ClientError::InvalidProofBundle(format!(
                "public_inputs_hash mismatch: expected {}, got {}",
                expected_public_inputs_hash, self.public_inputs_hash
            )));
        }
        let expected_bound_public_inputs_hash = self
            .public_inputs
            .compute_bound_hash()
            .map_err(|e| ClientError::InvalidProofBundle(format!("{e}")))?
            .to_hex();
        if self.bound_public_inputs_hash != expected_bound_public_inputs_hash {
            return Err(ClientError::InvalidProofBundle(format!(
                "bound_public_inputs_hash mismatch: expected {}, got {}",
                expected_bound_public_inputs_hash, self.bound_public_inputs_hash
            )));
        }

        let expected_bundle_hash = self.compute_hash_hex()?;
        if self.bundle_hash != expected_bundle_hash {
            return Err(ClientError::InvalidProofBundle(format!(
                "bundle_hash mismatch: expected {}, got {}",
                expected_bundle_hash, self.bundle_hash
            )));
        }

        Ok(())
    }

    /// Serialize the bundle to JSON after validating it.
    pub fn to_json(&self) -> Result<String> {
        self.validate()?;
        serde_json::to_string_pretty(self).map_err(Into::into)
    }

    /// Deserialize and validate a bundle from JSON.
    pub fn from_json(json: &str) -> Result<Self> {
        let bundle: Self = serde_json::from_str(json)?;
        bundle.validate()?;
        Ok(bundle)
    }

    /// Serialize the bundle to JSON bytes after validating it.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        serde_json::to_vec(self).map_err(Into::into)
    }

    /// Deserialize and validate a bundle from JSON bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let bundle: Self = serde_json::from_slice(bytes)?;
        bundle.validate()?;
        Ok(bundle)
    }

    /// Convert this bundle back into a submit-ready proof submission.
    pub fn to_submission(&self) -> Result<ProofSubmission> {
        self.validate()?;

        let submission = ProofSubmission {
            event_id: self.public_inputs.event_id,
            policy_id: self.public_inputs.policy_id.clone(),
            policy_params: self.public_inputs.policy_params.to_json_value(),
            proof_bytes: self.proof_bytes()?,
            witness_commitment: self.witness_commitment,
            public_inputs: Some(self.public_inputs.clone()),
        };
        submission.validate()?;
        Ok(submission)
    }

    /// Run local STARK verification using the bound public inputs.
    pub fn verify(&self) -> Result<VerificationResult> {
        self.validate()?;
        let proof_bytes = self.proof_bytes()?;
        ves_stark_verifier::verify_compliance_proof_auto_with_amount_binding(
            &proof_bytes,
            &self.public_inputs,
            &self.amount_binding,
        )
        .map_err(|e| ClientError::InvalidProofBundle(format!("bundle verification failed: {e}")))
    }

    /// Run strict local STARK verification and return an error for invalid proofs.
    pub fn verify_strict(&self) -> Result<VerificationResult> {
        self.validate()?;
        let proof_bytes = self.proof_bytes()?;
        ves_stark_verifier::verify_compliance_proof_auto_with_amount_binding_strict(
            &proof_bytes,
            &self.public_inputs,
            &self.amount_binding,
        )
        .map_err(|e| ClientError::InvalidProofBundle(format!("bundle verification failed: {e}")))
    }

    /// Validate that a submit response still matches this canonical bundle.
    pub fn validate_submit_response(&self, response: &SubmitProofResponse) -> Result<()> {
        self.validate()?;
        response.validate()?;
        validate_compliance_bundle_response_common(
            "submit proof response",
            self,
            response.event_id,
            response.tenant_id,
            response.store_id,
            &response.proof_type,
            response.proof_version,
            &response.policy_id,
            &response.policy_params,
            &response.policy_hash,
            &response.proof_hash,
            response.witness_commitment,
            response.witness_commitment_hex.as_deref(),
        )?;

        if let Some(public_inputs) = response.validate_and_parse_public_inputs()? {
            validate_public_inputs_equal(
                &self.public_inputs,
                &public_inputs,
                "submit proof response",
            )?;
        }

        Ok(())
    }

    /// Validate that fetched proof details still match this canonical bundle.
    pub fn validate_proof_details(&self, details: &ProofDetails) -> Result<()> {
        self.validate()?;
        details.validate()?;
        validate_compliance_bundle_response_common(
            "proof details",
            self,
            details.event_id,
            details.tenant_id,
            details.store_id,
            &details.proof_type,
            details.proof_version,
            &details.policy_id,
            &details.policy_params,
            &details.policy_hash,
            &details.proof_hash,
            details.witness_commitment,
            details.witness_commitment_hex.as_deref(),
        )?;

        if details.proof_bytes()? != self.proof_bytes()? {
            return Err(ClientError::InvalidProofBundle(
                "proof details proof bytes do not match bundle proof bytes".to_string(),
            ));
        }

        if let Some(public_inputs) = details.validate_and_parse_public_inputs()? {
            validate_public_inputs_equal(&self.public_inputs, &public_inputs, "proof details")?;
        }

        Ok(())
    }

    /// Validate that a sequencer verification response still matches this canonical bundle.
    pub fn validate_verify_response(&self, response: &VerifyResponse) -> Result<()> {
        self.validate()?;
        let witness_commitment = normalized_optional_witness_commitment(
            response.witness_commitment,
            response.witness_commitment_hex.as_deref(),
            "verify response",
        )?;

        if response.event_id != self.public_inputs.event_id {
            return Err(ClientError::InvalidProofBundle(format!(
                "verify response event_id mismatch: expected {}, got {}",
                self.public_inputs.event_id, response.event_id
            )));
        }
        if response.tenant_id != self.public_inputs.tenant_id {
            return Err(ClientError::InvalidProofBundle(format!(
                "verify response tenant_id mismatch: expected {}, got {}",
                self.public_inputs.tenant_id, response.tenant_id
            )));
        }
        if response.store_id != self.public_inputs.store_id {
            return Err(ClientError::InvalidProofBundle(format!(
                "verify response store_id mismatch: expected {}, got {}",
                self.public_inputs.store_id, response.store_id
            )));
        }
        if response.proof_type != self.proof_type {
            return Err(ClientError::InvalidProofBundle(format!(
                "verify response proof_type mismatch: expected {}, got {}",
                self.proof_type, response.proof_type
            )));
        }
        if response.proof_version != self.proof_version {
            return Err(ClientError::InvalidProofBundle(format!(
                "verify response proof_version mismatch: expected {}, got {}",
                self.proof_version, response.proof_version
            )));
        }
        if response.policy_id != self.public_inputs.policy_id {
            return Err(ClientError::InvalidProofBundle(format!(
                "verify response policy_id mismatch: expected {}, got {}",
                self.public_inputs.policy_id, response.policy_id
            )));
        }
        if response.policy_hash != self.public_inputs.policy_hash {
            return Err(ClientError::InvalidProofBundle(format!(
                "verify response policy_hash mismatch: expected {}, got {}",
                self.public_inputs.policy_hash, response.policy_hash
            )));
        }
        if response.proof_hash != self.proof_hash {
            return Err(ClientError::InvalidProofBundle(format!(
                "verify response proof_hash mismatch: expected {}, got {}",
                self.proof_hash, response.proof_hash
            )));
        }
        if response.canonical_public_inputs_hash != self.public_inputs_hash {
            return Err(ClientError::InvalidProofBundle(format!(
                "verify response canonical_public_inputs_hash mismatch: expected {}, got {}",
                self.public_inputs_hash, response.canonical_public_inputs_hash
            )));
        }
        if let Some(public_inputs_hash) = response.public_inputs_hash.as_deref() {
            if public_inputs_hash != self.public_inputs_hash {
                return Err(ClientError::InvalidProofBundle(format!(
                    "verify response public_inputs_hash mismatch: expected {}, got {}",
                    self.public_inputs_hash, public_inputs_hash
                )));
            }
        }
        if !response.public_inputs_match {
            return Err(ClientError::InvalidProofBundle(
                "verify response reports public_inputs_match = false".to_string(),
            ));
        }
        if let Some(witness_commitment) = witness_commitment {
            if witness_commitment != self.witness_commitment {
                return Err(ClientError::InvalidProofBundle(
                    "verify response witness commitment does not match bundle".to_string(),
                ));
            }
        }
        if response.stark_valid == Some(false) {
            return Err(ClientError::InvalidProofBundle(
                response
                    .stark_error
                    .clone()
                    .unwrap_or_else(|| "verify response reports stark_valid = false".to_string()),
            ));
        }
        if !response.valid {
            return Err(ClientError::InvalidProofBundle(
                response
                    .reason
                    .clone()
                    .unwrap_or_else(|| "verify response reports valid = false".to_string()),
            ));
        }

        Ok(())
    }
}

/// Version of the canonical agent authorization proof bundle format.
pub const AGENT_AUTHORIZATION_PROOF_BUNDLE_VERSION: u32 = 2;
/// Domain separator for canonical bundle hashing.
pub const DOMAIN_AGENT_AUTHORIZATION_PROOF_BUNDLE_HASH: &[u8] =
    b"STATESET_VES_AGENT_AUTHORIZATION_PROOF_BUNDLE_HASH_V1";

/// Canonical transport artifact for an `agent.authorization.v1` proof.
///
/// This bundles proof bytes, proof metadata, payload amount and receipt-bound public inputs,
/// the canonical payload-derived amount binding, and the delegated commerce receipt into a
/// single locally verifiable artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentAuthorizationProofBundle {
    /// Bundle format version.
    pub version: u32,
    /// Proof system type.
    pub proof_type: String,
    /// Wire-format proof version.
    pub proof_version: u32,
    /// Base64-encoded proof bytes.
    pub proof_b64: String,
    /// Domain-separated proof hash.
    pub proof_hash: String,
    /// Proof metadata captured at proving time.
    pub metadata: ProofMetadata,
    /// Witness commitment binding the private amount to the proof.
    pub witness_commitment: [u64; 4],
    /// Hex form of the witness commitment for JSON-safe transport.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// The same commitment, hex-encoded. Prefer this form on JSON APIs:
    /// JavaScript numbers cannot represent a `u64` exactly.
    pub witness_commitment_hex: Option<String>,
    /// Canonical payload amount and receipt-bound public inputs.
    pub public_inputs: CompliancePublicInputs,
    /// Canonical sequencer public-input hash for `public_inputs`.
    pub public_inputs_hash: String,
    /// Full local public-input hash for `public_inputs`, including `witnessCommitment`.
    pub bound_public_inputs_hash: String,
    /// Canonical payload-derived amount binding.
    pub amount_binding: PayloadAmountBinding,
    /// Canonical authorization receipt bound to the proof.
    pub receipt: CommerceAuthorizationReceipt,
    /// Domain-separated canonical bundle hash.
    pub bundle_hash: String,
}

impl AgentAuthorizationProofBundle {
    /// Create a canonical authorization proof bundle from a generated proof, public inputs,
    /// payload amount binding, and delegated execution receipt.
    pub fn new(
        proof: &ComplianceProof,
        public_inputs: &CompliancePublicInputs,
        amount_binding: &PayloadAmountBinding,
        receipt: &CommerceAuthorizationReceipt,
    ) -> Result<Self> {
        validate_bundle_proof_artifact(
            &proof.proof_bytes,
            &proof.proof_hash,
            &proof.metadata,
            &proof.witness_commitment,
            proof.witness_commitment_hex.as_deref(),
        )?;

        let normalized_receipt = receipt
            .normalized()
            .map_err(|e| ClientError::InvalidProofBundle(format!("invalid receipt: {e}")))?;
        normalized_receipt
            .validate()
            .map_err(|e| ClientError::InvalidProofBundle(format!("invalid receipt: {e}")))?;
        let normalized_binding = amount_binding
            .normalized()
            .map_err(|e| ClientError::InvalidProofBundle(format!("invalid amount binding: {e}")))?;
        normalized_binding
            .validate()
            .map_err(|e| ClientError::InvalidProofBundle(format!("invalid amount binding: {e}")))?;

        let bound_public_inputs = public_inputs
            .bind_payload_amount_binding_and_authorization_receipt(
                &normalized_binding,
                &normalized_receipt,
            )
            .map_err(|e| ClientError::InvalidProofBundle(format!("{e}")))?;
        let public_inputs_hash = bound_public_inputs
            .compute_hash()
            .map_err(|e| ClientError::InvalidProofBundle(format!("{e}")))?
            .to_hex();
        let bound_public_inputs_hash = bound_public_inputs
            .compute_bound_hash()
            .map_err(|e| ClientError::InvalidProofBundle(format!("{e}")))?
            .to_hex();

        let mut bundle = Self {
            version: AGENT_AUTHORIZATION_PROOF_BUNDLE_VERSION,
            proof_type: "stark".to_string(),
            proof_version: ves_stark_verifier::PROOF_VERSION,
            proof_b64: base64::engine::general_purpose::STANDARD.encode(&proof.proof_bytes),
            proof_hash: proof.proof_hash.clone(),
            metadata: proof.metadata.clone(),
            witness_commitment: proof.witness_commitment,
            witness_commitment_hex: Some(witness_commitment_u64_to_hex(&proof.witness_commitment)),
            public_inputs: bound_public_inputs,
            public_inputs_hash,
            bound_public_inputs_hash,
            amount_binding: normalized_binding,
            receipt: normalized_receipt,
            bundle_hash: String::new(),
        };
        bundle.bundle_hash = bundle.compute_hash_hex()?;
        bundle.validate()?;
        Ok(bundle)
    }

    /// Decode the raw proof bytes from the bundle.
    pub fn proof_bytes(&self) -> Result<Vec<u8>> {
        base64::engine::general_purpose::STANDARD
            .decode(&self.proof_b64)
            .map_err(|e| ClientError::InvalidProofBundle(format!("invalid proof_b64: {e}")))
    }

    /// Canonical JSON representation of the bundle payload excluding `bundle_hash`.
    pub fn canonical_json(&self) -> Result<String> {
        canonical_json(&serde_json::json!({
            "amountBinding": self.amount_binding,
            "metadata": self.metadata,
            "proofB64": self.proof_b64,
            "proofHash": self.proof_hash,
            "proofType": self.proof_type,
            "proofVersion": self.proof_version,
            "publicInputs": self.public_inputs,
            "publicInputsHash": self.public_inputs_hash,
            "boundPublicInputsHash": self.bound_public_inputs_hash,
            "receipt": self.receipt,
            "version": self.version,
            "witnessCommitment": self.witness_commitment,
            "witnessCommitmentHex": self.witness_commitment_hex,
        }))
        .map_err(|e| ClientError::InvalidProofBundle(format!("failed to canonicalize bundle: {e}")))
    }

    /// Domain-separated canonical bundle hash.
    pub fn compute_hash(&self) -> Result<Hash256> {
        let canonical = self.canonical_json()?;
        Ok(Hash256::sha256_with_domain(
            DOMAIN_AGENT_AUTHORIZATION_PROOF_BUNDLE_HASH,
            canonical.as_bytes(),
        ))
    }

    /// Domain-separated canonical bundle hash as lowercase hex.
    pub fn compute_hash_hex(&self) -> Result<String> {
        Ok(self.compute_hash()?.to_hex())
    }

    /// Validate the bundle invariants without running STARK verification.
    pub fn validate(&self) -> Result<()> {
        if self.version != AGENT_AUTHORIZATION_PROOF_BUNDLE_VERSION {
            return Err(ClientError::InvalidProofBundle(format!(
                "unsupported bundle version {}",
                self.version
            )));
        }
        if self.proof_type != "stark" {
            return Err(ClientError::InvalidProofBundle(format!(
                "unsupported proof type {}",
                self.proof_type
            )));
        }
        if self.proof_version == 0 {
            return Err(ClientError::InvalidProofBundle(
                "proof_version must be greater than zero".to_string(),
            ));
        }

        let proof_bytes = self.proof_bytes()?;
        validate_bundle_proof_artifact(
            &proof_bytes,
            &self.proof_hash,
            &self.metadata,
            &self.witness_commitment,
            self.witness_commitment_hex.as_deref(),
        )?;

        let normalized_receipt = self
            .receipt
            .normalized()
            .map_err(|e| ClientError::InvalidProofBundle(format!("invalid receipt: {e}")))?;
        normalized_receipt
            .validate()
            .map_err(|e| ClientError::InvalidProofBundle(format!("invalid receipt: {e}")))?;
        let normalized_binding = self
            .amount_binding
            .normalized()
            .map_err(|e| ClientError::InvalidProofBundle(format!("invalid amount binding: {e}")))?;
        normalized_binding
            .validate()
            .map_err(|e| ClientError::InvalidProofBundle(format!("invalid amount binding: {e}")))?;

        self.public_inputs
            .to_field_elements()
            .map_err(|e| ClientError::InvalidProofBundle(format!("{e}")))?;

        let policy_hash_valid = self
            .public_inputs
            .validate_policy_hash()
            .map_err(|e| ClientError::InvalidProofBundle(format!("{e}")))?;
        if !policy_hash_valid {
            return Err(ClientError::InvalidProofBundle(
                "public_inputs policyHash does not match canonical policy params".to_string(),
            ));
        }

        let bound_commitment = self
            .public_inputs
            .witness_commitment_u64()
            .map_err(|e| ClientError::InvalidProofBundle(format!("{e}")))?
            .ok_or_else(|| {
                ClientError::InvalidProofBundle(
                    "public_inputs is missing witnessCommitment".to_string(),
                )
            })?;
        if bound_commitment != self.witness_commitment {
            return Err(ClientError::InvalidProofBundle(
                "public_inputs witnessCommitment does not match bundle witness commitment"
                    .to_string(),
            ));
        }

        let receipt_hash = self
            .public_inputs
            .authorization_receipt_hash
            .as_deref()
            .ok_or_else(|| {
                ClientError::InvalidProofBundle(
                    "public_inputs is missing authorizationReceiptHash".to_string(),
                )
            })?;
        if receipt_hash != normalized_receipt.receipt_hash {
            return Err(ClientError::InvalidProofBundle(
                "public_inputs authorizationReceiptHash does not match receipt".to_string(),
            ));
        }

        let amount_binding_hash = self
            .public_inputs
            .amount_binding_hash
            .as_deref()
            .ok_or_else(|| {
                ClientError::InvalidProofBundle(
                    "public_inputs is missing amountBindingHash".to_string(),
                )
            })?;
        if amount_binding_hash != normalized_binding.binding_hash {
            return Err(ClientError::InvalidProofBundle(
                "public_inputs amountBindingHash does not match amount binding".to_string(),
            ));
        }

        self.public_inputs
            .validate_payload_amount_binding_and_authorization_receipt(
                &normalized_binding,
                &normalized_receipt,
            )
            .map_err(|e| ClientError::InvalidProofBundle(format!("{e}")))?;

        let expected_public_inputs_hash = self
            .public_inputs
            .compute_hash()
            .map_err(|e| ClientError::InvalidProofBundle(format!("{e}")))?
            .to_hex();
        if self.public_inputs_hash != expected_public_inputs_hash {
            return Err(ClientError::InvalidProofBundle(format!(
                "public_inputs_hash mismatch: expected {}, got {}",
                expected_public_inputs_hash, self.public_inputs_hash
            )));
        }
        let expected_bound_public_inputs_hash = self
            .public_inputs
            .compute_bound_hash()
            .map_err(|e| ClientError::InvalidProofBundle(format!("{e}")))?
            .to_hex();
        if self.bound_public_inputs_hash != expected_bound_public_inputs_hash {
            return Err(ClientError::InvalidProofBundle(format!(
                "bound_public_inputs_hash mismatch: expected {}, got {}",
                expected_bound_public_inputs_hash, self.bound_public_inputs_hash
            )));
        }

        let expected_bundle_hash = self.compute_hash_hex()?;
        if self.bundle_hash != expected_bundle_hash {
            return Err(ClientError::InvalidProofBundle(format!(
                "bundle_hash mismatch: expected {}, got {}",
                expected_bundle_hash, self.bundle_hash
            )));
        }

        Ok(())
    }

    /// Serialize the bundle to JSON after validating it.
    pub fn to_json(&self) -> Result<String> {
        self.validate()?;
        serde_json::to_string_pretty(self).map_err(Into::into)
    }

    /// Deserialize and validate a bundle from JSON.
    pub fn from_json(json: &str) -> Result<Self> {
        let bundle: Self = serde_json::from_str(json)?;
        bundle.validate()?;
        Ok(bundle)
    }

    /// Serialize the bundle to JSON bytes after validating it.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        serde_json::to_vec(self).map_err(Into::into)
    }

    /// Deserialize and validate a bundle from JSON bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let bundle: Self = serde_json::from_slice(bytes)?;
        bundle.validate()?;
        Ok(bundle)
    }

    /// Convert this bundle back into a submit-ready proof submission.
    pub fn to_submission(&self) -> Result<ProofSubmission> {
        self.validate()?;

        let max_total = self
            .public_inputs
            .policy_params
            .get_max_total()
            .ok_or_else(|| {
                ClientError::InvalidProofBundle(
                    "missing maxTotal in agent authorization policy params".to_string(),
                )
            })?;

        ProofSubmission::agent_authorization_for_receipt(
            max_total,
            &self.receipt,
            self.proof_bytes()?,
            self.witness_commitment,
        )?
        .with_public_inputs(self.public_inputs.clone())
    }

    /// Run local STARK verification using the bound public inputs and receipt.
    pub fn verify(&self) -> Result<VerificationResult> {
        self.validate()?;
        let proof_bytes = self.proof_bytes()?;
        ves_stark_verifier::verify_agent_authorization_proof_auto_with_amount_binding(
            &proof_bytes,
            &self.public_inputs,
            &self.amount_binding,
            &self.receipt,
        )
        .map_err(|e| ClientError::InvalidProofBundle(format!("bundle verification failed: {e}")))
    }

    /// Run strict local STARK verification and return an error for invalid proofs.
    pub fn verify_strict(&self) -> Result<VerificationResult> {
        self.validate()?;
        let proof_bytes = self.proof_bytes()?;
        ves_stark_verifier::verify_agent_authorization_proof_auto_with_amount_binding_strict(
            &proof_bytes,
            &self.public_inputs,
            &self.amount_binding,
            &self.receipt,
        )
        .map_err(|e| ClientError::InvalidProofBundle(format!("bundle verification failed: {e}")))
    }

    /// Validate that a submit response still matches this canonical bundle.
    pub fn validate_submit_response(&self, response: &SubmitProofResponse) -> Result<()> {
        self.validate()?;
        response.validate()?;
        validate_bundle_response_common(
            "submit proof response",
            self,
            response.event_id,
            response.tenant_id,
            response.store_id,
            &response.proof_type,
            response.proof_version,
            &response.policy_id,
            &response.policy_params,
            &response.policy_hash,
            &response.proof_hash,
            response.witness_commitment,
            response.witness_commitment_hex.as_deref(),
        )?;

        if let Some(public_inputs) = response.validate_and_parse_public_inputs()? {
            validate_public_inputs_equal(
                &self.public_inputs,
                &public_inputs,
                "submit proof response",
            )?;
        }

        Ok(())
    }

    /// Validate that fetched proof details still match this canonical bundle.
    pub fn validate_proof_details(&self, details: &ProofDetails) -> Result<()> {
        self.validate()?;
        details.validate()?;
        validate_bundle_response_common(
            "proof details",
            self,
            details.event_id,
            details.tenant_id,
            details.store_id,
            &details.proof_type,
            details.proof_version,
            &details.policy_id,
            &details.policy_params,
            &details.policy_hash,
            &details.proof_hash,
            details.witness_commitment,
            details.witness_commitment_hex.as_deref(),
        )?;

        if details.proof_bytes()? != self.proof_bytes()? {
            return Err(ClientError::InvalidProofBundle(
                "proof details proof bytes do not match bundle proof bytes".to_string(),
            ));
        }

        if let Some(public_inputs) = details.validate_and_parse_public_inputs()? {
            validate_public_inputs_equal(&self.public_inputs, &public_inputs, "proof details")?;
        }

        Ok(())
    }

    /// Validate that a sequencer verification response still matches this canonical bundle.
    pub fn validate_verify_response(&self, response: &VerifyResponse) -> Result<()> {
        self.validate()?;
        let witness_commitment = normalized_optional_witness_commitment(
            response.witness_commitment,
            response.witness_commitment_hex.as_deref(),
            "verify response",
        )?;

        if response.event_id != self.receipt.event_id {
            return Err(ClientError::InvalidProofBundle(format!(
                "verify response event_id mismatch: expected {}, got {}",
                self.receipt.event_id, response.event_id
            )));
        }
        if response.tenant_id != self.receipt.tenant_id {
            return Err(ClientError::InvalidProofBundle(format!(
                "verify response tenant_id mismatch: expected {}, got {}",
                self.receipt.tenant_id, response.tenant_id
            )));
        }
        if response.store_id != self.receipt.store_id {
            return Err(ClientError::InvalidProofBundle(format!(
                "verify response store_id mismatch: expected {}, got {}",
                self.receipt.store_id, response.store_id
            )));
        }
        if response.proof_type != self.proof_type {
            return Err(ClientError::InvalidProofBundle(format!(
                "verify response proof_type mismatch: expected {}, got {}",
                self.proof_type, response.proof_type
            )));
        }
        if response.proof_version != self.proof_version {
            return Err(ClientError::InvalidProofBundle(format!(
                "verify response proof_version mismatch: expected {}, got {}",
                self.proof_version, response.proof_version
            )));
        }
        if response.policy_id != self.public_inputs.policy_id {
            return Err(ClientError::InvalidProofBundle(format!(
                "verify response policy_id mismatch: expected {}, got {}",
                self.public_inputs.policy_id, response.policy_id
            )));
        }
        if response.policy_hash != self.public_inputs.policy_hash {
            return Err(ClientError::InvalidProofBundle(format!(
                "verify response policy_hash mismatch: expected {}, got {}",
                self.public_inputs.policy_hash, response.policy_hash
            )));
        }
        if response.proof_hash != self.proof_hash {
            return Err(ClientError::InvalidProofBundle(format!(
                "verify response proof_hash mismatch: expected {}, got {}",
                self.proof_hash, response.proof_hash
            )));
        }
        if response.canonical_public_inputs_hash != self.public_inputs_hash {
            return Err(ClientError::InvalidProofBundle(format!(
                "verify response canonical_public_inputs_hash mismatch: expected {}, got {}",
                self.public_inputs_hash, response.canonical_public_inputs_hash
            )));
        }
        if let Some(public_inputs_hash) = response.public_inputs_hash.as_deref() {
            if public_inputs_hash != self.public_inputs_hash {
                return Err(ClientError::InvalidProofBundle(format!(
                    "verify response public_inputs_hash mismatch: expected {}, got {}",
                    self.public_inputs_hash, public_inputs_hash
                )));
            }
        }
        if !response.public_inputs_match {
            return Err(ClientError::InvalidProofBundle(
                "verify response reports public_inputs_match = false".to_string(),
            ));
        }
        if let Some(witness_commitment) = witness_commitment {
            if witness_commitment != self.witness_commitment {
                return Err(ClientError::InvalidProofBundle(
                    "verify response witness commitment does not match bundle".to_string(),
                ));
            }
        }
        if response.stark_valid == Some(false) {
            return Err(ClientError::InvalidProofBundle(
                response
                    .stark_error
                    .clone()
                    .unwrap_or_else(|| "verify response reports stark_valid = false".to_string()),
            ));
        }
        if !response.valid {
            return Err(ClientError::InvalidProofBundle(
                response
                    .reason
                    .clone()
                    .unwrap_or_else(|| "verify response reports valid = false".to_string()),
            ));
        }

        Ok(())
    }
}
