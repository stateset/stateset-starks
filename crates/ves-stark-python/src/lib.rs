//! Python bindings for VES STARK proof system
//!
//! This crate provides Python bindings for generating and verifying
//! STARK compliance proofs using PyO3.

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};
use uuid::Uuid;

use ves_stark_air::Policy as RustPolicy;
use ves_stark_primitives::{
    CommerceAuthorizationReceipt, CompliancePublicInputs as RustCompliancePublicInputs,
    PayloadAmountBinding, PolicyParams,
};
use ves_stark_prover::{ComplianceProver, ComplianceWitness};
use ves_stark_verifier::{
    verify_agent_authorization_proof_auto_with_amount_binding, verify_compliance_proof_auto_bound,
    verify_compliance_proof_auto_with_amount_binding, VerifierError,
};

/// Policy type for compliance proofs
#[pyclass]
#[derive(Clone)]
pub struct Policy {
    inner: RustPolicy,
}

#[pymethods]
impl Policy {
    /// Create an AML threshold policy
    ///
    /// The prover will prove that the amount is strictly less than the threshold.
    ///
    /// Args:
    ///     threshold: The AML threshold value
    ///
    /// Returns:
    ///     Policy configured for AML threshold compliance
    #[staticmethod]
    pub fn aml_threshold(threshold: u64) -> Self {
        Self {
            inner: RustPolicy::aml_threshold(threshold),
        }
    }

    /// Create an order total cap policy
    ///
    /// The prover will prove that the amount is less than or equal to the cap.
    ///
    /// Args:
    ///     cap: The order total cap value
    ///
    /// Returns:
    ///     Policy configured for order total cap compliance
    #[staticmethod]
    pub fn order_total_cap(cap: u64) -> Self {
        Self {
            inner: RustPolicy::order_total_cap(cap),
        }
    }

    /// Create an agent authorization policy.
    ///
    /// The prover will prove that the amount is less than or equal to the delegated maximum total
    /// and bind the proof to the supplied delegated commerce intent hash.
    ///
    /// Args:
    ///     max_total: The delegated maximum total
    ///     intent_hash: The delegated commerce intent hash (hex64)
    ///
    /// Returns:
    ///     Policy configured for delegated agent authorization
    #[staticmethod]
    pub fn agent_authorization(max_total: u64, intent_hash: String) -> PyResult<Self> {
        let inner = RustPolicy::agent_authorization(max_total, intent_hash).map_err(|e| {
            PyValueError::new_err(format!("Invalid agent authorization policy: {}", e))
        })?;
        Ok(Self { inner })
    }

    /// Get the policy ID string
    #[getter]
    pub fn policy_id(&self) -> &'static str {
        self.inner.policy_id()
    }

    /// Get the policy limit value
    #[getter]
    pub fn limit(&self) -> u64 {
        self.inner.limit()
    }

    fn __repr__(&self) -> String {
        format!("Policy({}, limit={})", self.policy_id(), self.limit())
    }
}

/// Public inputs for compliance proof generation/verification
#[pyclass]
#[derive(Clone)]
pub struct CompliancePublicInputs {
    /// UUID of the event being proven
    #[pyo3(get, set)]
    pub event_id: String,
    /// Tenant ID
    #[pyo3(get, set)]
    pub tenant_id: String,
    /// Store ID
    #[pyo3(get, set)]
    pub store_id: String,
    /// Sequence number of the event
    #[pyo3(get, set)]
    pub sequence_number: u64,
    /// Payload kind (event type discriminator)
    #[pyo3(get, set)]
    pub payload_kind: u32,
    /// SHA-256 hash of plaintext payload (hex64, lowercase)
    #[pyo3(get, set)]
    pub payload_plain_hash: String,
    /// SHA-256 hash of ciphertext payload (hex64, lowercase)
    #[pyo3(get, set)]
    pub payload_cipher_hash: String,
    /// Event signing hash (hex64, lowercase)
    #[pyo3(get, set)]
    pub event_signing_hash: String,
    /// Policy identifier (e.g., "aml.threshold")
    #[pyo3(get, set)]
    pub policy_id: String,
    /// Policy parameters as dict
    policy_params_json: String,
    /// Policy hash (hex64, lowercase)
    #[pyo3(get, set)]
    pub policy_hash: String,
    /// Optional witness commitment (hex64, lowercase) to bind the proved witness to canonical inputs.
    #[pyo3(get, set)]
    pub witness_commitment: Option<String>,
    /// Optional authorization receipt hash (hex64, lowercase) committed into canonical public inputs.
    #[pyo3(get, set)]
    pub authorization_receipt_hash: Option<String>,
    /// Optional payload amount binding hash (hex64, lowercase) committed into canonical public inputs.
    #[pyo3(get, set)]
    pub amount_binding_hash: Option<String>,
}

#[pymethods]
impl CompliancePublicInputs {
    /// Create new CompliancePublicInputs
    ///
    /// Args:
    ///     event_id: UUID of the event being proven
    ///     tenant_id: Tenant ID
    ///     store_id: Store ID
    ///     sequence_number: Sequence number of the event
    ///     payload_kind: Payload kind (event type discriminator)
    ///     payload_plain_hash: SHA-256 hash of plaintext payload (hex64, lowercase)
    ///     payload_cipher_hash: SHA-256 hash of ciphertext payload (hex64, lowercase)
    ///     event_signing_hash: Event signing hash (hex64, lowercase)
    ///     policy_id: Policy identifier (e.g., "aml.threshold")
    ///     policy_params: Policy parameters as dict
    ///     policy_hash: Policy hash (hex64, lowercase)
    ///     witness_commitment: Optional witness commitment (hex64, lowercase)
    ///     authorization_receipt_hash: Optional authorization receipt hash (hex64, lowercase)
    ///     amount_binding_hash: Optional payload amount binding hash (hex64, lowercase)
    #[new]
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (event_id, tenant_id, store_id, sequence_number, payload_kind, payload_plain_hash, payload_cipher_hash, event_signing_hash, policy_id, policy_params, policy_hash, witness_commitment=None, authorization_receipt_hash=None, amount_binding_hash=None))]
    pub fn new(
        event_id: String,
        tenant_id: String,
        store_id: String,
        sequence_number: u64,
        payload_kind: u32,
        payload_plain_hash: String,
        payload_cipher_hash: String,
        event_signing_hash: String,
        policy_id: String,
        policy_params: &Bound<'_, PyDict>,
        policy_hash: String,
        witness_commitment: Option<String>,
        authorization_receipt_hash: Option<String>,
        amount_binding_hash: Option<String>,
    ) -> PyResult<Self> {
        // Convert PyDict to JSON string
        let policy_params_json = Python::with_gil(|py| {
            let json = py.import("json")?;
            let dumps = json.getattr("dumps")?;
            dumps.call1((policy_params,))?.extract::<String>()
        })?;

        Ok(Self {
            event_id,
            tenant_id,
            store_id,
            sequence_number,
            payload_kind,
            payload_plain_hash,
            payload_cipher_hash,
            event_signing_hash,
            policy_id,
            policy_params_json,
            policy_hash,
            witness_commitment,
            authorization_receipt_hash,
            amount_binding_hash,
        })
    }

    /// Get policy parameters as a dict
    #[getter]
    pub fn policy_params(&self, py: Python<'_>) -> PyResult<PyObject> {
        let json = py.import("json")?;
        let loads = json.getattr("loads")?;
        let result = loads.call1((&self.policy_params_json,))?;
        Ok(result.into())
    }

    /// Set policy parameters from a dict
    #[setter]
    pub fn set_policy_params(&mut self, value: &Bound<'_, PyDict>) -> PyResult<()> {
        let policy_params_json = Python::with_gil(|py| {
            let json = py.import("json")?;
            let dumps = json.getattr("dumps")?;
            dumps.call1((value,))?.extract::<String>()
        })?;
        self.policy_params_json = policy_params_json;
        Ok(())
    }

    fn __repr__(&self) -> String {
        format!(
            "CompliancePublicInputs(event_id='{}', policy_id='{}')",
            self.event_id, self.policy_id
        )
    }
}

fn verifier_error_to_py(err: VerifierError) -> PyErr {
    let message = format!("Verification error: {}", err);
    match err {
        VerifierError::PublicInputMismatch(_)
        | VerifierError::InvalidHexFormat { .. }
        | VerifierError::DeserializationError(_)
        | VerifierError::InvalidPolicyHash { .. }
        | VerifierError::PolicyMismatch { .. }
        | VerifierError::LimitMismatch { .. }
        | VerifierError::WitnessCommitmentMismatch
        | VerifierError::ProofTooLarge { .. }
        | VerifierError::UnsupportedProofVersion { .. } => PyValueError::new_err(message),
        VerifierError::InvalidProofStructure(_)
        | VerifierError::FriVerificationFailed(_)
        | VerifierError::ConstraintCheckFailed(_)
        | VerifierError::VerificationFailed(_) => PyRuntimeError::new_err(message),
    }
}

impl CompliancePublicInputs {
    fn to_rust(&self) -> PyResult<RustCompliancePublicInputs> {
        let event_id = Uuid::parse_str(&self.event_id)
            .map_err(|e| PyValueError::new_err(format!("Invalid event_id UUID: {}", e)))?;
        let tenant_id = Uuid::parse_str(&self.tenant_id)
            .map_err(|e| PyValueError::new_err(format!("Invalid tenant_id UUID: {}", e)))?;
        let store_id = Uuid::parse_str(&self.store_id)
            .map_err(|e| PyValueError::new_err(format!("Invalid store_id UUID: {}", e)))?;

        let policy_params: serde_json::Value = serde_json::from_str(&self.policy_params_json)
            .map_err(|e| PyValueError::new_err(format!("Invalid policy_params JSON: {}", e)))?;

        Ok(RustCompliancePublicInputs {
            event_id,
            tenant_id,
            store_id,
            sequence_number: self.sequence_number,
            payload_kind: self.payload_kind,
            payload_plain_hash: self.payload_plain_hash.clone(),
            payload_cipher_hash: self.payload_cipher_hash.clone(),
            event_signing_hash: self.event_signing_hash.clone(),
            policy_id: self.policy_id.clone(),
            policy_params: PolicyParams(policy_params),
            policy_hash: self.policy_hash.clone(),
            witness_commitment: self.witness_commitment.clone(),
            authorization_receipt_hash: self.authorization_receipt_hash.clone(),
            amount_binding_hash: self.amount_binding_hash.clone(),
        })
    }
}

fn bind_public_inputs_to_commitment(
    public_inputs: &CompliancePublicInputs,
    witness_commitment: &[u64; 4],
) -> PyResult<RustCompliancePublicInputs> {
    let rust_inputs = public_inputs.to_rust()?;
    rust_inputs
        .bind_witness_commitment(witness_commitment)
        .map_err(|e| PyValueError::new_err(format!("Failed to bind witness commitment: {}", e)))
}

fn receipt_from_py_dict(value: &Bound<'_, PyDict>) -> PyResult<CommerceAuthorizationReceipt> {
    let receipt_json = Python::with_gil(|py| {
        let json = py.import("json")?;
        let dumps = json.getattr("dumps")?;
        dumps.call1((value,))?.extract::<String>()
    })?;
    serde_json::from_str(&receipt_json)
        .map_err(|e| PyValueError::new_err(format!("Invalid authorization receipt dict: {}", e)))
}

fn payload_amount_binding_from_py_dict(
    value: &Bound<'_, PyDict>,
) -> PyResult<PayloadAmountBinding> {
    let binding_json = Python::with_gil(|py| {
        let json = py.import("json")?;
        let dumps = json.getattr("dumps")?;
        dumps.call1((value,))?.extract::<String>()
    })?;
    serde_json::from_str(&binding_json)
        .map_err(|e| PyValueError::new_err(format!("Invalid payload amount binding dict: {}", e)))
}

/// Result of proof generation
#[pyclass]
pub struct ComplianceProof {
    /// Raw proof bytes
    proof_bytes_vec: Vec<u8>,
    /// SHA-256 hash of proof bytes (hex)
    #[pyo3(get)]
    pub proof_hash: String,
    /// Time taken to generate proof in milliseconds
    #[pyo3(get)]
    pub proving_time_ms: u64,
    /// Size of proof in bytes
    #[pyo3(get)]
    pub proof_size: usize,
    /// Witness commitment (4 x u64)
    witness_commitment_vec: Vec<u64>,
    /// Witness commitment encoded as 32 bytes (4 x u64 big-endian) and hex-encoded (64 chars).
    #[pyo3(get)]
    pub witness_commitment_hex: String,
}

#[pymethods]
impl ComplianceProof {
    /// Get the raw proof bytes
    #[getter]
    pub fn proof_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.proof_bytes_vec)
    }

    /// Get the witness commitment as a list of 4 integers
    #[getter]
    pub fn witness_commitment(&self) -> Vec<u64> {
        self.witness_commitment_vec.clone()
    }

    fn __repr__(&self) -> String {
        format!(
            "ComplianceProof(proof_size={}, proving_time_ms={})",
            self.proof_size, self.proving_time_ms
        )
    }
}

/// Result of proof verification
#[pyclass]
pub struct VerificationResult {
    /// Whether the proof is valid
    #[pyo3(get)]
    pub valid: bool,
    /// Time taken to verify in milliseconds
    #[pyo3(get)]
    pub verification_time_ms: u64,
    /// Error message if verification failed
    #[pyo3(get)]
    pub error: Option<String>,
    /// Policy ID that was verified
    #[pyo3(get)]
    pub policy_id: String,
    /// Policy limit that was verified against
    #[pyo3(get)]
    pub policy_limit: u64,
}

#[pymethods]
impl VerificationResult {
    fn __repr__(&self) -> String {
        format!(
            "VerificationResult(valid={}, policy_id='{}', policy_limit={})",
            self.valid, self.policy_id, self.policy_limit
        )
    }

    fn __bool__(&self) -> bool {
        self.valid
    }
}

/// Generate a STARK compliance proof for the provided amount witness.
///
/// Args:
///     amount: The amount to prove compliance for (must satisfy policy constraint)
///     public_inputs: Public inputs including event metadata and policy info
///     policy: The policy to prove compliance against
///
/// Returns:
///     ComplianceProof containing proof bytes and metadata
///
/// Raises:
///     ValueError: If inputs are invalid
///     RuntimeError: If proof generation fails
///
/// Note:
///     This proves a statement about the supplied ``amount`` witness. Binding that
///     witness back to encrypted payload contents is the responsibility of the
///     surrounding pipeline, not this library.
///
/// Example:
///     >>> policy = Policy.aml_threshold(10000)
///     >>> proof = prove(5000, public_inputs, policy)
///     >>> print(f"Proof generated in {proof.proving_time_ms}ms")
#[pyfunction]
pub fn prove(
    amount: u64,
    public_inputs: &CompliancePublicInputs,
    policy: &Policy,
) -> PyResult<ComplianceProof> {
    // Convert public inputs
    let rust_inputs = public_inputs.to_rust()?;

    // Create witness
    let witness = ComplianceWitness::try_new(amount, rust_inputs)
        .map_err(|e| PyValueError::new_err(format!("Invalid witness/public inputs: {}", e)))?;

    // Create prover and generate proof
    let prover = ComplianceProver::with_policy(policy.inner.clone());
    let proof = prover
        .prove(&witness)
        .map_err(|e| PyRuntimeError::new_err(format!("Proof generation failed: {}", e)))?;

    Ok(ComplianceProof {
        proof_bytes_vec: proof.proof_bytes,
        proof_hash: proof.proof_hash,
        proving_time_ms: proof.metadata.proving_time_ms,
        proof_size: proof.metadata.proof_size,
        witness_commitment_vec: proof.witness_commitment.to_vec(),
        witness_commitment_hex: proof.witness_commitment_hex.ok_or_else(|| {
            PyRuntimeError::new_err("Missing witness_commitment_hex in proof".to_string())
        })?,
    })
}

/// Verify a STARK compliance proof
///
/// Args:
///     proof_bytes: The raw proof bytes from prove()
///     public_inputs: Public inputs (must match those used for proving)
///     witness_commitment: Witness commitment from the proof (list of 4 integers)
///
/// Returns:
///     VerificationResult indicating if proof is valid
///
/// Raises:
///     ValueError: If public inputs, proof bytes, or witness commitment are malformed
///
/// Example:
///     >>> result = verify(proof.proof_bytes, public_inputs, proof.witness_commitment)
///     >>> if result.valid:
///     ...     print("Proof is valid!")
#[pyfunction]
pub fn verify(
    proof_bytes: &[u8],
    public_inputs: &CompliancePublicInputs,
    witness_commitment: Vec<u64>,
) -> PyResult<VerificationResult> {
    // Convert witness commitment
    if witness_commitment.len() != 4 {
        return Err(PyValueError::new_err(format!(
            "Witness commitment must have exactly 4 elements, got {}",
            witness_commitment.len()
        )));
    }
    let commitment: [u64; 4] = [
        witness_commitment[0],
        witness_commitment[1],
        witness_commitment[2],
        witness_commitment[3],
    ];
    let rust_inputs = bind_public_inputs_to_commitment(public_inputs, &commitment)?;

    // Verify proof
    let result = verify_compliance_proof_auto_bound(proof_bytes, &rust_inputs);

    match result {
        Ok(verification) => Ok(VerificationResult {
            valid: verification.valid,
            verification_time_ms: verification.verification_time_ms,
            error: verification.error,
            policy_id: verification.policy_id,
            policy_limit: verification.policy_limit,
        }),
        Err(e) => Err(verifier_error_to_py(e)),
    }
}

/// Verify a STARK compliance proof against a canonical payload amount binding.
#[pyfunction]
pub fn verify_with_amount_binding(
    proof_bytes: &[u8],
    public_inputs: &CompliancePublicInputs,
    amount_binding: &Bound<'_, PyDict>,
) -> PyResult<VerificationResult> {
    let rust_inputs = public_inputs.to_rust()?;
    let binding = payload_amount_binding_from_py_dict(amount_binding)?;

    let result =
        verify_compliance_proof_auto_with_amount_binding(proof_bytes, &rust_inputs, &binding);

    match result {
        Ok(verification) => Ok(VerificationResult {
            valid: verification.valid,
            verification_time_ms: verification.verification_time_ms,
            error: verification.error,
            policy_id: verification.policy_id,
            policy_limit: verification.policy_limit,
        }),
        Err(e) => Err(verifier_error_to_py(e)),
    }
}

/// Verify an `agent.authorization.v1` proof against a canonical authorization receipt.
#[pyfunction]
pub fn verify_agent_authorization(
    proof_bytes: &[u8],
    public_inputs: &CompliancePublicInputs,
    witness_commitment: Vec<u64>,
    receipt: &Bound<'_, PyDict>,
) -> PyResult<VerificationResult> {
    if witness_commitment.len() != 4 {
        return Err(PyValueError::new_err(format!(
            "Witness commitment must have exactly 4 elements, got {}",
            witness_commitment.len()
        )));
    }
    let commitment: [u64; 4] = [
        witness_commitment[0],
        witness_commitment[1],
        witness_commitment[2],
        witness_commitment[3],
    ];
    let rust_inputs = bind_public_inputs_to_commitment(public_inputs, &commitment)?;
    let receipt = receipt_from_py_dict(receipt)?;
    let binding = rust_inputs
        .payload_amount_binding(receipt.amount)
        .map_err(|e| verifier_error_to_py(VerifierError::PublicInputMismatch(format!("{e}"))))?;

    let result = verify_agent_authorization_proof_auto_with_amount_binding(
        proof_bytes,
        &rust_inputs,
        &binding,
        &receipt,
    );

    match result {
        Ok(verification) => Ok(VerificationResult {
            valid: verification.valid,
            verification_time_ms: verification.verification_time_ms,
            error: verification.error,
            policy_id: verification.policy_id,
            policy_limit: verification.policy_limit,
        }),
        Err(e) => Err(verifier_error_to_py(e)),
    }
}

/// Verify an `agent.authorization.v1` proof against both a canonical payload amount binding and a
/// canonical authorization receipt.
#[pyfunction]
pub fn verify_agent_authorization_with_amount_binding(
    proof_bytes: &[u8],
    public_inputs: &CompliancePublicInputs,
    amount_binding: &Bound<'_, PyDict>,
    receipt: &Bound<'_, PyDict>,
) -> PyResult<VerificationResult> {
    let rust_inputs = public_inputs.to_rust()?;
    let binding = payload_amount_binding_from_py_dict(amount_binding)?;
    let receipt = receipt_from_py_dict(receipt)?;

    let result = verify_agent_authorization_proof_auto_with_amount_binding(
        proof_bytes,
        &rust_inputs,
        &binding,
        &receipt,
    );

    match result {
        Ok(verification) => Ok(VerificationResult {
            valid: verification.valid,
            verification_time_ms: verification.verification_time_ms,
            error: verification.error,
            policy_id: verification.policy_id,
            policy_limit: verification.policy_limit,
        }),
        Err(e) => Err(verifier_error_to_py(e)),
    }
}

/// Compute the policy hash for given policy ID and parameters
///
/// Args:
///     policy_id: Policy identifier (e.g., "aml.threshold")
///     policy_params: Policy parameters as dict
///
/// Returns:
///     Policy hash as hex string (64 characters, lowercase)
///
/// Raises:
///     RuntimeError: If hash computation fails
///
/// Example:
///     >>> hash = compute_policy_hash("aml.threshold", {"threshold": 10000})
#[pyfunction]
pub fn compute_policy_hash(policy_id: &str, policy_params: &Bound<'_, PyDict>) -> PyResult<String> {
    // Convert PyDict to JSON
    let params_json = Python::with_gil(|py| {
        let json = py.import("json")?;
        let dumps = json.getattr("dumps")?;
        dumps.call1((policy_params,))?.extract::<String>()
    })?;

    let params: serde_json::Value = serde_json::from_str(&params_json)
        .map_err(|e| PyValueError::new_err(format!("Invalid policy_params JSON: {}", e)))?;

    let hash = ves_stark_primitives::compute_policy_hash(policy_id, &PolicyParams(params))
        .map_err(|e| PyRuntimeError::new_err(format!("Failed to compute policy hash: {}", e)))?;

    Ok(hash.to_hex())
}

/// Create a canonical payload amount binding for the supplied public inputs and extracted amount.
#[pyfunction]
pub fn create_payload_amount_binding(
    py: Python<'_>,
    public_inputs: &CompliancePublicInputs,
    amount: u64,
) -> PyResult<PyObject> {
    let rust_inputs = public_inputs.to_rust()?;

    let binding = rust_inputs.payload_amount_binding(amount).map_err(|e| {
        PyValueError::new_err(format!("Invalid payload amount binding inputs: {}", e))
    })?;

    let binding_json = serde_json::to_string(&binding).map_err(|e| {
        PyRuntimeError::new_err(format!("Failed to serialize payload amount binding: {}", e))
    })?;
    let json = py.import("json")?;
    let loads = json.getattr("loads")?;
    Ok(loads.call1((binding_json,))?.into())
}

/// VES STARK Python module
///
/// This module provides Python bindings for the VES STARK proof system,
/// enabling generation and verification of zero-knowledge compliance proofs.
///
/// Example:
///     >>> import ves_stark
///     >>> policy = ves_stark.Policy.aml_threshold(10000)
///     >>> proof = ves_stark.prove(5000, public_inputs, policy)
///     >>> result = ves_stark.verify(proof.proof_bytes, public_inputs, proof.witness_commitment)
///     >>> print(f"Valid: {result.valid}")
#[pymodule]
fn ves_stark(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Policy>()?;
    m.add_class::<CompliancePublicInputs>()?;
    m.add_class::<ComplianceProof>()?;
    m.add_class::<VerificationResult>()?;
    m.add_function(wrap_pyfunction!(prove, m)?)?;
    m.add_function(wrap_pyfunction!(verify, m)?)?;
    m.add_function(wrap_pyfunction!(verify_with_amount_binding, m)?)?;
    m.add_function(wrap_pyfunction!(verify_agent_authorization, m)?)?;
    m.add_function(wrap_pyfunction!(
        verify_agent_authorization_with_amount_binding,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(compute_policy_hash, m)?)?;
    m.add_function(wrap_pyfunction!(create_payload_amount_binding, m)?)?;
    Ok(())
}
