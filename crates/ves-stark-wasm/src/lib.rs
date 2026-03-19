//! WebAssembly bindings for the VES STARK proof system.
//!
//! This crate exposes a browser-oriented API over the existing prover and verifier
//! crates using `wasm-bindgen`. It keeps proof logic in the shared Rust core and
//! only handles JavaScript boundary parsing/serialization here.

use js_sys::{Array, BigInt, Object, Reflect, Uint8Array};
use serde_json::json;
use uuid::Uuid;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

use ves_stark_air::Policy;
use ves_stark_primitives::{
    compute_policy_hash, CompliancePublicInputs, PayloadAmountBinding, PolicyParams,
};
use ves_stark_prover::{ComplianceProver, ComplianceWitness};
use ves_stark_verifier::{
    verify_compliance_proof_auto_bound, verify_compliance_proof_auto_with_amount_binding,
};

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console, js_name = error)]
    fn console_error(message: &str);
}

fn js_error(message: impl Into<String>) -> JsValue {
    JsValue::from_str(&message.into())
}

#[cfg(target_arch = "wasm32")]
fn install_panic_hook() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        std::panic::set_hook(Box::new(|panic_info| {
            console_error(&format!("ves-stark-wasm panic: {panic_info}"));
        }));
    });
}

#[cfg(not(target_arch = "wasm32"))]
fn install_panic_hook() {}

#[wasm_bindgen(start)]
pub fn start() {
    install_panic_hook();
}

fn set_property(object: &Object, key: &str, value: JsValue) -> Result<(), JsValue> {
    Reflect::set(object, &JsValue::from_str(key), &value)
        .map(|_| ())
        .map_err(|_| js_error(format!("failed to set JS property {key}")))
}

fn required_value(object: &Object, key: &str) -> Result<JsValue, JsValue> {
    let value = Reflect::get(object, &JsValue::from_str(key))
        .map_err(|_| js_error(format!("failed to read {key}")))?;
    if value.is_undefined() || value.is_null() {
        Err(js_error(format!("missing required field {key}")))
    } else {
        Ok(value)
    }
}

fn optional_value(object: &Object, key: &str) -> Result<Option<JsValue>, JsValue> {
    let value = Reflect::get(object, &JsValue::from_str(key))
        .map_err(|_| js_error(format!("failed to read {key}")))?;
    if value.is_undefined() || value.is_null() {
        Ok(None)
    } else {
        Ok(Some(value))
    }
}

fn required_object(value: JsValue, field_name: &str) -> Result<Object, JsValue> {
    value
        .dyn_into::<Object>()
        .map_err(|_| js_error(format!("{field_name} must be an object")))
}

fn required_string(object: &Object, key: &str) -> Result<String, JsValue> {
    required_value(object, key)?
        .as_string()
        .ok_or_else(|| js_error(format!("{key} must be a string")))
}

fn optional_string(object: &Object, key: &str) -> Result<Option<String>, JsValue> {
    optional_value(object, key)?
        .map(|value| {
            value
                .as_string()
                .ok_or_else(|| js_error(format!("{key} must be a string")))
        })
        .transpose()
}

fn js_value_to_u64(value: JsValue, field_name: &str) -> Result<u64, JsValue> {
    if value.is_bigint() {
        let bigint =
            BigInt::new(&value).map_err(|_| js_error(format!("{field_name} must be a bigint")))?;
        let text = bigint
            .to_string(10)
            .map_err(|_| js_error(format!("{field_name} must be a base-10 bigint")))?
            .as_string()
            .ok_or_else(|| js_error(format!("{field_name} bigint string conversion failed")))?;
        return text
            .parse::<u64>()
            .map_err(|_| js_error(format!("{field_name} must fit in u64")));
    }

    if let Some(text) = value.as_string() {
        return text
            .parse::<u64>()
            .map_err(|_| js_error(format!("{field_name} must be a valid u64 string")));
    }

    if let Some(number) = value.as_f64() {
        if !number.is_finite() || number < 0.0 || number.fract() != 0.0 {
            return Err(js_error(format!(
                "{field_name} must be a non-negative integer"
            )));
        }
        if number > 9_007_199_254_740_991_f64 {
            return Err(js_error(format!(
                "{field_name} exceeds the JavaScript safe integer range; pass a BigInt or string"
            )));
        }
        return Ok(number as u64);
    }

    Err(js_error(format!(
        "{field_name} must be a number, bigint, or decimal string"
    )))
}

fn required_u64(object: &Object, key: &str) -> Result<u64, JsValue> {
    js_value_to_u64(required_value(object, key)?, key)
}

fn required_u32(object: &Object, key: &str) -> Result<u32, JsValue> {
    let value = required_u64(object, key)?;
    u32::try_from(value).map_err(|_| js_error(format!("{key} must fit in u32")))
}

fn policy_params_from_object(policy_id: &str, object: &Object) -> Result<PolicyParams, JsValue> {
    match policy_id {
        "aml.threshold" => Ok(PolicyParams(json!({
            "threshold": required_u64(object, "threshold")?,
        }))),
        "order_total.cap" => Ok(PolicyParams(json!({
            "cap": required_u64(object, "cap")?,
        }))),
        "agent.authorization.v1" => {
            let max_total = required_u64(object, "maxTotal")?;
            let intent_hash = required_string(object, "intentHash")?;
            PolicyParams::agent_authorization(max_total, &intent_hash)
                .map_err(|err| js_error(format!("invalid agent authorization params: {err}")))
        }
        _ => Err(js_error(format!("unsupported policy type {policy_id}"))),
    }
}

fn parse_policy_params(policy_id: &str, value: JsValue) -> Result<PolicyParams, JsValue> {
    let object = required_object(value, "policyParams")?;
    policy_params_from_object(policy_id, &object)
}

fn parse_uuid_field(object: &Object, key: &str) -> Result<Uuid, JsValue> {
    Uuid::parse_str(&required_string(object, key)?)
        .map_err(|err| js_error(format!("{key} must be a valid UUID: {err}")))
}

fn parse_public_inputs(value: JsValue) -> Result<CompliancePublicInputs, JsValue> {
    let object = required_object(value, "publicInputs")?;
    let policy_id = required_string(&object, "policyId")?;
    let policy_params = parse_policy_params(&policy_id, required_value(&object, "policyParams")?)?;

    Ok(CompliancePublicInputs {
        event_id: parse_uuid_field(&object, "eventId")?,
        tenant_id: parse_uuid_field(&object, "tenantId")?,
        store_id: parse_uuid_field(&object, "storeId")?,
        sequence_number: required_u64(&object, "sequenceNumber")?,
        payload_kind: required_u32(&object, "payloadKind")?,
        payload_plain_hash: required_string(&object, "payloadPlainHash")?,
        payload_cipher_hash: required_string(&object, "payloadCipherHash")?,
        event_signing_hash: required_string(&object, "eventSigningHash")?,
        policy_id,
        policy_params,
        policy_hash: required_string(&object, "policyHash")?,
        witness_commitment: optional_string(&object, "witnessCommitment")?,
        authorization_receipt_hash: optional_string(&object, "authorizationReceiptHash")?,
        amount_binding_hash: optional_string(&object, "amountBindingHash")?,
    })
}

fn parse_payload_amount_binding(value: JsValue) -> Result<PayloadAmountBinding, JsValue> {
    let object = required_object(value, "amountBinding")?;

    Ok(PayloadAmountBinding {
        event_id: parse_uuid_field(&object, "eventId")?,
        tenant_id: parse_uuid_field(&object, "tenantId")?,
        store_id: parse_uuid_field(&object, "storeId")?,
        sequence_number: required_u64(&object, "sequenceNumber")?,
        payload_kind: required_u32(&object, "payloadKind")?,
        payload_plain_hash: required_string(&object, "payloadPlainHash")?,
        payload_cipher_hash: required_string(&object, "payloadCipherHash")?,
        event_signing_hash: required_string(&object, "eventSigningHash")?,
        amount: required_u64(&object, "amount")?,
        binding_hash: required_string(&object, "bindingHash")?,
    })
}

fn u64_to_js(value: u64) -> JsValue {
    JsValue::from(BigInt::from(value))
}

fn proof_to_js(
    proof: ves_stark_prover::ComplianceProof,
    witness_commitment_hex: String,
) -> Result<JsValue, JsValue> {
    let object = Object::new();
    let witness_commitment = Array::new();
    for limb in proof.witness_commitment {
        witness_commitment.push(&JsValue::from_str(&limb.to_string()));
    }

    set_property(
        &object,
        "proofBytes",
        Uint8Array::from(proof.proof_bytes.as_slice()).into(),
    )?;
    set_property(&object, "proofHash", JsValue::from_str(&proof.proof_hash))?;
    set_property(
        &object,
        "provingTimeMs",
        JsValue::from_f64(proof.metadata.proving_time_ms as f64),
    )?;
    set_property(
        &object,
        "proofSize",
        JsValue::from_f64(proof.metadata.proof_size as f64),
    )?;
    set_property(&object, "witnessCommitment", witness_commitment.into())?;
    set_property(
        &object,
        "witnessCommitmentHex",
        JsValue::from_str(&witness_commitment_hex),
    )?;

    Ok(object.into())
}

fn verification_result_to_js(
    result: ves_stark_verifier::VerificationResult,
) -> Result<JsValue, JsValue> {
    let object = Object::new();

    set_property(&object, "valid", JsValue::from_bool(result.valid))?;
    set_property(
        &object,
        "verificationTimeMs",
        JsValue::from_f64(result.verification_time_ms as f64),
    )?;
    match result.error {
        Some(error) => set_property(&object, "error", JsValue::from_str(&error))?,
        None => set_property(&object, "error", JsValue::NULL)?,
    }
    set_property(&object, "policyId", JsValue::from_str(&result.policy_id))?;
    set_property(&object, "policyLimit", u64_to_js(result.policy_limit))?;

    Ok(object.into())
}

fn payload_amount_binding_to_js(binding: PayloadAmountBinding) -> Result<JsValue, JsValue> {
    let object = Object::new();

    set_property(
        &object,
        "eventId",
        JsValue::from_str(&binding.event_id.to_string()),
    )?;
    set_property(
        &object,
        "tenantId",
        JsValue::from_str(&binding.tenant_id.to_string()),
    )?;
    set_property(
        &object,
        "storeId",
        JsValue::from_str(&binding.store_id.to_string()),
    )?;
    set_property(
        &object,
        "sequenceNumber",
        u64_to_js(binding.sequence_number),
    )?;
    set_property(
        &object,
        "payloadKind",
        JsValue::from_f64(binding.payload_kind as f64),
    )?;
    set_property(
        &object,
        "payloadPlainHash",
        JsValue::from_str(&binding.payload_plain_hash),
    )?;
    set_property(
        &object,
        "payloadCipherHash",
        JsValue::from_str(&binding.payload_cipher_hash),
    )?;
    set_property(
        &object,
        "eventSigningHash",
        JsValue::from_str(&binding.event_signing_hash),
    )?;
    set_property(&object, "amount", u64_to_js(binding.amount))?;
    set_property(
        &object,
        "bindingHash",
        JsValue::from_str(&binding.binding_hash),
    )?;

    Ok(object.into())
}

fn bind_public_inputs_to_witness_hex(
    public_inputs: CompliancePublicInputs,
    witness_commitment_hex: &str,
) -> Result<CompliancePublicInputs, JsValue> {
    let witness_commitment =
        ves_stark_primitives::witness_commitment_hex_to_u64(witness_commitment_hex)
            .map_err(|err| js_error(format!("invalid witness commitment hex: {err}")))?;

    public_inputs
        .bind_witness_commitment(&witness_commitment)
        .map_err(|err| js_error(format!("failed to bind witness commitment: {err}")))
}

#[wasm_bindgen]
pub fn prove(
    amount: u64,
    public_inputs: JsValue,
    policy_type: String,
    policy_limit: u64,
) -> Result<JsValue, JsValue> {
    let public_inputs = parse_public_inputs(public_inputs)?;

    if public_inputs.policy_id != policy_type {
        return Err(js_error(format!(
            "policyType {policy_type} does not match publicInputs.policyId {}",
            public_inputs.policy_id
        )));
    }

    let policy = Policy::from_public_inputs(&public_inputs.policy_id, &public_inputs.policy_params)
        .map_err(|err| {
            js_error(format!(
                "invalid policy parameters for {policy_type}: {err}"
            ))
        })?;
    if policy.limit() != policy_limit {
        return Err(js_error(format!(
            "policyLimit {policy_limit} does not match publicInputs policy limit {}",
            policy.limit()
        )));
    }
    if !policy.validate_amount(amount) {
        return Err(js_error(format!(
            "amount {amount} does not satisfy policy {policy_type} with limit {policy_limit}"
        )));
    }

    let witness = ComplianceWitness::try_new(amount, public_inputs)
        .map_err(|err| js_error(format!("invalid witness: {err}")))?;
    let proof = ComplianceProver::with_policy(policy)
        .prove(&witness)
        .map_err(|err| js_error(format!("proof generation failed: {err}")))?;
    let witness_commitment_hex = proof
        .witness_commitment_hex
        .clone()
        .ok_or_else(|| js_error("proof did not include witnessCommitmentHex"))?;

    proof_to_js(proof, witness_commitment_hex)
}

#[wasm_bindgen(js_name = verifyHex)]
pub fn verify_hex(
    proof_bytes: Vec<u8>,
    public_inputs: JsValue,
    witness_commitment_hex: String,
) -> Result<JsValue, JsValue> {
    let public_inputs = parse_public_inputs(public_inputs)?;
    let bound_inputs = bind_public_inputs_to_witness_hex(public_inputs, &witness_commitment_hex)?;
    let result = verify_compliance_proof_auto_bound(&proof_bytes, &bound_inputs)
        .map_err(|err| js_error(format!("verification failed: {err}")))?;
    verification_result_to_js(result)
}

#[wasm_bindgen(js_name = verifyWithAmountBinding)]
pub fn verify_with_amount_binding(
    proof_bytes: Vec<u8>,
    public_inputs: JsValue,
    amount_binding: JsValue,
) -> Result<JsValue, JsValue> {
    let public_inputs = parse_public_inputs(public_inputs)?;
    let amount_binding = parse_payload_amount_binding(amount_binding)?;
    let result = verify_compliance_proof_auto_with_amount_binding(
        &proof_bytes,
        &public_inputs,
        &amount_binding,
    )
    .map_err(|err| js_error(format!("verification failed: {err}")))?;
    verification_result_to_js(result)
}

#[wasm_bindgen(js_name = computePolicyHash)]
pub fn compute_policy_hash_js(
    policy_id: String,
    policy_params: JsValue,
) -> Result<String, JsValue> {
    let policy_params = parse_policy_params(&policy_id, policy_params)?;
    compute_policy_hash(&policy_id, &policy_params)
        .map(|hash| hash.to_hex())
        .map_err(|err| js_error(format!("failed to compute policy hash: {err}")))
}

#[wasm_bindgen(js_name = createAmlThresholdParams)]
pub fn create_aml_threshold_params(threshold: u64) -> Result<JsValue, JsValue> {
    let object = Object::new();
    set_property(&object, "threshold", u64_to_js(threshold))?;
    Ok(object.into())
}

#[wasm_bindgen(js_name = createOrderTotalCapParams)]
pub fn create_order_total_cap_params(cap: u64) -> Result<JsValue, JsValue> {
    let object = Object::new();
    set_property(&object, "cap", u64_to_js(cap))?;
    Ok(object.into())
}

#[wasm_bindgen(js_name = createAgentAuthorizationParams)]
pub fn create_agent_authorization_params(
    max_total: u64,
    intent_hash: String,
) -> Result<JsValue, JsValue> {
    let object = Object::new();
    set_property(&object, "maxTotal", u64_to_js(max_total))?;
    set_property(&object, "intentHash", JsValue::from_str(&intent_hash))?;
    Ok(object.into())
}

#[wasm_bindgen(js_name = createPayloadAmountBinding)]
pub fn create_payload_amount_binding(
    public_inputs: JsValue,
    amount: u64,
) -> Result<JsValue, JsValue> {
    let public_inputs = parse_public_inputs(public_inputs)?;
    let binding = PayloadAmountBinding::from_public_inputs(&public_inputs, amount)
        .map_err(|err| js_error(format!("failed to create payload amount binding: {err}")))?;
    payload_amount_binding_to_js(binding)
}
