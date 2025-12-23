//! Unified Policy Abstraction
//!
//! This module provides a unified interface for all compliance policies,
//! allowing runtime policy selection in both prover and verifier.

use crate::policies::aml_threshold::AmlThresholdPolicy;
use crate::policies::order_total_cap::OrderTotalCapPolicy;
use crate::policies::policy_ids;
use ves_stark_primitives::{Felt, FELT_ZERO, felt_from_u64};
use ves_stark_primitives::public_inputs::PolicyParams;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Comparison type for policy validation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComparisonType {
    /// Strict less than (amount < limit)
    LessThan,
    /// Less than or equal (amount <= limit)
    LessThanOrEqual,
}

/// Errors that can occur when deriving policy limits
#[derive(Debug, Error)]
pub enum PolicyError {
    /// AML thresholds must be greater than zero for strict comparison
    #[error("AML threshold must be greater than zero")]
    InvalidThreshold,
    /// Unsupported policy identifier
    #[error("Unsupported policy id: {0}")]
    UnsupportedPolicyId(String),
    /// Missing required policy parameter
    #[error("Missing policy parameter: {0}")]
    MissingPolicyParam(&'static str),
}

/// Unified policy enum for runtime selection
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type")]
pub enum Policy {
    /// AML threshold policy (amount < threshold)
    AmlThreshold {
        threshold: u64,
    },
    /// Order total cap policy (amount <= cap)
    OrderTotalCap {
        cap: u64,
    },
}

impl Policy {
    /// Create an AML threshold policy
    pub fn aml_threshold(threshold: u64) -> Self {
        Policy::AmlThreshold { threshold }
    }

    /// Create an order total cap policy
    pub fn order_total_cap(cap: u64) -> Self {
        Policy::OrderTotalCap { cap }
    }

    /// Get the policy identifier
    pub fn policy_id(&self) -> &'static str {
        match self {
            Policy::AmlThreshold { .. } => policy_ids::AML_THRESHOLD,
            Policy::OrderTotalCap { .. } => policy_ids::ORDER_TOTAL_CAP,
        }
    }

    /// Get the limit value (threshold or cap)
    pub fn limit(&self) -> u64 {
        match self {
            Policy::AmlThreshold { threshold } => *threshold,
            Policy::OrderTotalCap { cap } => *cap,
        }
    }

    /// Get the effective limit used by the AIR.
    ///
    /// For strict less-than policies, we enforce amount <= threshold - 1.
    pub fn effective_limit(&self) -> Result<u64, PolicyError> {
        match self {
            Policy::AmlThreshold { threshold } => {
                if *threshold == 0 {
                    return Err(PolicyError::InvalidThreshold);
                }
                Ok(threshold - 1)
            }
            Policy::OrderTotalCap { cap } => Ok(*cap),
        }
    }

    /// Get the comparison type
    pub fn comparison_type(&self) -> ComparisonType {
        match self {
            Policy::AmlThreshold { .. } => ComparisonType::LessThan,
            Policy::OrderTotalCap { .. } => ComparisonType::LessThanOrEqual,
        }
    }

    /// Validate an amount against the policy
    pub fn validate_amount(&self, amount: u64) -> bool {
        match self {
            Policy::AmlThreshold { threshold } => amount < *threshold,
            Policy::OrderTotalCap { cap } => amount <= *cap,
        }
    }

    /// Parse a policy from public input policy id + params.
    pub fn from_public_inputs(policy_id: &str, policy_params: &PolicyParams) -> Result<Self, PolicyError> {
        match policy_id {
            policy_ids::AML_THRESHOLD => {
                let threshold = policy_params
                    .get_threshold()
                    .ok_or(PolicyError::MissingPolicyParam("threshold"))?;
                Ok(Policy::AmlThreshold { threshold })
            }
            policy_ids::ORDER_TOTAL_CAP => {
                let cap = policy_params
                    .get_cap()
                    .ok_or(PolicyError::MissingPolicyParam("cap"))?;
                Ok(Policy::OrderTotalCap { cap })
            }
            _ => Err(PolicyError::UnsupportedPolicyId(policy_id.to_string())),
        }
    }

    /// Get limit as field element limbs
    pub fn limit_limbs(&self) -> [Felt; 8] {
        let limit = self.limit();
        let mut limbs = [FELT_ZERO; 8];
        limbs[0] = felt_from_u64(limit & 0xFFFFFFFF);
        limbs[1] = felt_from_u64(limit >> 32);
        limbs
    }

    /// Get effective limit as field element limbs
    pub fn effective_limit_limbs(&self) -> Result<[Felt; 8], PolicyError> {
        let limit = self.effective_limit()?;
        let mut limbs = [FELT_ZERO; 8];
        limbs[0] = felt_from_u64(limit & 0xFFFFFFFF);
        limbs[1] = felt_from_u64(limit >> 32);
        Ok(limbs)
    }

    /// Convert to AmlThresholdPolicy (for trace building)
    pub fn as_aml_threshold(&self) -> Option<AmlThresholdPolicy> {
        match self {
            Policy::AmlThreshold { threshold } => Some(AmlThresholdPolicy::new(*threshold)),
            _ => None,
        }
    }

    /// Convert to OrderTotalCapPolicy (for trace building)
    pub fn as_order_total_cap(&self) -> Option<OrderTotalCapPolicy> {
        match self {
            Policy::OrderTotalCap { cap } => Some(OrderTotalCapPolicy::new(*cap)),
            _ => None,
        }
    }
}

impl From<AmlThresholdPolicy> for Policy {
    fn from(policy: AmlThresholdPolicy) -> Self {
        Policy::AmlThreshold { threshold: policy.threshold }
    }
}

impl From<OrderTotalCapPolicy> for Policy {
    fn from(policy: OrderTotalCapPolicy) -> Self {
        Policy::OrderTotalCap { cap: policy.cap }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aml_threshold_policy() {
        let policy = Policy::aml_threshold(10000);

        assert_eq!(policy.policy_id(), "aml.threshold");
        assert_eq!(policy.limit(), 10000);
        assert_eq!(policy.comparison_type(), ComparisonType::LessThan);

        assert!(policy.validate_amount(5000));
        assert!(policy.validate_amount(9999));
        assert!(!policy.validate_amount(10000)); // Not strictly less than
        assert!(!policy.validate_amount(10001));
    }

    #[test]
    fn test_order_total_cap_policy() {
        let policy = Policy::order_total_cap(10000);

        assert_eq!(policy.policy_id(), "order_total.cap");
        assert_eq!(policy.limit(), 10000);
        assert_eq!(policy.comparison_type(), ComparisonType::LessThanOrEqual);

        assert!(policy.validate_amount(5000));
        assert!(policy.validate_amount(10000)); // Equal is valid for LTE
        assert!(!policy.validate_amount(10001));
    }

    #[test]
    fn test_effective_limit() {
        let policy = Policy::aml_threshold(10);
        assert_eq!(policy.effective_limit().unwrap(), 9);

        let policy = Policy::order_total_cap(10);
        assert_eq!(policy.effective_limit().unwrap(), 10);

        let policy = Policy::aml_threshold(0);
        assert!(matches!(policy.effective_limit(), Err(PolicyError::InvalidThreshold)));
    }

    #[test]
    fn test_limit_limbs() {
        let policy = Policy::aml_threshold(0x123456789ABCDEF0);
        let limbs = policy.limit_limbs();

        assert_eq!(limbs[0].as_int(), 0x9ABCDEF0);
        assert_eq!(limbs[1].as_int(), 0x12345678);
        for i in 2..8 {
            assert_eq!(limbs[i].as_int(), 0);
        }
    }
}
