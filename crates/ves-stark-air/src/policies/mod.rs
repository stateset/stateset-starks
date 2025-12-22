//! Policy-specific constraint implementations
//!
//! Each policy defines specific constraints that must be satisfied
//! for the compliance proof to be valid.
//!
//! # Available Policies
//!
//! - `aml.threshold`: Proves amount < threshold (strict less than)
//! - `order_total.cap`: Proves amount <= cap (less than or equal)

pub mod aml_threshold;
pub mod order_total_cap;

pub use aml_threshold::AmlThresholdPolicy;
pub use order_total_cap::OrderTotalCapPolicy;

/// Policy identifier constants
pub mod policy_ids {
    /// AML threshold policy: proves amount < threshold
    pub const AML_THRESHOLD: &str = "aml.threshold";
    /// Order total cap policy: proves amount <= cap
    pub const ORDER_TOTAL_CAP: &str = "order_total.cap";
}
