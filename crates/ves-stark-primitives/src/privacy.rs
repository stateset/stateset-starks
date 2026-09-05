//! Fail-closed confidentiality requirements for the current integrity-only backend.

use serde::{Deserialize, Serialize};

/// Whether the application requires witness confidentiality.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofPrivacy {
    /// Require a reviewed zero-knowledge construction. Unsupported by this backend.
    #[default]
    Confidential,
    /// Explicitly accept that proof bytes can disclose the amount and witness salt.
    AllowDisclosure,
}

/// The configured backend cannot satisfy a confidentiality requirement.
#[derive(Debug, thiserror::Error)]
#[error("confidential proofs are unavailable: the Winterfell backend can disclose witness amounts; use an explicit integrity-only API only when disclosure is acceptable")]
pub struct ConfidentialityUnavailable;

impl ProofPrivacy {
    /// Reject unsupported confidentiality requirements before handling a witness.
    pub fn enforce(self) -> Result<(), ConfidentialityUnavailable> {
        match self {
            Self::Confidential => Err(ConfidentialityUnavailable),
            Self::AllowDisclosure => Ok(()),
        }
    }
}

/// This backend has a demonstrated witness-recovery attack. Salted commitments
/// do not make its proof transcript zero knowledge.
pub const SUPPORTS_ZERO_KNOWLEDGE: bool = false;
