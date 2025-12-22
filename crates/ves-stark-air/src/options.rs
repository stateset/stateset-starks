//! Proof Options Configuration
//!
//! Configurable parameters for STARK proof generation that affect
//! security level, proof size, and proving/verification time.

use winter_air::FieldExtension;

/// Options for proof generation
#[derive(Debug, Clone)]
pub struct ProofOptions {
    /// Number of FRI queries (higher = more security, slower verification)
    /// Recommended: 27-32 for ~100 bits of security
    pub num_queries: usize,

    /// Blowup factor for LDE (Low-Degree Extension)
    /// Must be a power of 2. Higher = more security, larger proof.
    /// Recommended: 8-16
    pub blowup_factor: usize,

    /// Grinding factor for proof-of-work
    /// Higher = smaller proof, slower proving.
    /// Recommended: 16-20
    pub grinding_factor: u32,

    /// Field extension degree
    /// None (1) for base field, Quadratic (2) for extension
    pub field_extension: FieldExtension,

    /// FRI folding factor
    /// Higher = fewer FRI layers, larger queries
    /// Recommended: 8
    pub fri_folding_factor: usize,
}

impl Default for ProofOptions {
    fn default() -> Self {
        Self {
            num_queries: 28,
            blowup_factor: 8,
            grinding_factor: 16,
            field_extension: FieldExtension::None,
            fri_folding_factor: 8,
        }
    }
}

impl ProofOptions {
    /// Create options optimized for fast proving (lower security)
    pub fn fast() -> Self {
        Self {
            num_queries: 20,
            blowup_factor: 4,
            grinding_factor: 8,
            field_extension: FieldExtension::None,
            fri_folding_factor: 8,
        }
    }

    /// Create options optimized for security (~128 bits)
    pub fn secure() -> Self {
        Self {
            num_queries: 40,
            blowup_factor: 16,
            grinding_factor: 20,
            field_extension: FieldExtension::Quadratic,
            fri_folding_factor: 8,
        }
    }

    /// Estimate the security level in bits
    pub fn security_level(&self) -> usize {
        // Simplified security estimation based on FRI security analysis
        // query_security = num_queries * log2(blowup_factor)
        // grinding_factor adds that many bits via proof-of-work
        let query_security = self.num_queries * self.blowup_factor.ilog2() as usize;
        let grinding_security = self.grinding_factor as usize;

        // Extension field provides additional security against algebraic attacks
        let base_security = query_security + grinding_security;
        let extension_bonus = match self.field_extension {
            FieldExtension::None => 0,
            FieldExtension::Quadratic => 10, // ~10 bits bonus
            FieldExtension::Cubic => 20,     // ~20 bits bonus
        };

        base_security + extension_bonus
    }

    /// Convert to Winterfell ProofOptions
    pub fn to_winterfell(&self) -> winter_air::ProofOptions {
        winter_air::ProofOptions::new(
            self.num_queries,
            self.blowup_factor,
            self.grinding_factor,
            self.field_extension,
            self.fri_folding_factor,
            31, // FRI max remainder polynomial degree
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_options() {
        let opts = ProofOptions::default();
        assert!(opts.security_level() >= 80);
    }

    #[test]
    fn test_secure_options() {
        let opts = ProofOptions::secure();
        assert!(opts.security_level() >= 100);
    }

    #[test]
    fn test_to_winterfell() {
        let opts = ProofOptions::default();
        let winterfell_opts = opts.to_winterfell();
        assert_eq!(winterfell_opts.num_queries(), opts.num_queries);
    }
}
