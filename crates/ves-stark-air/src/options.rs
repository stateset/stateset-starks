//! Proof Options Configuration
//!
//! Configurable parameters for STARK proof generation that affect
//! security level, proof size, and proving/verification time.
//!
//! # Security model
//!
//! Conjectured soundness of a FRI-based STARK is the **minimum** of two
//! independent bounds, not the sum:
//!
//! 1. **Query soundness** — `num_queries * log2(blowup_factor) + grinding_factor`.
//!    Each query tests a random position of the low-degree extension; grinding
//!    adds proof-of-work bits.
//!
//! 2. **Algebraic soundness** — the DEEP out-of-domain sampling and the FRI
//!    batching/folding challenges are drawn from the *challenge field*. A
//!    cheating prover wins if a challenge happens to be a root of a polynomial
//!    of degree `MAX_CONSTRAINT_DEGREE * trace_length`, so the error is about
//!    `(deg * n) / |F_ext|`, giving `log2(|F_ext|) - log2(deg * n)` bits.
//!
//! This distinction matters here because the base field is Goldilocks
//! (`p = 2^64 - 2^32 + 1`). Over the **bare base field** the algebraic term
//! caps soundness at roughly `64 - log2(deg * n)` — about 40 bits for a 2^20
//! trace — no matter how many queries are used. A field extension is therefore
//! not a small additive bonus: it is what raises that ceiling at all, by
//! `log2(p)` bits per degree. Every preset in this module consequently uses an
//! extension field, and [`ProofOptions::conjectured_security_level`] reports
//! the min of the two bounds rather than their sum.

use thiserror::Error;
use winter_air::FieldExtension;

/// Bits in the Goldilocks base field modulus (`p = 2^64 - 2^32 + 1`).
pub const BASE_FIELD_BITS: usize = 64;

/// Highest transition-constraint degree across the AIRs in this workspace
/// (Rescue `pow7` gated by full-trace-length periodic selectors). It sets how
/// far the composition polynomial's degree exceeds the trace length, and with
/// it the algebraic soundness error.
pub const MAX_CONSTRAINT_DEGREE: usize = 10;

/// Trace length assumed by [`ProofOptions::security_level`] when the caller does
/// not supply one. Chosen as an upper bound on the traces this workspace
/// produces so the no-argument estimate errs low rather than overstating.
/// Callers that know their trace length should use
/// [`ProofOptions::conjectured_security_level`] instead.
pub const ASSUMED_MAX_TRACE_LENGTH: usize = 1 << 20;

/// Security floor, in bits, that every preset shipped from this module must
/// clear. Enforced by unit test.
pub const MIN_ACCEPTABLE_SECURITY_BITS: usize = 100;

/// Errors that can occur when validating proof options
#[derive(Debug, Error)]
pub enum OptionsError {
    /// `num_queries` was zero, which proves nothing.
    #[error("num_queries must be greater than zero")]
    InvalidNumQueries,
    /// `blowup_factor` was not a power of two, or was below 2.
    #[error("blowup_factor must be a power of two >= 2, got {0}")]
    InvalidBlowupFactor(usize),
    /// `blowup_factor` cannot accommodate the AIR's maximum constraint degree.
    #[error("blowup_factor too small for current AIR: need >= {min_required}, got {actual}")]
    BlowupFactorTooSmall {
        /// Smallest blowup the current constraint degrees permit.
        min_required: usize,
        /// Blowup that was requested.
        actual: usize,
    },
    /// `fri_folding_factor` was not a power of two, or was below 2.
    #[error("fri_folding_factor must be a power of two >= 2, got {0}")]
    InvalidFriFoldingFactor(usize),
}

/// Options for proof generation
#[derive(Debug, Clone)]
pub struct ProofOptions {
    /// Number of FRI queries (higher = more security, slower verification).
    ///
    /// Contributes `num_queries * log2(blowup_factor)` bits of *query*
    /// soundness. This is only half the picture — the result is capped by the
    /// algebraic bound, so raising this past the cap buys nothing. See the
    /// module-level security model.
    pub num_queries: usize,

    /// Blowup factor for LDE (Low-Degree Extension)
    /// Must be a power of 2. Higher = more security, larger proof.
    /// Recommended: 8-16
    pub blowup_factor: usize,

    /// Grinding factor for proof-of-work
    /// Higher = smaller proof, slower proving.
    /// Recommended: 16-20
    pub grinding_factor: u32,

    /// Field extension degree for challenge sampling.
    ///
    /// This is the single most important security parameter here, because it
    /// sets the algebraic soundness ceiling at `log2(p) * degree - log2(deg*n)`.
    /// Over the bare base field (`None`) that ceiling is ~40 bits for a 2^20
    /// trace regardless of query count, so `None` is not a usable production
    /// setting for this 64-bit field. Quadratic gives ~104 bits, Cubic ~168.
    pub field_extension: FieldExtension,

    /// FRI folding factor
    /// Higher = fewer FRI layers, larger queries
    /// Recommended: 8
    pub fri_folding_factor: usize,
}

impl Default for ProofOptions {
    /// Secure-by-default: ~104 conjectured bits.
    ///
    /// This is what an integrator gets without reading any documentation, so it
    /// is a defensible production setting rather than a fast one. The quadratic
    /// extension is what makes that possible: query parameters are chosen to sit
    /// just above the ~104-bit algebraic ceiling it provides, so neither bound
    /// is wasted.
    fn default() -> Self {
        Self {
            num_queries: 24,
            blowup_factor: 16,
            grinding_factor: 16,
            field_extension: FieldExtension::Quadratic,
            fri_folding_factor: 16,
        }
    }
}

impl ProofOptions {
    /// Options optimized for proving speed: ~80 conjectured bits.
    ///
    /// **Development and testing only.** Below
    /// [`MIN_ACCEPTABLE_SECURITY_BITS`]; do not use to produce proofs that will
    /// be anchored or relied upon. It still uses a quadratic extension, because
    /// dropping to the bare base field would cap soundness near 40 bits — that
    /// is not a speed/security trade, it is a broken configuration.
    pub fn fast() -> Self {
        Self {
            num_queries: 18,
            // The batch AIR uses degree-10 constraints (Rescue pow7 × selectors with
            // full-trace periodic columns), requiring a minimum blowup factor of 16.
            blowup_factor: 16,
            grinding_factor: 8,
            field_extension: FieldExtension::Quadratic,
            fri_folding_factor: 8,
        }
    }

    /// Options optimized for security: ~168 conjectured bits.
    ///
    /// Uses a cubic extension. A quadratic extension caps at ~104 bits, which
    /// cannot honestly be called a 128-bit setting for a 2^20 trace, so the
    /// cubic extension is what actually buys the headroom.
    pub fn secure() -> Self {
        Self {
            num_queries: 40,
            blowup_factor: 16,
            grinding_factor: 20,
            field_extension: FieldExtension::Cubic,
            fri_folding_factor: 8,
        }
    }

    /// Validate proof options for internal consistency
    pub fn validate(&self) -> Result<(), OptionsError> {
        if self.num_queries == 0 {
            return Err(OptionsError::InvalidNumQueries);
        }
        if self.blowup_factor < 2 || !self.blowup_factor.is_power_of_two() {
            return Err(OptionsError::InvalidBlowupFactor(self.blowup_factor));
        }
        // The batch AIR includes degree-10 constraints (Rescue pow7 × selectors with full-trace
        // periodic columns), requiring a minimum blowup factor of 16 in Winterfell. Smaller values
        // cause assertion failures in the prover.
        const MIN_REQUIRED_BLOWUP: usize = 16;
        if self.blowup_factor < MIN_REQUIRED_BLOWUP {
            return Err(OptionsError::BlowupFactorTooSmall {
                min_required: MIN_REQUIRED_BLOWUP,
                actual: self.blowup_factor,
            });
        }
        if self.fri_folding_factor < 2 || !self.fri_folding_factor.is_power_of_two() {
            return Err(OptionsError::InvalidFriFoldingFactor(
                self.fri_folding_factor,
            ));
        }
        Ok(())
    }

    /// Degree of the challenge field over the base field (1, 2, or 3).
    fn extension_degree(&self) -> usize {
        match self.field_extension {
            FieldExtension::None => 1,
            FieldExtension::Quadratic => 2,
            FieldExtension::Cubic => 3,
        }
    }

    /// Query-soundness bound, in bits: `num_queries * log2(blowup) + grinding`.
    ///
    /// This is only one of the two bounds; see
    /// [`Self::conjectured_security_level`].
    pub fn query_security_bits(&self) -> usize {
        self.num_queries * self.blowup_factor.ilog2() as usize + self.grinding_factor as usize
    }

    /// Algebraic-soundness ceiling, in bits, for a trace of `trace_length` rows:
    /// `log2(|F_ext|) - ceil(log2(MAX_CONSTRAINT_DEGREE * trace_length))`.
    ///
    /// No number of queries can raise this. It is the term that binds over a
    /// 64-bit base field, and the reason every preset uses an extension.
    pub fn algebraic_security_bits(&self, trace_length: usize) -> usize {
        let challenge_field_bits = BASE_FIELD_BITS * self.extension_degree();
        // ceil(log2(deg * n)), computed in u128 so the product cannot wrap.
        let domain = (MAX_CONSTRAINT_DEGREE as u128) * (trace_length.max(2) as u128);
        let domain_bits = 128 - (domain - 1).leading_zeros() as usize;
        challenge_field_bits.saturating_sub(domain_bits)
    }

    /// Conjectured security level in bits for a trace of `trace_length` rows.
    ///
    /// The **minimum** of the query bound and the algebraic bound — a proof is
    /// only as sound as its weakest term, so these do not add.
    pub fn conjectured_security_level(&self, trace_length: usize) -> Result<usize, OptionsError> {
        self.validate()?;
        Ok(self
            .query_security_bits()
            .min(self.algebraic_security_bits(trace_length)))
    }

    /// Estimate the security level in bits, assuming the largest trace this
    /// workspace produces ([`ASSUMED_MAX_TRACE_LENGTH`]).
    ///
    /// Prefer [`Self::conjectured_security_level`] when the trace length is
    /// known: shorter traces are strictly sounder.
    pub fn security_level(&self) -> usize {
        self.try_security_level().unwrap_or(0)
    }

    /// Fallible form of [`Self::security_level`].
    pub fn try_security_level(&self) -> Result<usize, OptionsError> {
        self.conjectured_security_level(ASSUMED_MAX_TRACE_LENGTH)
    }

    /// Convert to Winterfell ProofOptions
    pub fn to_winterfell(&self) -> winter_air::ProofOptions {
        self.try_to_winterfell()
            .expect("invalid proof options; use try_to_winterfell() to handle this error")
    }

    /// Convert to Winterfell ProofOptions without panicking
    pub fn try_to_winterfell(&self) -> Result<winter_air::ProofOptions, OptionsError> {
        self.validate()?;
        Ok(winter_air::ProofOptions::new(
            self.num_queries,
            self.blowup_factor,
            self.grinding_factor,
            self.field_extension,
            self.fri_folding_factor,
            15, // FRI max remainder polynomial degree (smaller = more FRI layers but smaller proof)
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_options() {
        let opts = ProofOptions::default();
        assert!(opts.try_security_level().unwrap() >= MIN_ACCEPTABLE_SECURITY_BITS);
    }

    #[test]
    fn test_secure_options() {
        let opts = ProofOptions::secure();
        assert!(opts.try_security_level().unwrap() >= 128);
    }

    /// The dominant soundness term for a 64-bit base field is the algebraic
    /// (DEEP/OOD + FRI batching) error, which is bounded by the size of the
    /// field the *challenges* are drawn from — not by the number of queries.
    /// Piling on queries over the base field cannot buy security it does not
    /// have; an estimator that ignores this overstates the real level.
    #[test]
    fn test_security_is_capped_by_challenge_field_not_query_count() {
        let absurd = ProofOptions {
            num_queries: 1000,
            blowup_factor: 16,
            grinding_factor: 32,
            field_extension: FieldExtension::None,
            fri_folding_factor: 8,
        };
        // Query security alone would claim 1000*4 + 32 = 4032 bits.
        let reported = absurd.try_security_level().unwrap();
        assert!(
            reported <= 64,
            "base-field security must never exceed log2(|F|) = 64, got {reported}"
        );
        assert!(
            reported < 4032,
            "estimator must not report raw query security, got {reported}"
        );
    }

    /// An extension field does not add a flat bonus on top of query security —
    /// it raises the ceiling that the algebraic error imposes. Each extension
    /// degree must move the cap by roughly log2(p) = 64 bits, not by 10 or 20.
    #[test]
    fn test_extension_field_raises_the_cap_it_is_not_an_additive_bonus() {
        let mk = |ext| ProofOptions {
            num_queries: 1000,
            blowup_factor: 16,
            grinding_factor: 32,
            field_extension: ext,
            fri_folding_factor: 8,
        };
        // With query security effectively unbounded, the reported level *is* the cap.
        let none = mk(FieldExtension::None).try_security_level().unwrap();
        let quad = mk(FieldExtension::Quadratic).try_security_level().unwrap();
        let cubic = mk(FieldExtension::Cubic).try_security_level().unwrap();

        assert!(quad > none && cubic > quad, "caps must be strictly ordered");
        // Not the old flat +10 / +20 model.
        assert!(
            quad - none > 40,
            "quadratic must roughly double the cap, gained only {} bits",
            quad - none
        );
        assert!(
            cubic - quad > 40,
            "cubic must add another field's worth, gained only {} bits",
            cubic - quad
        );
    }

    /// The algebraic error grows with the size of the evaluation domain, so a
    /// longer trace means strictly less security for the same parameters.
    #[test]
    fn test_security_decreases_as_trace_grows() {
        let opts = ProofOptions::secure();
        let small = opts.conjectured_security_level(1 << 8).unwrap();
        let large = opts.conjectured_security_level(1 << 24).unwrap();
        assert!(
            large < small,
            "a 2^24 trace must not be as sound as a 2^8 trace ({large} vs {small})"
        );
    }

    /// Goldilocks is a 64-bit field. No configuration over the base field can
    /// reach a modern security target, so no preset may ship with one.
    #[test]
    fn test_no_preset_uses_the_bare_base_field() {
        for (name, opts) in [
            ("default", ProofOptions::default()),
            ("fast", ProofOptions::fast()),
            ("secure", ProofOptions::secure()),
        ] {
            assert!(
                !matches!(opts.field_extension, FieldExtension::None),
                "preset `{name}` uses the bare 64-bit base field, which caps \
                 soundness far below any usable target"
            );
        }
    }

    /// `default()` is what an integrator gets without reading any docs, so it
    /// must itself be a defensible production setting.
    #[test]
    fn test_default_is_secure_by_default() {
        let d = ProofOptions::default().try_security_level().unwrap();
        assert!(
            d >= MIN_ACCEPTABLE_SECURITY_BITS,
            "default preset reports {d} bits, below the {MIN_ACCEPTABLE_SECURITY_BITS}-bit floor"
        );
    }

    /// The estimate must be the *minimum* of the two independent bounds, so a
    /// deliberately query-starved config is still reported as weak even with a
    /// large challenge field.
    #[test]
    fn test_query_starved_config_is_still_reported_weak() {
        let starved = ProofOptions {
            num_queries: 4,
            blowup_factor: 16,
            grinding_factor: 0,
            field_extension: FieldExtension::Cubic,
            fri_folding_factor: 8,
        };
        assert_eq!(starved.try_security_level().unwrap(), 16);
    }

    #[test]
    fn test_to_winterfell() {
        let opts = ProofOptions::default();
        let winterfell_opts = opts.try_to_winterfell().unwrap();
        assert_eq!(winterfell_opts.num_queries(), opts.num_queries);
    }

    #[test]
    #[should_panic(expected = "invalid proof options")]
    fn test_to_winterfell_panics_on_invalid_options() {
        let opts = ProofOptions {
            blowup_factor: 3,
            ..ProofOptions::default()
        };
        let _ = opts.to_winterfell();
    }
}
