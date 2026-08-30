//! Shared helper for targets that fuzz a *guarded* trust boundary.
//!
//! # Why this exists
//!
//! `libfuzzer-sys` installs a panic hook that calls `abort()` *before*
//! unwinding, so libFuzzer can capture a clean stack. That is the right default,
//! but it makes any panic look fatal — including one the library under test
//! deliberately catches.
//!
//! The verifiers here do catch one: `winter-air`'s `TraceInfo::read_from`
//! validates only the lower bound of the log2 trace-length byte and then
//! evaluates `2_usize.pow(n)` for an `n` read straight from the input, so any
//! byte >= 64 overflows (winter-air 0.10.3, `src/air/trace_info.rs:311`). The
//! stateset verifiers wrap deserialization in
//! `ves_stark_primitives::panic_guard::guard_untrusted` and return
//! `DeserializationError` instead.
//!
//! With libfuzzer's hook in place the process aborts before that guard can run,
//! so the fuzzer reports a crash for input the library handles correctly.
//!
//! # What is still tested
//!
//! The property that matters is *"no panic escapes the library to its caller"*,
//! not *"no panic occurs anywhere inside it"*. [`assert_no_panic_escapes`]
//! checks exactly that: it silences the hook so internal guards work, runs the
//! call, and aborts — giving libFuzzer its crash signal — only if a panic makes
//! it out. A genuine unguarded panic is still a reported crash.

use std::panic::{self, AssertUnwindSafe};
use std::sync::Once;

static SILENCE_HOOK: Once = Once::new();

/// Run `f`, aborting the process if a panic escapes it.
///
/// Returns `f`'s value when it completes normally.
pub fn assert_no_panic_escapes<T, F: FnOnce() -> T>(f: F) -> T {
    // Replace libfuzzer's abort-on-panic hook once per process, so the
    // library's own `catch_unwind` guards get a chance to run. Silent because a
    // guarded panic is expected here and printing it for every input would bury
    // real findings.
    SILENCE_HOOK.call_once(|| {
        panic::set_hook(Box::new(|_| {}));
    });

    match panic::catch_unwind(AssertUnwindSafe(f)) {
        Ok(value) => value,
        Err(_) => {
            // A panic reached the caller: the library failed its contract.
            // Abort so libFuzzer records this as a crash, and restore the
            // default hook first so the message is visible.
            let _ = panic::take_hook();
            eprintln!(
                "FUZZ FAILURE: a panic escaped the library boundary. \
                 The untrusted-input surface must return Ok/Err, never unwind."
            );
            std::process::abort();
        }
    }
}
