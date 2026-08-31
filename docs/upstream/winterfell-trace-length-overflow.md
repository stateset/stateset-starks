**Title:** `TraceInfo::read_from` overflows on an unchecked log2 trace-length byte

**Affects:** winter-air 0.10.3 through 0.13.1 (`src/air/trace_info.rs`, the
`read_from` impl).

**Summary**

`read_from` validates only the *lower* bound of the trace-length byte and then
computes `2_usize.pow(n)` for an `n` read directly from the input:

```rust
let trace_length = source.read_u8()?;
if trace_length < TraceInfo::MIN_TRACE_LENGTH.ilog2() as u8 { return Err(..) }
let trace_length = 2_usize.pow(trace_length as u32);   // n may be up to 255
```

There is no `MAX_TRACE_LENGTH` in the crate, so any byte >= 64 overflows.
Under `overflow-checks = true` this panics; under the default release setting it
wraps to 0 and is rejected later. Eleven bytes of input reach it through
`Proof::from_bytes`.

**Reproduce**

```rust
let bytes = [89u8, 4, 255, 98, 255, 255, 255, 255, 255, 255, 43];
let _ = winter_air::proof::Proof::from_bytes(&bytes); // panics with overflow-checks
```

**Suggested fix**

Add an upper bound before the `pow`, e.g. reject `trace_length > 63` (or a
documented `MAX_TRACE_LENGTH_LOG2`), returning `DeserializationError::InvalidValue`.
