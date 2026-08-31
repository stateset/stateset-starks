**Title:** `ByteReader::read_many` allocates `with_capacity` from an unchecked length prefix (process abort on malformed input)

**Affects:** winter-utils 0.10.2 through current (`src/serde/byte_reader.rs`,
provided method `read_many`), reachable via `Proof::from_bytes`.

**Summary**

```rust
fn read_many<D>(&mut self, num_elements: usize) -> Result<Vec<D>, DeserializationError> {
    let mut result = Vec::with_capacity(num_elements);
```

`num_elements` comes from `read_usize()` on the input and is never compared to
the bytes remaining. A 39-byte proof can declare 2^56 elements; the resulting
request (~72 PB) fails allocation, and Rust's `handle_alloc_error` **aborts**
the process rather than returning an error. `catch_unwind` cannot contain it.
For any service that verifies proofs from untrusted parties this is a one-request
denial of service.

**Reproduce**

```rust
let bytes = [246u8, 3, 39, 3, 0, 0, 1, 168, 1, 4, 1, 1, 8, 1, 3, 3, 39, 3, 0, 0, 1,
             246, 3, 39, 3, 0, 0, 1, 246, 3, 39, 3, 0, 0, 1, 168, 1, 4, 1];
let _ = winter_air::proof::Proof::from_bytes(&bytes); // SIGABRT: memory allocation of 72057607577400833 bytes failed
```

**Suggested fix**

Every element consumes at least one byte, so in `read_many`:

```rust
if num_elements > self.remaining() {   // or via check_eor(num_elements)
    return Err(DeserializationError::InvalidValue(..));
}
```

Also worth making `SliceReader::check_eor` use `checked_add`; `self.pos + num_bytes`
can wrap for adversarial `num_bytes`.
