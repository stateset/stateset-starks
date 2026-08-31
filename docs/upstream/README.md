# Upstream reports

Ready-to-file issue text for defects found in dependencies. Both below were found
by `fuzz_proof_deserialization` and are contained in this repo
(`panic_guard`, `bounded_reader`); filing them removes the need for every other
Winterfell consumer to rediscover them.

- `winterfell-trace-length-overflow.md` — `winter-air`, `TraceInfo::read_from`
- `winterfell-read-many-unbounded-alloc.md` — `winter-utils`, `ByteReader::read_many`

Target: https://github.com/facebook/winterfell/issues
