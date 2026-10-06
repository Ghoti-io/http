# Development

## Layout

```
include/ghoti.io/http/   Public headers
src/core/                Result strings, limits default, the allocator
src/http/                Headers, request and response, parser, writer, shared checks
tests/unit/              Unit tests (gtest)
tests/fuzz/              libFuzzer harnesses and seed corpus
tools/check-defects.sh   The planted-defect gate
examples/echo.c          A request parsed three bytes at a time, answered by the writer
```

## One predicate, written once

What counts as a token, a legal field value or target, how a header list frames
a body, and whether a head is acceptable are decided once, in
`src/http/util.c`, and used by the parser and the writer alike
(`ghttp_request_validate`, `ghttp_response_validate`,
`ghttp_framing_from_headers`). The writer refuses what the parser would refuse
because it asks the same functions, not because two lists agree today.

## The parser does not look at how input is split

A head or trailer section is gathered one byte at a time, judged byte by byte
(bare LF, bare CR, NUL, line length, total size) and parsed whole once its empty
line arrives. A chunk-size line is a state machine over single bytes. A body is
passed through as slices of the caller's input. Nothing consults the length of a
call, which is why `tests/unit/test_split.cpp` can cut every fixture at every
byte boundary and expect one answer.

## Gates

- `check-defects` copies the tree, plants one defect per run by an exact textual
  edit (checked to have changed the file), and requires the tests named for it
  to fail. A control run of the unpatched copy must pass first. Add a defect by
  adding a `plant` call; run only the one executable that holds its test.
- Two harnesses fuzz: `fuzz_parse` (split independence, limits, allocation
  failure) and `fuzz_roundtrip` (parse, write, parse).
