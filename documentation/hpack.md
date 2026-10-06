# What the HPACK codec enforces of RFC 7541

**Status:** describes what shipped (version 0.0.0).

`ghttp_hpack_*` (`include/ghoti.io/http/hpack.h`) is header compression for
HTTP/2, RFC 7541: a decoder and an encoder, each owning a dynamic table, with
every unbounded quantity capped by `GHTTP_HpackLimits`. The Huffman code and the
integer coding are in an internal unit (`coding.c`) that a later QPACK codec
will share. The static table and the Huffman code are generated from the RFC's
text (`tools/hpack/gen_tables.py`), and `make check-hpack-tables` fails if the
committed file is not what the generator produces from the pinned RFC;
`tools/check-defects.sh` shows it fail. Each rule below is tested; the test
names in `tests/unit/test_hpack.cpp` are sentences.

Any decoding failure is `GHTTP_ERR_CORRUPT` (RFC 9113 calls it a connection
error of type COMPRESSION_ERROR) and the decoder stays failed, because the two
tables can no longer be known to agree. A limit is `GHTTP_ERR_LIMIT`.

## Decoder: enforced

- **Integers (section 5.1):** the prefix width of each representation; a
  continuation that does not end, a value above 2^31 - 1, and an encoding with
  more than five continuation octets are refused (`GHTTP_ERR_CORRUPT`). Zero
  padding within those five octets is accepted, as the RFC allows; the
  encoding need not be canonical.
- **Strings (section 5.2):** a length that runs past the block is refused. A
  Huffman string is refused when its padding is longer than seven bits, when the
  padding is not the most significant bits of EOS, and when it contains EOS. The
  expansion is capped as it is produced, so a Huffman bomb stops at
  `max_field_bytes` and not at its expansion.
- **Indexing (section 2.3):** index 0 and an index past the dynamic table are
  refused.
- **The dynamic table (section 4):** entries cost name + value + 32; the oldest
  are evicted first; an entry larger than the table empties it and is not added.
  A literal whose name refers to an entry that its own insertion evicts still
  decodes.
- **Table size updates (section 6.3):** valid only at the start of a block, and
  not above the cap. The cap is the larger of `max_table_size` and the protocol
  default of 4096 until the peer is known to have seen our smaller maximum: the
  decoder starts at 4096 because the peer may use that until our SETTINGS is
  acknowledged, and `ghttp_hpack_decoder_set_max_table_size()` is called when it
  is. After the maximum is lowered, the next block must open with an update
  (section 4.2), and a block that does not is refused.
- **Limits:** the header list (the sum of name + value + 32, the measure of RFC
  9113 section 6.5.2), the number of fields, and one name or value. The list
  limit is applied as fields are decoded, so an indexed bomb (a few octets that
  each name a large entry) stops at the limit.

## Encoder: what it promises

- Output the decoder above accepts, and byte for byte the RFC 7541 Appendix C
  examples under `GHTTP_HPACK_INDEX_AUTO` (the one policy that indexes
  everything, for examples and tests).
- `GHTTP_HPACK_INDEX_SAFE`, which `ghttp_hpack_encode()` uses, never indexes
  `authorization`, `proxy-authorization`, `cookie` or `set-cookie`: such
  fields are sent as never-indexed literals (section 7.1) so
  that an intermediary cannot learn them by guessing at a shared table.
- The peer's table size is honoured and capped at the encoder's own limit. A
  change is announced at the start of the next block: the smallest size
  reached, then the final one when they differ (section 4.2). A change back to
  the current size with nothing in between says nothing. An encoder capped
  below the table the peer is assumed to hold announces the cap in its first
  block.
- Huffman coding is used unless it is longer (`GHTTP_HPACK_HUFFMAN_AUTO`).
- A failed `ghttp_hpack_encode()` restores the output buffer it was appending
  to, and an allocator failing at any point is `GHTTP_ERR_OOM` and never a leak.
  The encoder's table cannot be restored, though: a failure after the first
  field leaves the encoder **failed for good** (every later call returns the
  error), because the fields already encoded are in its table, and the pending
  size update was in the block thrown away, so the peer's decoder would
  disagree. A failure before anything changed (the first field's pending update
  could not be written) leaves it usable and the update still pending.

## Not enforced, or not provided

- **No decision about what to index** beyond the policy chosen; there is no
  heuristic about entry reuse.
- **No encoder-side header-list limit.** The caller bounds what it encodes; the
  HTTP/2 connection checks a peer's `SETTINGS_MAX_HEADER_LIST_SIZE` before
  encoding.
- **Not a QPACK.** Only the shared Huffman and integer units are common.
