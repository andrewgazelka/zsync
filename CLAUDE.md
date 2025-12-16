# zsync

## Serialization (CRITICAL)

**NEVER use JSON for binary data serialization. Use rkyv or raw bytes.**

This is a file sync tool where efficiency matters. JSON is:
- Slow to serialize/deserialize
- Bloated (text encoding of binary data)
- Wasteful over the wire

### Preferred Approaches (in order)

1. **rkyv** - Zero-copy deserialization, fastest option for structured data
   - Already used in `cache.rs` for LMDB storage
   - Use for any data stored on disk or sent over network

2. **Raw bytes** - For wire protocols where streaming/incremental parsing matters
   - Used in `protocol.rs` for the SSH transport layer
   - Manual `to_be_bytes()`/`from_be_bytes()` is fine here

3. **bincode** - If rkyv doesn't fit (rare)

### rkyv Reference

The rkyv source is cloned at `~/Projects/rkyv` for exploring implementation details.

### Example Pattern

```rust
// GOOD - rkyv for structured data
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct CachedData {
    chunks: Vec<Chunk>,
}

// Serialize
let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&data)?;

// Zero-copy deserialize
let archived = rkyv::access::<ArchivedCachedData, rkyv::rancor::Error>(&bytes)?;
```

### TODO: Migrate delta.rs

`delta.rs` currently uses `serde_json` for `Delta` and `Signature` compression. This should be migrated to rkyv. The `DeltaOp::Literal` uses `bytes::Bytes` which needs a wrapper for rkyv.
