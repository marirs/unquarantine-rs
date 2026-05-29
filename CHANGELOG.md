# Changelog

## 0.3.1

- Rust MSRV to 1.88
- CI Audit.yml

## 0.3.0

Dependency overhaul for crates.io publishability + security hardening.
Edition 2024, MSRV 1.85.

### Dependencies
- Replaced **rust-crypto** (unmaintained; RUSTSEC-2016-0005 / RUSTSEC-2022-0011)
  with the maintained **RustCrypto** stack (`blowfish` + `cipher`). Only Blowfish
  was ever used; RC4 remains hand-rolled.
- Replaced **inflate** (unmaintained) with **miniz_oxide** (maintained, pure-Rust
  raw-DEFLATE).
- Replaced the **ole** git dependency (which blocked `cargo publish`) with **cfb**,
  the maintained pure-Rust OLE2 / Compound-File reader on crates.io.
- Upgraded `base64` 0.13 → 0.22 (Engine API), `clap` 3 → 4 (`command`/`arg`
  attributes), `zip` 0.5 → 2, `crc` 2 → 3, `thiserror` 1 → 2.
- Dropped `maplit` (unused) and `lazy_static` (replaced by `std::sync::LazyLock`
  and `const` slices).

### Fixes (correctness)
- **`blowfishit`** previously wrote into an empty buffer and always returned an
  empty `Vec`; Blowfish-based vendors (Symantec ccSubSDK / QBI, Panda) never
  decrypted. Now performs real ECB block decryption.
- **Symantec `idx_unquarantine`** looped forever (input slice was never advanced);
  it now advances past each record and terminates.

### Fixes (correctness, cont.)
- Microsoft Defender PC: a fully-decoded `0B AD` content file is now labelled
  "Microsoft Windows Defender (PC)"; only the `D3 45` metadata-only header keeps
  the "partially supported" label (was mislabelling decoded content as partial).

### Thread-safety
- `UnQuarantine` is `Send + Sync` and the whole API is reentrant (free functions
  over `&[u8]`, no shared mutable state). Enforced with a compile-time
  `assert_send_sync` and a concurrent-decode test.

### Fixes (robustness / security)
- Every fixed-offset slice and length-prefixed field across all ~40 vendor
  parsers is now bounds-checked; malformed or truncated input returns an `Error`
  instead of panicking. New `Error::Truncated` / `Error::Invalid` variants.
- `unpack_i16/i32/i64` no longer panic on short input.
- **Decompression-bomb cap:** raw inflate (Baidu/Lumension/Panda) is now bounded
  to 512 MiB via `decompress_to_vec_with_limit` (previously only zip extraction
  was capped).
- **Integer-overflow hardening:** length/offset fields are read as unsigned and
  combined with checked/`i64` arithmetic (G-Data, Baidu, MS Defender, TrendMicro,
  Kaspersky), so crafted files can no longer trigger an add/`+=` overflow panic
  (debug) or silent wrap (release).
- Decompression and zip extraction are capped per entry (512 MiB) to bound
  zip-bomb inputs; encrypted-zip handling no longer `unwrap()`s.
- Integer subtractions that could underflow/overflow (BitDefender, ESET, Kaspersky,
  MS Defender, Symantec, TrendMicro) are now checked or wrapping.

### API
- Added `UnQuarantine::from_bytes(&[u8])` for in-memory input (content/magic-based
  detection). McAfee BUP now works from a buffer via an in-memory Compound File.
- **Breaking:** `get_unquarantined_buffer()` now returns `&[Vec<u8>]` (borrow) instead
  of cloning the whole `Vec<Vec<u8>>` on every call. Added
  `into_unquarantined_buffer(self) -> Vec<Vec<u8>>` to move the bytes out.
- Dropped the unused `'a` lifetime parameter from `UnQuarantine`.

### Vendors
- Added **FortiClient** (`QUARF\0\0\0` magic; payload XOR-0xAB, plus the full
  metadata sidecar — SHA-256, timestamp, file id, original filename, threat
  name — as a second buffer), the only vendor
  DeXRAY supports that was previously missing.

### Allocation / zero-copy
- Zip- and OLE-based vendors (CMC, Panda, Symantec qtn, generic zip, McAfee) now
  parse straight from a borrowed `Cursor<&[u8]>` instead of copying the whole input
  into an owned buffer first. (Decryption output is necessarily owned — XOR/RC4/
  Blowfish/inflate all produce new bytes — so only input handling is zero-copy.)

### Packaging / CLI
- `clap` is now an **optional** dependency behind a `cli` feature; the library no
  longer pulls it in. The `unquarantine` binary (`required-features = ["cli"]`)
  replaces the old example: it prints the detected vendor per file and writes each
  restored item with a **trailing `_`** (`<name>.NN_`) so a restored sample cannot
  be executed by an accidental double-click.
- `zip` switched to `default-features = false, features = ["deflate"]` to stay
  pure-Rust (drops `bzip2-sys`/`zstd-sys`/`lzma`).
- Added GitHub Actions CI (fmt + clippy `-D warnings` + build + test, all-features)
  and a Release workflow that builds the CLI for Linux/macOS (x86_64 + arm64) and
  Windows x86_64 and attaches archives to the tag. No `cargo publish` in CI.
