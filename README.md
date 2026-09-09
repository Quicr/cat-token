<p align="center">
  <img src="logo.svg" alt="CAT for MOQ Logo" width="240">
</p>


**Linux** [![Ubuntu](https://github.com/Quicr/cat-token/actions/workflows/ci.yml/badge.svg?branch=main&event=push)](https://github.com/Quicr/cat-token/actions/workflows/ci.yml?query=branch%3Amain+os%3Aubuntu-latest) | **macOS** [![macOS](https://github.com/Quicr/cat-token/actions/workflows/ci.yml/badge.svg?branch=main&event=push)](https://github.com/Quicr/cat-token/actions/workflows/ci.yml?query=branch%3Amain+os%3Amacos-latest) | **Windows** [![Windows](https://github.com/Quicr/cat-token/actions/workflows/ci.yml/badge.svg?branch=main&event=push)](https://github.com/Quicr/cat-token/actions/workflows/ci.yml?query=branch%3Amain+os%3Awindows-latest) | [![License](https://img.shields.io/badge/License-BSD_2--Clause-blue.svg)](https://opensource.org/licenses/BSD-2-Clause)

Rust implementation of a **strict, fail-closed profile** of
[Common Access Token for Media Over QUIC Transport (CAT-4-MOQT)](https://github.com/moq-wg/CAT-4-MOQT)
built on [CTA-5007-B](https://shop.cta.tech/products/common-access-token).
This is not a full CTA-5007-B recipient: anywhere the base spec allows
multiple encodings of the same semantic content, this crate accepts one
form and rejects the rest. See [docs/PROFILE.md](docs/PROFILE.md) for the
supported-form matrix, the authorization contract, and interoperability
non-goals.

## Installation

```bash
cargo add cat-token
```

## Features

- Strict narrow-profile CAT recipient over CBOR/CWT (single-form parser, fail-closed authorization; see [docs/PROFILE.md](docs/PROFILE.md))
- MOQT-specific claims: namespace/track authorization with binary matching
- DPoP (Demonstrating Proof-of-Possession) — CWT profile (draft-nandakumar-moq-generic-dpop-proof-00) and RFC 9449 JWT compact form
- Cryptographic algorithms: HMAC-SHA256, ES256, PS256
- COSE_Encrypt0 encryption (AES-128-GCM, AES-256-GCM)
- URI and header matching with exact, prefix, suffix, contains, regex (POSIX ERE), SHA-256, and SHA-512/256 match types
- Geographic claims: coordinates (catgeocoord), geohash, altitude, ISO 3166 region codes
- Network claims: IPv4/IPv6 addresses and prefixes (RFC 9164), ASN
- X.509 certificate chain matching (cattpk)
- Composite claims: OR, NOR, AND operators with depth-limited evaluation
- Token revalidation and renewal (catr) support
- RFC 8941 Structured Field Values parsing for header matching
- Deterministic CBOR encoding with map key ordering validation
- Bounded resource usage: LRU caches, regex size limits, token size limits
- Key zeroization on drop for sensitive material

## Build

```bash
# Build with MOQT support (default)
cargo build --release

# Build without MOQT (generic CAT only)
cargo build --release --no-default-features --features builtin-trie
```

## Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `moqt` | Yes | MOQT-specific claims, scopes, and DPoP validation |
| `builtin-trie` | Yes | Built-in trie for URI pattern matching |
| `qp-trie` | No | Use qp-trie crate instead of built-in trie |

For generic CAT tokens without MOQT, disable the `moqt` feature. See [`examples/generic_cat.rs`](examples/generic_cat.rs) for usage.

## Test

```bash
# All tests
cargo test --all-features

# Single test by name
cargo test test_dpop_validation --all-features

# Single test file
cargo test --test test_composite_claims --all-features
```

## Benchmark

```bash
# All benchmarks
cargo bench --all-features

# Individual benchmarks
cargo bench --bench crypto_bench --all-features
cargo bench --bench token_bench --all-features
cargo bench --bench cbor_bench --all-features
cargo bench --bench trie_bench --all-features
```

## Examples

```bash
cargo run --example quickstart
cargo run --example generic_cat
cargo run --example server_token_issuer
cargo run --example relay_validator --features moqt
```

## CLI

```bash
# Generate MOQT tokens
cargo run --bin cat-cli -- moqt-token --key private.pem --endpoint relay.example.com
```

## Test vectors

`cat-token` owns the reference vectors for `draft-ietf-moq-c4m`
Appendix A. The `generate-test-vectors` binary drives three modes,
all backed by the same deterministic generator:

```bash
# Emit JSON fixtures (default). Writes tests/test_data/*.json.
cargo run --bin generate-test-vectors --features moqt

# Emit an Appendix-A-shaped markdown block that can be pasted
# verbatim into draft-ietf-moq-c4m.md. Hex fields stay on a single
# line so the draft cannot introduce mid-hex whitespace on paste.
cargo run --bin generate-test-vectors --features moqt -- --emit draft-md

# Verify that the draft's embedded vectors still match cat.rs.
# Default source is https://raw.githubusercontent.com/moq-wg/CAT-4-MOQT/main/draft-ietf-moq-c4m.md.
cargo run --bin generate-test-vectors --features moqt -- --verify
cargo run --bin generate-test-vectors --features moqt -- --verify --from-file /path/to/draft.md
```

CI runs the emitter as a strict self-check on every push, plus an
advisory drift check against the live draft `main`. See
[`docs/TEST-VECTORS.md`](docs/TEST-VECTORS.md) for the full workflow,
determinism guarantees, exit-code semantics, and the list of
recognised vector categories.

## Quick Start

```rust
use cat_token::*;
use cat_token::moqt::{MoqtValidator, MoqtAuthRequest, MoqtScopeBuilder, roles};
use chrono::{Duration, Utc};

// Create a publisher token for live streaming
let scope = MoqtScopeBuilder::new()
    .publisher()
    .namespace_exact(b"cdn.example.com")
    .track_prefix(b"/live/")
    .build();

let token = CatTokenBuilder::new()
    .issuer("https://auth.example.com")
    .audience(vec!["relay.example.com".to_string()])
    .expires_at(Utc::now() + Duration::hours(1))
    .moqt_scope(scope)
    .moqt_reval(300.0)  // 5-minute revalidation
    .build();

// Validate authorization
let validator = MoqtValidator::new();
let request = MoqtAuthRequest::new(
    MoqtAction::Publish,
    vec![b"cdn.example.com".to_vec(), b"live-stream-42".to_vec()],
    b"/video".to_vec(),
);

let result = validator.authorize(&token, &request);
assert!(result.authorized);
```

## Predefined Roles

```rust
// Publisher: PublishNamespace, Publish
let pub_scope = roles::publisher(b"example.com", b"/live/");

// Subscriber: SubscribeNamespace, Subscribe, Fetch  
let sub_scope = roles::subscriber(b"example.com", b"/vod/");

// Admin: all actions
let admin_scope = roles::admin(b"example.com");

// Read-only: Subscribe, Fetch only
let ro_scope = roles::read_only(b"example.com", b"/archive/");
```

## Standards Compliance

This crate implements a **narrow, deterministic, fail-closed profile** of
CTA-5007-B. It is not a full CTA-5007-B recipient: anywhere the base spec
allows multiple representational forms for the same semantic content, this
crate accepts exactly one form and rejects the rest. See
[`docs/PROFILE.md`](docs/PROFILE.md) for the supported-forms matrix and
per-claim rules.

Note also that:

- `cattpk` is a *pin* post-check that runs after a caller-supplied
  `PathValidator` has authenticated the peer certificate. The crate does not
  implement RFC 5280 path validation; deploy it downstream of a real
  X.509 path validator.
- Distributed replay coherence is out of scope. The bundled `ReplayGuard`
  implementation is in-memory only; production deployments must supply a
  distributed backend behind the `ReplayGuard` trait.

## License

BSD-2-Clause
