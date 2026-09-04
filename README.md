<p align="center">
  <img src="logo.svg" alt="CAT for MOQ Logo" width="240">
</p>


**Linux** [![Ubuntu](https://github.com/Quicr/cat-token/actions/workflows/ci.yml/badge.svg?branch=main&event=push)](https://github.com/Quicr/cat-token/actions/workflows/ci.yml?query=branch%3Amain+os%3Aubuntu-latest) | **macOS** [![macOS](https://github.com/Quicr/cat-token/actions/workflows/ci.yml/badge.svg?branch=main&event=push)](https://github.com/Quicr/cat-token/actions/workflows/ci.yml?query=branch%3Amain+os%3Amacos-latest) | **Windows** [![Windows](https://github.com/Quicr/cat-token/actions/workflows/ci.yml/badge.svg?branch=main&event=push)](https://github.com/Quicr/cat-token/actions/workflows/ci.yml?query=branch%3Amain+os%3Awindows-latest) | [![License](https://img.shields.io/badge/License-BSD_2--Clause-blue.svg)](https://opensource.org/licenses/BSD-2-Clause)

Rust implementation of [Common Access Token for Media Over QUIC Transport (CAT-4-MOQT)](https://github.com/moq-wg/CAT-4-MOQT) based on [CTA-5007-B](https://shop.cta.tech/products/common-access-token).

## Installation

```bash
cargo add cat-token
```

## Features

- Full CTA-5007-B CAT token support with CBOR/CWT encoding
- MOQT-specific claims: namespace/track authorization with binary matching
- DPoP (Demonstrating Proof-of-Possession) support per RFC 9449
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

# Generate test vectors
cargo run --bin generate-test-vectors
```

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

Full compliance with CTA-5007-B and all referenced standards. See [`docs/std-compliance-req.md`](docs/std-compliance-req.md) for the detailed compliance matrix.

## License

BSD-2-Clause
