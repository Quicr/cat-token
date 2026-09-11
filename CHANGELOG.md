# Changelog

## 0.3.0 — 2026-09-10

Pre-embed hardening pass in preparation for CDN-scale fleet
integration (100k+ auth flows per node per second). The version is
kept at 0.3.0 — the wire profile and every persisted state format
are unchanged. The changes are on the surface Rust callers touch:
constructor contracts, replay-store guarantees, and the response of
the authorize path to backend outage.

### Breaking

- **`CatTokenValidator::new()` and its `Default` impl are removed.**
  Callers now pass their allowed issuer set at construction time via
  [`CatTokenValidator::for_expected_issuers`], or opt into the
  explicit-danger form [`CatTokenValidator::dangerously_any_issuer`].
  The old surface admitted a validator that accepted tokens from any
  issuer through omission — the new API requires an affirmative
  choice.
- **`SingleKeyResolver::new(algorithm, issuer)` requires the issuer
  argument.** The previous `require_issuer(...)` opt-in step is
  folded into construction; there is no path that resolves a key
  without an issuer bound to it, except through
  [`SingleKeyResolver::dangerously_any_issuer`].
- **`InMemoryStrictJtiStore::new(freshness_window_seconds,
  max_entries)` requires a mandatory entry cap.** Callers that
  intentionally accept unbounded growth (fuzzers, single-shot
  diagnostics) use [`InMemoryStrictJtiStore::dangerously_unbounded`].
  Same shape on [`AsyncInMemoryStrictJtiStore`].
- **`JtiStore::check_and_insert` takes `&str` instead of `String`.**
  In-memory stores allocate once at insert time; distributed backends
  never had to allocate on the hot path.
- **`CatPorBlockList::is_blocked` and `add` return `Result<_,
  CatError>`.** Lock poisoning now surfaces as
  `CatError::BackendUnavailable` instead of silently promoting a
  poisoned mutex through `into_inner`. Aligns catpor with the
  fail-closed contract already applied to the JTI store and replay
  guard.
- **`RelayRequestContext::with_request_headers` returns
  `Result<Self, CatError>`, and a new
  [`RelayRequestContext::add_request_header`] method appends a
  single validated header.** Both reject CR/LF/NUL bytes in names
  and values and require ASCII header names per RFC 9110 §5.1.
  Prevents header-injection through attacker-controlled bytes
  that a downstream logger or metrics pipeline would otherwise
  echo verbatim.

### Added

- [`MoqtValidator::require_dpop`] and
  [`MoqtValidator::require_cattpk`] — per-validator toggles that
  refuse tokens missing DPoP `cnf` or X.509 pinning respectively.
  Off by default; opt-in for deployments that want DPoP or pinning
  mandatory across every request.
- [`MoqtValidator::require_dpop_replay_tracking`] — commits DPoP
  JTIs even when the token clears `honor_jti`. Prevents a hostile
  issuer from suppressing replay defense by omitting `honor_jti`.
- [`InMemoryStrictJtiStore`] is now sharded across 16 fixed shards
  with an `AtomicUsize` for O(1) `len()`. Removes the single-mutex
  contention point that showed up in the pre-integration soak test.
- [`DpopProof::jwk_thumbprint`] caches the RFC 7638 SHA-256
  thumbprint after the first call via `OnceLock`. Every subsequent
  audience-binding check on the same proof reuses the cached value.
- [`extract_spki_from_cert`] rejects inputs larger than
  [`MAX_CERT_DER_BYTES`] (64 KiB) before invoking the DER parser.
  A leaf certificate that fits inside 64 KiB is well above any
  realistic CA-issued shape; the cap bounds the CPU cost of a
  single authorization hop against pathological input.
- [`AsyncMoqtValidator::authorize_offloaded`] (behind the new
  `tokio` feature) wraps the sync pre-commit half in
  `tokio::task::spawn_blocking` so ES256/PS256 verify does not run
  on the reactor. The two replay commits still run on the caller's
  reactor.
- COSE decoder rejects a `bstr` unprotected header on the
  COSE_Sign1 / COSE_Mac0 envelope, matching RFC 9052 §3 literally.
  Prevents a legacy encoder that emits an empty `bstr` in that
  slot from slipping past the parser.
- `Es256Algorithm` and `Ps256Algorithm` carry explicit
  `impl ZeroizeOnDrop` markers. The inner `p256::ecdsa::SigningKey`
  and `rsa::pss::SigningKey` already zeroize on drop; the marker
  pins that guarantee at the crate boundary so a future field
  addition cannot silently regress it.
- `CatError::category(&self) -> &'static str` and `CatError::detail`
  helpers make metrics-emitting integrators grep-free — the category
  string is stable and partitions failures into "malformed",
  "denied", and "operator".

### Changed

- `constant_time_eq` now reads its accumulator through
  `std::ptr::read_volatile` so LLVM cannot reintroduce an
  early-exit branch. Length short-circuit is unchanged — every
  current caller compares fixed-length values (JWK thumbprints,
  ES256 signatures, ath hashes).
- URI parser rejects raw non-ASCII bytes. RFC 3986 requires
  percent-encoding; feeding raw UTF-8 into the byte-copy path
  would have driven the `as char` codepoint reinterpretation
  and desynchronized the normalized string from the input.
- `unfold_header_value` copies UTF-8 slices with `push_str`
  rather than the byte-at-a-time `as char` cast, so multi-byte
  UTF-8 headers survive canonicalization intact.
- `serde_cbor` removed as a top-level dependency. The advisory
  ignore for RUSTSEC-2021-0127 is gone; the corresponding entry
  in `docs/DEPENDENCY-DEBT.md` was removed.

## 0.3.0-baseline — 2026-09-05

Original 0.3.0 baseline. Introduces the CWT/COSE DPoP profile from
draft-nandakumar-moq-generic-dpop-proof-00 and closes the audit's remaining
release blockers.

### Breaking

- `DpopProof` wire format switched from JWT/JOSE (`dpop-proof+jwt`) to
  COSE_Sign1 CWT with `typ=dpop-proof+cwt;profile=cta5007b-v1`.
- `DpopProof::encode` returns `Vec<u8>` (was `String`).
- `DpopProof::decode` takes `&[u8]` (was `&str`).
- `DpopProof::create_for_moqt` `alg` parameter is now `i64` (COSE
  algorithm id, e.g. `ALG_ES256`) — no longer the JOSE `"ES256"` string.
- `DpopValidator::validate_without_jti_commit` and related APIs take
  `Option<&[u8]>` for the access-token hash — no longer base64url text.
- `compute_access_token_hash` now returns `Vec<u8>`; the base64url form
  is available under the new `compute_access_token_hash_b64` helper.
- The JWT-specific test module has been removed.

### Added

- Strict CWT parser: rejects duplicate CBOR map keys, trailing bytes
  after any decoded item, non-integer keys in COSE/CWT/actx/COSE_Key
  maps, and text-form `cti` (must be a byte string per RFC 8392 §3.1.7).
- `DpopValidator::with_jti_store_strict` — construction fails unless
  the store returns `true` from the new `JtiStore::is_strict()`
  method. Guides CDN deployments toward TTL-backed distributed stores.
- Unconditional cross-check between `actx.resource` endpoint and
  `RelayRequestContext::relay_endpoint`. No longer requires opting into
  `with_expected_resource()`.
- Frozen private-use CWT-claim labels (`actx=400`, `nonce=401`,
  `ath=402`) identified by the `profile=cta5007b-v1` parameter in the
  proof `typ` string.

### Fixed

- `LruJtiStore` is now clearly labeled non-strict in its rustdoc and
  in `docs/std-compliance-req.md`.
- `docs/PROFILE.md`: `moqt-reval=0` is accepted per draft (was
  documented as rejected).
- `docs/std-compliance-req.md`: removed references to the removed
  `authorize_with_dpop()` API and dialed back blanket-PASS claims for
  RFC 9449 and CAT-4-MOQT.
