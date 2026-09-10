# Changelog

## 0.5.1 — 2026-09-09

API-elegance follow-up on 0.5.0. Splits the generic `CryptoError`
variant into three intent-explicit failure modes so a caller can tell
"the key is bad" apart from "the replay store is down" apart from
"the integrator wired this up wrong". Deletes two dead error variants,
marks the error enum `#[non_exhaustive]`, tightens the crate-root
re-export surface, and hides internal precommit/commit types from
autocomplete. No behavioural changes to the authorization pipeline.

### Changed (breaking)

- **`CatError::CryptoError` is split into three variants.** Callers
  matching on the old `CryptoError(_)` must migrate:
  - `KeyOperationFailed(String)` — sign / verify / MAC / encrypt /
    decrypt / JWK-parse failed. Bad key material or corrupt input.
  - `BackendUnavailable(String)` — a replay store, key resolver, or
    other pluggable backend failed (mutex poisoning, distributed-store
    timeout, transient outage). The validator MUST fail closed.
  - `ConfigurationRefused(String)` — the integrator's configuration
    violates a fail-closed policy contract (strict-store requested but
    a best-effort one was supplied, `catreplay` obligation without a
    guard, etc.). Not transient; retrying will not help.
- **`CatError` is now `#[non_exhaustive]`.** Downstream `match` arms
  on the enum must add a wildcard.
- **Removed `CatError::UsageLimitExceeded` and
  `CatError::MethodNotAllowed`.** Neither was constructed anywhere in
  the crate. Method violations flow through `InvalidClaimValue`.
- **`MoqtValidator::allow_missing_audience` renamed to
  `dangerously_allow_missing_audience`.** Audience binding is the
  primary defense against cross-relay token replay; the old name did
  not signal that turning it off is a security-posture decision.
- **`RelayRequestContext::transport` / `.http` sub-structs removed.**
  The 0.5.0 grouping was a false abstraction — every real caller
  either reached through to the underlying fields or built the sub-
  struct inline. Field access is now `pub(crate)` with `.peer_ip()`,
  `.request_uri()`, etc. getters; the `with_*` builder setters are
  unchanged so existing constructors keep compiling.
- **`AuthorizedRequest` fields already private in 0.5.0 — this release
  extends the same treatment to `RelayRequestContext`** so both
  authorization boundary types are getter-only.
- **`CatReplayObligation`, `PreCommit`, and
  `MoqtValidator::validate_moqt_claims` are `#[doc(hidden)]`.** They
  remain `pub` for the async integration path and for `moqt-reval`
  contract tests, but they are not part of the surface a first-time
  integrator should see.

### Migration

- `Err(CatError::CryptoError(msg))` from crypto primitives →
  `Err(CatError::KeyOperationFailed(msg))`.
- `Err(CatError::CryptoError(msg))` from replay-store / lock / backend
  paths → `Err(CatError::BackendUnavailable(msg))`.
- `Err(CatError::CryptoError(msg))` from strict-store contract
  refusals or admission-policy misconfiguration →
  `Err(CatError::ConfigurationRefused(msg))`.
- `MoqtValidator::new().allow_missing_audience()` →
  `MoqtValidator::new().dangerously_allow_missing_audience()`.
- `ctx.transport.peer_ip` / `ctx.http.uri` → `ctx.peer_ip()` /
  `ctx.request_uri()` (or keep using the `.with_peer_ip(ip)` /
  `.with_request_uri(uri)` builders).

### Added

- Crate-level rustdoc on `lib.rs` documents the two feature profiles
  (default = CAT-4-MOQT relay validator, no-default = generic
  CWT/CTA-5007-B library) so the choice is discoverable without
  reading `Cargo.toml`.
- `MoqtValidator::dpop_strict` and `AsyncMoqtValidator::strict`
  rustdoc now cross-reference each other and warn that a deployment
  mixing sync and async paths must share the same underlying store
  instance.

### Fixed

- Crate-root re-exports are now an explicit curated list rather than
  `pub use module::*`. Prevents accidental leakage of module-private
  helpers into the public surface. The `prelude` module remains the
  recommended import path for integrators.

## 0.5.0 — 2026-09-09

API cleanup release. Every change here is a rename or a visibility
tightening — the underlying policy engine, DPoP verification, MOQT
scope matching, and replay-store contracts are unchanged. The point is
teachability: an integrator should be able to read `MoqtValidator`,
`Decoder`, `RelayRequestContext`, and `AuthorizedRequest` and see one
obvious way to compose a fail-closed pipeline. Every prior alternative
that made the surface look wider than it actually was has been removed.

### Changed (breaking)

- **`Decoder<'a>` replaces the seven free `decode_token_*` functions.**
  Callers pick a verifying key with `Decoder::with_algorithm(&alg)` or
  `Decoder::with_resolver(&resolver)`, layer on optional
  `.admission(&policy)`, `.encryption_key(&key)`, and `.limits(cwt)`,
  then call `.decode(&bytes)` or `.decode_base64(&str)`. The old
  `decode_token` and `decode_encrypted_token` free functions are kept
  as thin convenience shortcuts; the `_with_admission`,
  `_with_resolver`, `_with_limits`, `_with_admission_and_limits`, and
  `_base64` variants are removed. The builder is `Copy`-cheap so a
  single decoder can be reused across requests.
- **`RelayRequestContext` fields grouped into `transport` and `http`
  sub-structs.** `TransportInfo { peer_tls_alpn, peer_ip, peer_asn }`
  and `HttpRequest { uri, method, headers }` are constructible
  independently and swap-assignable via `.transport(t)` / `.http(h)`.
  The flat per-field builder setters (`with_peer_ip`, `with_request_uri`,
  etc.) still exist and write through the sub-structs; direct field
  access now goes through `ctx.transport.peer_ip` / `ctx.http.uri`.
- **`AuthorizedRequest` fields are private, getters replace them.** Use
  `matched_scope_index()`, `requires_revalidation()`,
  `revalidation_interval()`, `renewal()`, and `reuse_detected()`. The
  struct is an authorization decision, not a config bag — its fields
  should never be mutated after `authorize` returns.
- **`MoqtValidator::authorize` split into two entry points.**
  `authorize(&token, &ctx)` is the guard-free path; a token that
  demands a replay guard is rejected as
  `InvalidClaimValue("token asserts catreplay but no replay guard
  configured")`. `authorize_with_replay(&token, &ctx, &guard,
  block_list)` is the full path. Removes the turbofish papercut where
  the old generic `authorize::<G>(..., None, None)` needed a phantom
  type annotation. `AsyncMoqtValidator` uses the same names —
  `authorize` and `authorize_with_replay` — so the sync and async
  surfaces are learnable as one concept.
- **`MoqtValidator::with_dpop_validation` renamed to
  `dpop_best_effort`; `try_with_strict_dpop_validation` renamed to
  `dpop_strict`.** The old names implied "strict is optional"; the new
  names make the deployment posture the choice — best-effort for local
  development, strict (rejects non-strict stores at construction) for
  CDN. `AsyncMoqtValidator::try_from_sync_strict` and
  `from_sync_best_effort` renamed to `strict` and `best_effort`
  respectively for the same reason.
- **Internal claim-enforcement helpers restricted to `pub(crate)`.**
  `enforce_catu`, `enforce_catnip`, `enforce_catpor`, `validate_method`,
  `apply_match_value`, `validate_all_headers`, `unfold_header_value`,
  and `strip_token_from_uri` are no longer public. Integrators drive
  the whole authorization pipeline through `MoqtValidator::authorize` /
  `authorize_with_replay`; the individual helpers were never part of a
  stable surface. `enforce_catreplay` is removed entirely — the commit
  logic is inlined into `commit` and `commit_async`.

### Migration

- `decode_token_with_admission(bytes, &resolver, &policy)` →
  `Decoder::with_resolver(&resolver).admission(&policy).decode(bytes)`.
- `decode_token_with_resolver(bytes, &resolver)` →
  `Decoder::with_resolver(&resolver).decode(bytes)`.
- `decode_token_base64(str, &alg)` →
  `Decoder::with_algorithm(&alg).decode_base64(str)`.
- `ctx.peer_ip = Some(ip)` → `ctx.transport.peer_ip = Some(ip)` (or
  keep using `.with_peer_ip(ip)`).
- `result.matched_scope_index` → `result.matched_scope_index()`.
- `validator.authorize::<dyn ReplayGuard>(&t, &c, None, None)` →
  `validator.authorize(&t, &c)`.
- `validator.authorize::<G>(&t, &c, Some(&guard), Some(&blocklist))` →
  `validator.authorize_with_replay(&t, &c, &guard, Some(&blocklist))`.
- `MoqtValidator::new().with_dpop_validation(settings)` →
  `MoqtValidator::new().dpop_best_effort(settings)`.
- `MoqtValidator::new().try_with_strict_dpop_validation(settings,
  store)` → `MoqtValidator::new().dpop_strict(settings, store)`.
- `AsyncMoqtValidator::try_from_sync_strict(sync, store)` →
  `AsyncMoqtValidator::strict(sync, store)`.
- `AsyncMoqtValidator::from_sync_best_effort(sync, store)` →
  `AsyncMoqtValidator::best_effort(sync, store)`.
- `async_validator.authorize_async(&t, &c, None, None).await` →
  `async_validator.authorize(&t, &c).await`.
- `async_validator.authorize_async(&t, &c, Some(&g), list).await` →
  `async_validator.authorize_with_replay(&t, &c, &g, list).await`.

## 0.4.3 — 2026-09-08

Fixes the test-vector pipeline into `draft-ietf-moq-c4m`. Hand-copying
hex from `tests/test_data/*.json` into Appendix A of the draft
introduced mid-hex whitespace, byte-string / text-string type
mismatches, and truncated fields (see the Copilot review on
moq-wg/CAT-4-MOQT#47). The generator now emits a draft-shaped
markdown block with every hex field on a single line, and a `--verify`
mode fetches the draft's own `draft-ietf-moq-c4m.md` and diffs it
against what cat.rs currently produces. CI runs the emitter against
itself as a strict self-check and against the draft `main` branch as
an advisory drift report.

### Added

- **`generate-test-vectors --emit draft-md`** writes an
  Appendix-A-shaped markdown file (`tests/test_data/draft_appendix_a.md`
  by default; `--out PATH` overrides) whose fenced `~~~ json` blocks
  keep every `cose_hex` / `payload_cbor_hex` / `tag_hex` /
  `signature_hex` / `cnf_jkt_hex` / `key_hex` / `public_key_*_hex` /
  `private_key_hex` field on a single line. The block is intended to
  be pasted verbatim into the draft; do not hand-wrap.
- **`generate-test-vectors --verify`** loads a `draft-ietf-moq-c4m.md`
  copy (`--from URL`, default `https://raw.githubusercontent.com/moq-wg/CAT-4-MOQT/main/draft-ietf-moq-c4m.md`,
  or `--from-file PATH`), unwraps line-continued JSON string literals,
  parses every fenced JSON block under Appendix A, and diffs each
  vector's hex-shaped fields against what cat.rs currently emits.
  Exits non-zero on any mismatch or JSON parse error under the
  appendix.
- **CI job `draft-vectors`** runs the emitter and verifies its own
  output on every push (strict gate — a broken emitter fails CI). A
  second, `continue-on-error: true` step diffs against the live draft
  `main` for advisory drift reporting; the failure is the signal that
  the draft needs a refresh from the emitter output.

### Fixed

- **`dpop_jwk_binding` vector JKT** is now the real RFC 7638 JWK
  thumbprint of the fixed ES256 test key. The previous value was a
  literal `a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1`
  with a `]` sentinel patched to `0` via `str::replace`, which
  produced meaningless bytes. Any consumer replaying the previous
  vector's cnf-jkt should regenerate against 0.4.3.
- **`token_hmac_full` claim metadata** now reports `catv: 1` and the
  concrete `catu` path prefix rule that the encoded CBOR actually
  contains. The previous metadata carried `catv: "CAT-v1"` (never
  encoded) and a phantom `catu: 10` (also never encoded), so a peer
  reading only the JSON annotations would build a mismatched
  expectation of the CBOR payload.
- **`lru` bumped 0.16 → 0.18** to pick up the panic-safety fix for
  `LruCache::pop()` (RUSTSEC-2026-0253). cat-token's `LruCache`
  callers key on `Vec<u8>` / `String`, neither of which panics on
  drop, so the vulnerability was not reachable through this crate —
  but the bump is free and closes the advisory.

### Security

- **`deny.toml` advisory ignores.** Two open advisories are
  explicitly deferred with the exposure-audit rationale documented in
  the new `docs/DEPENDENCY-DEBT.md`:
  - RUSTSEC-2023-0071 (`rsa 0.9` Marvin timing attack): cat-token
    uses `rsa` for PS256 *verification* only; the attack targets
    private-key operations, so the recipient path is not on the
    attack surface. Awaiting `rsa 0.10` stable.
  - RUSTSEC-2021-0127 (`serde_cbor` unmaintained): migration to
    `ciborium` (already a direct dep) is tracked separately because
    it touches every strict-profile CBOR call site.

## 0.4.2 — 2026-09-07

Round-4 audit follow-up. Adds an async authorize path so production
relays can integrate cat-token without wrapping every replay commit in
`spawn_blocking`, aligns the DPoP JWT wire format with
draft-nandakumar-moq-generic-dpop-proof-00 §3.2 (text `tns`/`tn`/`jti`),
closes the DPoP-protected setup authorization gap for endpoint-only
actions, and enforces the strict JTI-store contract at
`AsyncMoqtValidator` construction time so a non-strict backend cannot
slip past into a CDN deployment. Ships the CDN-scale replay contract
harness distributed backends must pass before deployment, extends CI
to the async surface, adds a genuine scale bench for `authorize_async`
under simulated backend latency, and documents the obligations the
embedding relay still owns.

### Added

- **`jti_contract` module** — the property-test harness every strict
  `JtiStore` / `AsyncJtiStore` implementation must pass before it is
  deployed at CDN scale. Public assertions cover immediate-duplicate
  smoke test (`assert_no_dropped_insert_within_ttl`), sharding hygiene
  (`assert_distinct_keys_never_collide`), insert-if-absent atomicity
  under contention (`assert_atomic_insert_if_absent`), and outage
  fail-closed behaviour (`assert_fail_closed_on_backend_outage`).
  Async siblings live under `jti_contract::asynchronous` when built
  with `--features async`; the async atomicity helper drives all
  inserts concurrently via `futures::future::join_all` so a
  check-then-set race actually surfaces. TTL retention under time
  passage / memory pressure is out of scope — that requires a soak
  against production-shaped traffic. Backend implementers fork
  `tests/test_jti_contract.rs`, swap in their Redis/DynamoDB store,
  and run the same suite.
- **`async_scale_bench`** (`--bench async_scale_bench --features async`)
  drives 512 concurrent `authorize_async` calls against a
  latency-injecting store, sweeping 0/100/1000 μs simulated backend
  RTTs. Each request carries a fresh signed DPoP proof and the token
  has a `cnf` binding, so the JTI store is actually on the path — a
  runtime assertion inside the bench (`store.calls() == CONCURRENCY`)
  fails the run if the wiring ever regresses. Catches regressions in
  the pre-commit/commit split and ES256 verification path; a real
  100k-flow soak still requires production-shaped infrastructure the
  crate cannot ship.
- **Async feature matrix in CI.** `.github/workflows/ci.yml` now
  builds and tests the `moqt,async` and `builtin-trie,moqt,async`
  cells so the async surface is gated on the same bar as sync.
- **`docs/RELAY-OBLIGATIONS.md`** — checklist of what the embedding
  relay must still prove before promoting a `cat-token` integration
  to 100k+ CDN scale. Covers distributed replay backends (JTI + cti),
  CPU-bound crypto isolation via the `authorize_precommit` /
  `commit_async` split with concrete `spawn_blocking` shape and event-
  loop lag monitoring, JTI/cti two-phase-commit failure model,
  soak/failover, `cattpk` pinning + upstream RFC 5280 path validation,
  and `moqt-reval` deadline enforcement + `catr` renewal threading.
- **`AsyncReplayGuard::is_strict()`** — self-attestation mirror of
  the JTI-store strict-store contract, with
  `AsyncMoqtValidator::require_strict_replay_guard()` refusing a
  best-effort guard at the `catreplay` commit surface. Closes the
  gap where a CDN deployment could pin JTI strictness but silently
  degrade the second commit through a leaky `cti` backend.
- **`AsyncMoqtValidator` rustdoc example** documenting the
  `spawn_blocking(precommit) → commit_async(reactor)` offload
  shape so integrators do not have to derive it from the trait
  surface.
- **`docs/PROFILE.md` DPoP section** — pins the wire `typ` values to
  the draft verbatim and documents the private-use CBOR label
  numbers (400/401/402 for `actx`/`nonce`/`ath`) that peers must
  agree on out of band.
- **Async authorize surface** behind the new `async` feature
  (`--features async`, pulls in `async-trait` and `futures` for the
  concurrent-inserts helper; no runtime dependency).
  - `AsyncMoqtValidator::authorize_async` — mirrors
    `MoqtValidator::authorize` but awaits the two replay commits
    (DPoP JTI, `catreplay` cti). Pre-commit checks share the sync
    implementation; only the storage effects diverge.
  - `AsyncJtiStore` and `AsyncReplayGuard` traits — async siblings of
    `JtiStore` / `ReplayGuard` with identical fail-closed contracts.
  - `AsyncJtiStoreAdapter` — wrap a sync `JtiStore` for callers that
    keep replay state in-process. Distributed backends should
    implement `AsyncJtiStore` natively.
  - `AsyncInMemoryStrictJtiStore` — reference strict backend for tests
    and single-node deployments; `is_strict() == true`.
  - `MoqtValidator::authorize_precommit` and
    `MoqtValidator::commit` — the sync pipeline is now factored into
    a pre-commit / commit split so sync and async paths share the
    policy code. `PreCommit`, `CatReplayObligation`, and
    `DpopValidator::dpop_commit_key` are exposed for the same reason.
  - Integration test `tests/test_async_authorize.rs` exercises the
    happy path, JTI replay, `catreplay` commit, and store-outage
    fail-closed contract.
- **DPoP nonce challenge enforcement** (RFC 9449 §8).
  `RelayRequestContext::with_expected_dpop_nonce` pins a per-request
  server nonce; a proof lacking a nonce or carrying a mismatched
  nonce is rejected with `DpopValidationFailed`. Callers that don't
  rotate nonces leave it unset and the check is a no-op.
- **DPoP-protected setup authorization**. `ClientSetup` /
  `ServerSetup` proofs can now round-trip through
  `MoqtValidator::authorize` with empty `tns`/`tn` on both proof and
  request context (endpoint-shape actions per CAT-4-MOQT §3.1.2). A
  setup proof that smuggles a namespace or track is rejected as
  before.

### Fixed

- **DPoP JWT wire format** now emits `tns` and `tn` as single UTF-8
  text strings using the MOQTransport §1.5.1 canonical serialization
  (safe ASCII passes through, other bytes escape as `.HH`; segments
  join with `-`), matching the CWT byte-string form
  semantically and matching
  draft-nandakumar-moq-generic-dpop-proof-00 §3.2 verbatim. Decode
  rejects the pre-0.4.2 JSON-array `tns` shape as
  `InvalidClaimValue` so a peer emitting the old form cannot silently
  authorize. `jti` is a UTF-8 text string; `ath` remains base64url.
  Non-UTF-8 namespace/track bytes are no longer sign-time errors —
  they round-trip through the canonical `.HH` escape. Stale module
  rustdoc that described `tns`/`tn` as base64url is corrected — the
  doc drift had been an interop hazard for peers built against the
  header.
- **AsyncMoqtValidator strict-store construction contract.**
  `AsyncMoqtValidator::from_sync` is replaced by two intent-explicit
  constructors: `try_from_sync_strict` refuses stores that report
  `is_strict() == false` (the CDN deployment path), and
  `from_sync_best_effort` is the opt-in for local development. This
  mirrors the sync `MoqtValidator::try_with_strict_dpop_validation`
  contract that previously had no async equivalent.

## 0.4.1 — 2026-09-06

Post-audit follow-up. Fixes the CI feature-matrix compile break introduced
in 0.4.0, aligns DPoP action mnemonics with CAT-4-MOQT §3.1.2, and
tightens documentation and API surface around the CDN integration
boundary.

### Breaking

- MOQT action wire mnemonics now follow CAT-4-MOQT §3.1.2 Table 2:
  `PublishNamespace` → `PUB_NS` (was `PUBLISH_NAMESPACE`),
  `SubscribeNamespace` → `SUB_NS` (was `SUBSCRIBE_NAMESPACE`),
  `RequestUpdate` → `REQ_UPDATE` (was `REQUEST_UPDATE`),
  `TrackStatus` → `TRK_STATUS` (was `TRACK_STATUS`),
  `ClientSetup` / `ServerSetup` → `SETUP` (were `CLIENT_SETUP` /
  `SERVER_SETUP`; the wire form is ambiguous by draft, DPoP proofs
  decode `SETUP` as `ClientSetup`).
- Removed `MoqtValidator::with_dpop_validator`. It bypassed the
  strict-store contract enforced by `try_with_strict_dpop_validation`
  and had no in-tree callers.
- Removed `MoqtAction::action_name()`. Wire naming lives on
  `moqt_action_wire_name` in `dpop.rs`; the enum should not carry two
  parallel spellings.

### Fixed

- CI feature-matrix (`.github/workflows/ci.yml`) no longer fails at
  `--no-default-features` or feature-subset builds:
  - `tests/test_replay_fault_injection.rs` is gated behind
    `#![cfg(feature = "moqt")]`.
  - `tests/test_trie.rs` is gated behind `moqt` **and** at least one of
    `builtin-trie` / `qp-trie` (the `PrefixTrie` symbol requires one).
  - Generic COSE / CWT constants (`COSE_HDR_*`, `CWT_CLAIM_IAT/CTI`,
    `COSE_KEY_*`, `COSE_KTY_*`, `COSE_CRV_P256`, `COSE_TAG_SIGN1`) are
    now `pub` — they are RFC 8152 / 8392 primitives, not MOQT-specific,
    and exposing them keeps them clippy-clean under `--no-default-
    features` without misleading `#[allow(dead_code)]`.
- `docs/std-compliance-req.html` regenerated from
  `docs/std-compliance-req.md`; removed stale references to
  `authorize_with_dpop()` and `DpopProof::create_proof()`.
- `src/dpop.rs` module documentation rewritten to describe the current
  dual-format (CWT + JWT) state instead of promising JWT "later".

### Added

- `MoqtValidator::try_with_strict_dpop_validation` rustdoc now spells
  out the caller obligations behind `JtiStore::is_strict()`:
  self-attestation only, plus explicit requirements on atomic
  insert-if-absent, TTL ≥ freshness window, and fail-closed on backend
  outage. Distributed CDN backends must be audited against these
  requirements at integration time — this crate cannot verify them.
- `JtiStore::is_strict` rustdoc clarified as self-attestation with
  scope limits.
- `MoqtValidator::authorize` rustdoc documents the DPoP-JTI-then-CAT-
  cti commit ordering as **non-atomic across two independent stores**,
  and points callers who need atomicity at binding both commits to the
  same transactional backend.

## 0.4.0 — 2026-09-05

CDN deployment readiness release. Closes round-2 audit findings around
JTI backend contracts, resource-URI shape enforcement, and dual-format
DPoP support.

### Breaking

- `MoqtResourceUri.namespace` is now `Option<Vec<Vec<u8>>>` (was
  `Vec<u8>`) to model the tuple form of MOQT namespaces. Track resources
  require a namespace; namespace-only actions have `track == None`;
  endpoint-only actions have both `None`.
- `parse_moqt_resource_uri` now parses comma-separated base64url
  segments per MOQTransport §1.5.1 and rejects mixed shapes for the
  requested action.
- `construct_moqt_uri` signature now takes `Option<&[Vec<u8>]>` for
  namespace tuples; passing `Some(&[])` or a track without a namespace
  is rejected.
- `DpopProof` gained a `wire_format: DpopWireFormat` field and
  `with_wire_format()` builder. `encode`/`decode` dispatch on it;
  default remains CWT.

### Added

- **JWT DPoP wire format** (RFC 9449 compact form) as a sibling to
  the CWT profile. `DpopWireFormat::Jwt` produces
  `base64url(header).base64url(payload).base64url(sig)` with the same
  `actx`/`ath`/`jti` semantics as CWT. `decode` autodetects wire format;
  `decode_as` forces a specific format. See `src/dpop.rs::jwt`.
- `MoqtValidator::try_with_strict_dpop_validation(settings, store)` —
  construction fails unless the JtiStore returns `is_strict() == true`.
  Prevents accidentally wiring an LRU-evicting cache into a
  fail-closed CDN authorization path.
- `MoqtValidator::with_dpop_validator(validator)` — accept a
  pre-configured `DpopValidator` for advanced deployments.
- `InMemoryStrictJtiStore` — unbounded HashMap with TTL-based cleanup.
  `is_strict()` returns `true`. Optional `with_max_entries(cap)`
  refuses (not evicts) inserts at capacity and increments
  `rejected_over_capacity()`. Suitable as a reference strict backend
  for single-relay deployments and for tests.
- Unconditional actx-shape enforcement in `MoqtValidator::authorize`:
  each `MoqtAction` has a `resource_shape()` (Endpoint / Namespace /
  Track) that is checked against the parsed URI *and* against the
  DPoP proof's `actx` before any request is authorized. Endpoint
  actions must not carry `tns`/`tn`; namespace actions must carry
  `tns` but not `tn`; track actions must carry both.
- `MoqtAction::resource_shape()` and `MoqtResourceShape` enum.
- `DpopValidator::preflight(&settings)` — startup validator for the
  freshness window bounds. Fails loud at construction time instead of
  silently accepting proofs that would never validate.
- Fault-injection test suite (`tests/test_replay_fault_injection.rs`)
  documenting the JtiStore failure contract:
  - JTI is burned on first success; retry with same JTI fails as
    replay.
  - Transient backend errors surface as `CryptoError` and do NOT poison
    the cache — retry with a fresh JTI must succeed.
  - Relay restart with an in-memory strict store loses replay state
    (documented trade-off; distributed strict backends don't have
    this).
  - Strict store at `max_entries` refuses new inserts loudly.

### Fixed

- `LruJtiStore::with_shards_and_window` now distributes capacity
  exactly across shards. Previously the requested capacity could be
  silently rounded down (shards × floor(capacity/shards)); the last
  shard now absorbs the remainder.
- Introduced `MAX_JTI_CACHE_SIZE = 10_000_000` upper clamp so
  pathological configuration cannot trigger unbounded allocation.
- Namespace comparison in `MoqtValidator::authorize` now compares the
  full tuple (`proof.payload.actx.tns != *ns`) instead of only the
  first segment.
- `docs/std-compliance-req.md`: stale `DpopProof::create_proof()`
  reference replaced with the current `DpopProof::create_for_moqt` +
  `with_wire_format` construction.
- `README.md`: "Full CTA-5007-B CAT token support" reworded to
  reflect that this crate is a strict narrow-profile recipient, not a
  full CTA-5007-B implementation.
- `spin` bumped from 0.9.8 to 0.9.9 (transitive; 0.9.8 was yanked).

## 0.3.0 — 2026-09-05

Breaking release. Introduces the CWT/COSE DPoP profile from
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
