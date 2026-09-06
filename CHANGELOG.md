# Changelog

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
