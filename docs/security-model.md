# Security model

`cat-token` is a **strict fail-closed** recipient for CAT-4-MOQT tokens.
The reader of this document is a relay operator or an SDK integrator
who needs to know what the crate promises, what it deliberately does
not check, and what obligations rest on the caller.

## Fail-closed defaults

Every ambiguity the base spec allows is resolved by refusing the
token. Concretely:

- **Single-form acceptance.** Where CTA-5007-B / CAT-4-MOQT permit
  multiple encodings for the same semantic content (arrays of bytes vs
  arrays of arrays; strict-tagged vs untagged CBOR), the crate accepts
  exactly one form and rejects the rest. See `docs/PROFILE.md` for the
  matrix. This eliminates whole classes of parser-differential attacks
  between issuer and relay.
- **Recursion budget clamped.** CBOR decode recursion is capped at
  `CBOR_MAX_RECURSION_DEPTH = 32` for every entry point (COSE
  envelope, header extraction, DPoP CBOR payload, COSE_Encrypt0
  header). The profile-level nesting limit is 8; the decoder floor
  bites first.
- **JTI must be present** on every DPoP proof — no policy override.
- **Empty scopes / empty allowed-actions** never authorise
  ("empty means match all" is a foot-gun; the crate rejects).
- **Any unrecognised critical claim** in `crit` fails validation.
- **JTI-store errors** short-circuit to `CatError::BackendUnavailable`;
  authorization never falls back to "let it through".
- **Locked-out fields.** Public getters are `&T` or clones; no `&mut`
  handle leaks into the crate's internal state. External setters that
  once existed for spec-time convenience are now `pub(crate)`.

## Trust boundary

```
     ┌──────────────┐                     ┌──────────────┐
     │  ISSUER      │                     │  RELAY       │
     │  (trusted    │  ───── token ─────► │  (untrusted  │
     │   private    │                     │   until      │
     │   key)       │  ◄─── DPoP proof ── │   verified)  │
     └──────────────┘                     └──────────────┘
                          cat-token
                       runs *here*
```

- The **issuer**'s private key is not the crate's concern. The crate
  never mints tokens in a relay context — token construction is
  behind the `CatTokenBuilder` API which is intended for a separate
  issuance service.
- The **relay** operates on cat-token's output. It supplies request
  context (peer IP, ALPN, URI, method, headers, DPoP proof, peer
  location, block list, replay guard). If a token asserts a claim
  and the required context is not attached, authorization is refused
  with `CatError::MissingRelayContext { claim, field }` — that error
  is *always* the relay's bug, never the token issuer's.
- The **JTI store** is external. `LruJtiStore` (the in-process
  default) is `is_strict() == false` and suitable only for
  single-node deployments and tests. CDN-scale relays must plug in a
  distributed TTL-backed store that returns `is_strict() == true`
  and construct the validator via
  `DpopValidator::with_jti_store_strict`.

## What cat-token does NOT check

- **X.509 chain validation.** `check_cattpk_pin` compares the SPKI of
  a `VerifiedPeerCertificate` (a type produced by the caller's
  `PathValidator`) to the `cattpk` claim. Signature, expiry,
  revocation, name constraints are the caller's problem.
- **Regex denial-of-service.** `catu` / `cath` regex claims flow
  through the `regex` crate with a compile-size cap; the crate does
  not run the pattern on arbitrary-length input on your behalf.
- **Byte-serving of tokens.** No I/O. The crate parses bytes you hand
  it and never fetches keys, JWKs, or revocation lists on its own.
- **Clock authority.** The caller supplies `now_unix`. The crate does
  not read the wall clock in the authorize path except where the
  block-list uses `Utc::now()` for expiration; time-critical
  deployments should audit that path if they cannot trust the system
  clock.

## Cross-tenant isolation

- The DPoP JTI store keys entries as `iss:thumbprint:cti`. The
  shard-selection hash absorbs the `iss:` prefix first, then the full
  key — one bursty issuer's inserts spread uniformly across all
  shards rather than concentrating on one.
- Cross-tenant eviction contention on a shared in-process LRU still
  exists. If two tenants share an `LruJtiStore` and one is much
  louder than the other, the quiet tenant *will* see premature
  evictions. The correct fix at scale is per-tenant strict backends
  behind the `JtiStore` trait; the in-process LRU is not the right
  tool.

## Replay retention obligations

- `is_strict() == true` is a **self-attestation**. The crate cannot
  verify from the trait alone that the backend:
  - is durable across relay restarts,
  - implements insert-if-absent atomically across nodes (not
    check-then-set),
  - has TTL ≥ the DPoP freshness window,
  - fails closed on outage.
  Those obligations are on the store implementer. See the rustdoc on
  `JtiStore::is_strict` and `MoqtValidator::dpop_strict` for the full
  caller contract.
- `AsyncReplayGuard::commit` MUST run **after** all validation. The
  async pipeline is structured so the commit happens post-verify —
  do not reorder if you implement the trait yourself.

## Metrics and alerting

`cat-token` does not emit metrics on its own — it exposes a small set
of observation points and leaves emission to the integrator. This
decouples the crate from any particular metrics library (`metrics`,
`opentelemetry`, `prometheus`, `tracing` histograms) and keeps the
default build free of transitive metric-runtime dependencies.

### Failure categories: `CatError::category()`

Every error the authorization pipeline returns implements
`CatError::category() -> &'static str`. The label is stable and
belongs on a counter partition:

| Category | Meaning | Recommended metric |
|---|---|---|
| `malformed` | Issuer produced bytes that do not respect the profile (bad CBOR, bad COSE, unsupported algorithm, malformed claim). Signals an integration bug or a hostile issuer. | `cat_token_reject_total{category="malformed"}` |
| `denied` | Well-formed claim not satisfied by the request (expired token, wrong issuer, catu prefix mismatch, DPoP nonce differs, catgeocoord miss, replay detected). Signals correct authorization behaviour. | `cat_token_reject_total{category="denied"}` |
| `operator` | Wiring bug or backend outage (missing relay context, JTI-store unavailable, configuration refused). Signals a relay-side problem the operator must fix; **must not** be interpreted as authz failure. | `cat_token_reject_total{category="operator"}` and page on rate > 0. |

For high-cardinality label dimensions prefer `CatError::detail()` over
the `Display` form — detail is `SafeDisplay`-sanitized but the claim
name attached to the variant (via `MalformedClaim { claim, .. }` and
`ClaimEnforcementFailed { claim, .. }`) is the natural high-signal
label.

### Replay-store health: `DpopValidator::jti_cache_stats()`

Returns a `JtiCacheStats` snapshot:

```rust
pub struct JtiCacheStats {
    pub size: usize,               // current entry count
    pub capacity: usize,           // configured capacity
    pub under_pressure: bool,      // size >= 90% capacity
    pub premature_evictions: u64,  // JTIs evicted before their freshness window elapsed
}
```

Recommended emission:

| Field | Metric | Alert when |
|---|---|---|
| `size` | `cat_token_jti_store_size` (gauge) | — |
| `capacity` | `cat_token_jti_store_capacity` (gauge) | — |
| `under_pressure` | `cat_token_jti_store_pressure` (gauge, 0/1) | sustained `= 1` for > 1 min |
| `premature_evictions` | `cat_token_jti_store_premature_evictions_total` (counter) | delta > 0 over any 1 min window |

See `DpopValidator::minimum_jti_cache_capacity()` and
`DpopValidator::maximum_jti_cache_capacity()` for the accepted
capacity range.

### Load-bearing alerts

- **`cat_token_reject_total{category="operator"}` rising** — the
  relay is wired wrong. Not an authorization event; page the
  operator.
- **`cat_token_jti_store_premature_evictions_total` rising** — a
  DPoP proof was evicted before its freshness window. Replay
  protection is *degraded on this node*. Bump `capacity`, shard
  count, or move to a strict backend.

### Where metrics DO NOT come from

- The crate never emits metrics in a hot path — no locking or
  channel send on the authorize path.
- No `tracing::info!` on the accept path either. `debug!` and
  `trace!` are the loudest levels present; adjust the tracing
  subscriber's filter accordingly.
- `metrics-exporter-prometheus` is not a dependency. If you
  integrate with Prometheus, wire it up in your relay's boot code.

## Disclosure

Please report vulnerabilities via a private security advisory on the
repository. Do not file public issues for security bugs.
