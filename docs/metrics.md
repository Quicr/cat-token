# Metrics

`cat-token` does not emit metrics on its own — it exposes a small set of
observation points and leaves emission to the integrator. This decouples
the crate from any particular metrics library (`metrics`,
`opentelemetry`, `prometheus`, `tracing` histograms) and keeps the
default build free of transitive metric-runtime dependencies.

## Failure categories: `CatError::category()`

Every error the authorization pipeline returns implements
`CatError::category() -> &'static str`. The label is stable and belongs
on a counter partition:

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

## Replay-store health: `DpopValidator::jti_cache_stats()`

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

A non-zero `premature_evictions` counter means an accepted JTI was
dropped before its freshness window elapsed and replay protection is
degraded on that node — page. See
`DpopValidator::minimum_jti_cache_capacity()` and
`DpopValidator::maximum_jti_cache_capacity()` for the accepted range.

## Where metrics DO NOT come from

- The crate never emits metrics in a hot path — no locking or channel
  send on the authorize path.
- No `tracing::info!` on the accept path either. `debug!` and `trace!`
  are the loudest levels present; adjust the tracing subscriber's
  filter accordingly.
- `metrics-exporter-prometheus` is not a dependency. If you integrate
  with Prometheus, wire it up in your relay's boot code.
