# Relay obligations

`cat-token` is an embedded authorization core. `MoqtValidator::authorize`
and `AsyncMoqtValidator::authorize_async` return a decision for one
request; the surrounding relay owns everything that cannot be settled
inside a single call. This document lists what the relay must still
prove before a `cat-token`-backed deployment can be certified for
100,000+ CDN scale.

None of these obligations can be discharged by a library patch. They
are called out here so an integrator can hold their own deployment
against a concrete checklist rather than re-derive the list from the
audit history.

## 1. Distributed replay store

The default `LruJtiStore` and `AsyncInMemoryStrictJtiStore` are
process-local and are correct only for single-node development. A
production relay running multiple ingest nodes MUST plug in a
distributed strict `JtiStore` / `AsyncJtiStore` and prove:

- **Atomic insert-if-absent across nodes.** A JTI accepted by node A
  must be rejected as replay by node B. `jti_contract::assert_atomic_insert_if_absent`
  covers the contract; the relay must run it against the real
  backend under the ingest-rate load of the deployment.
- **TTL ≥ DPoP freshness window + max clock skew.** The freshness
  window is configured on `CatDpopSettings`; the store must retain
  the JTI for at least that window plus the largest clock skew the
  fleet tolerates.
- **No eviction inside the retention window.** Sharded/LRU stores
  that shed under memory pressure are unsafe as strict backends;
  `jti_contract::assert_no_dropped_insert_within_ttl` is a smoke
  test only. A real soak must verify retention under production
  ingress.
- **Fail-closed on outage.** `check_and_insert` must surface
  `CatError::CryptoError` when the backend is unreachable, never
  `Ok(())`. `jti_contract::assert_fail_closed_on_backend_outage`
  documents the contract; the relay must instrument the client so a
  connection failure, timeout, or partitioned quorum surfaces the
  error rather than swallowing it.
- **Failover and restart hygiene.** A node restart or leader change
  MUST NOT reset the JTI set. This is a property of the storage
  layer, not the crate.

`catreplay`'s `AsyncReplayGuard` has an analogous set of obligations
for the `cti` state. The crate does not surface an `is_strict`
attestation on that trait; the relay must prove correctness of the
`cti` backend independently.

## 2. Non-atomic two-phase commit (JTI, then cti)

`authorize_async` (and `authorize`) commit the DPoP JTI first, then
the `catreplay` cti. A failure in the second commit leaves the JTI
burned — the same request cannot be retried with the same proof.
This is documented at `src/moqt.rs` on the sync `authorize` and is
consistent with RFC 9449's non-idempotent authorization
considerations, but the relay must:

- Retry a failed request with a fresh DPoP proof (new JTI). Retrying
  with the same proof is guaranteed to fail replay.
- Instrument the commit boundary so a second-commit failure is
  observable, not silent — it is a lost request from the caller's
  perspective.

## 3. Isolate CPU-bound cryptographic verification

Only the two replay commits inside `authorize_async` are actually
awaitable. Token decoding, CAT claim evaluation, MOQT scope matching,
and DPoP signature verification (ES256/PS256) all run synchronously
inside the future. At high connection rates a burst of ES256
verifications can starve the executor and inflate p99/p999 tail
latency.

Options (choose one; the crate does not choose for you):

- Run `authorize_async` on a dedicated CPU worker pool that is
  distinct from the I/O runtime.
- Apply strict per-connection concurrency limits around DPoP
  verification so the executor cannot be saturated.
- Use `tokio::task::spawn_blocking` for the sync half of the
  authorization if the deployment tolerates the extra hop.

`benches/async_scale_bench.rs` demonstrates the shape of the async
path under simulated backend latency; it does NOT prove event-loop
safety at production rates. That comes from real-relay soaks.

## 4. Load, failover, and soak

`cargo bench` and the property harness inside `jti_contract` catch
regressions. They do NOT prove production readiness. Before promoting
a `cat-token` integration to CDN scale, the deploying team should run:

- **Sustained soak** at target QPS for at least the DPoP freshness
  window, with real DPoP verification per request and the actual
  distributed replay backend on the path. Measure p50, p99, p999,
  and memory retention.
- **Failover** during load: kill a JTI store node, kill a relay
  node, kill an issuer key resolver. Every path MUST fail closed;
  none SHOULD produce silent `Ok(())` from a store call.
- **Backend outage / timeout injection** on the JTI store. Verify
  the relay surfaces `CatError::CryptoError` and rejects the
  request rather than authorising it.
- **Clock skew** across relay nodes. Verify a proof issued at the
  edge of the freshness window is either accepted or rejected
  consistently across the fleet.
- **Restart under load.** No relay node may accept a JTI that
  another node has already committed.

## 5. Profile / label agreement with peers

Both DPoP wire forms (`typ=dpop-proof+cwt`, `typ=dpop-proof+jwt`) are
emitted verbatim per `draft-nandakumar-moq-generic-dpop-proof-00`.
The CBOR label numbers this crate assigns to `actx`/`nonce`/`ath`
(400/401/402) are private-use; peers using a different mapping will
not interoperate. Confirm the label assignment with your DPoP issuer
and any peer relays out of band.

## 6. `cattpk` pinning

`MoqtValidator::authorize` does NOT evaluate `cattpk`. The relay
MUST invoke `authenticate_and_pin` with a real `PathValidator` and
thread the resulting `VerifiedPeerCertificate` through its TLS
termination layer. Skipping the pin check is an authorization
bypass; the crate cannot enforce it because it does not see the
peer certificate.

---

If any obligation above is unmet, the deployment does not meet the
100,000+ CDN-scale bar described in the audit sign-off, regardless
of what the crate's own test suite reports.
