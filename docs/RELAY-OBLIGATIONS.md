# Relay obligations

`cat-token` is an embedded authorization core. `MoqtValidator::authorize`
and `AsyncMoqtValidator::authorize` return a decision for one
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

`catreplay`'s `AsyncReplayGuard` carries the same set of obligations
for the `cti` state. As of 0.4.2 the trait exposes
`AsyncReplayGuard::is_strict()` mirroring the JTI-store
self-attestation, and `AsyncMoqtValidator::require_strict_replay_guard()`
turns the check on so a non-strict guard cannot slip past into a CDN
deployment for the second commit surface. TTL for the `cti` store must
be sized to the maximum token lifetime (`exp - iat`), not the DPoP
freshness window — a re-used token can arrive at any point inside its
own validity, not just within the JTI window. The strict attestation
covers the same axes as the JTI store: atomic insert-if-absent, TTL ≥
token lifetime + skew, no eviction inside TTL, fail-closed on outage.
The crate cannot verify the distributed backend; the integrator is
asserting the contract by opting in.

## 2. Non-atomic two-phase commit (JTI, then cti)

Both `authorize` entry points (sync and async) commit the DPoP JTI first, then
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

Only the two replay commits inside `AsyncMoqtValidator::authorize` are actually
awaitable. Token decoding, CAT claim evaluation, MOQT scope matching,
and DPoP signature verification (ES256/PS256) all run synchronously
inside the future. At high connection rates a burst of ES256
verifications can starve the executor and inflate p99/p999 tail
latency. `AsyncMoqtValidator::authorize_precommit` (via the sync
`MoqtValidator`) and `AsyncMoqtValidator::commit_async` are split
precisely so the CPU-bound half can be lifted off the I/O runtime
without pulling the whole authorize call into a blocking pool.

Recommended shape:

- **Split precommit and commit across executors.** Call
  `MoqtValidator::authorize_precommit` under
  `tokio::task::spawn_blocking` (or your runtime's equivalent) to
  keep ES256/PS256 verification off the reactor. Feed the resulting
  `PreCommit` into `AsyncMoqtValidator::commit_async` back on the I/O
  runtime so the two replay commits stay awaitable. `commit_async`
  is a `pub` method on `AsyncMoqtValidator` for this reason.
- **Bound the blocking pool.** `spawn_blocking` slots are not free —
  cap them so a DPoP surge cannot exhaust the whole pool and stall
  unrelated I/O. A per-connection admission gate (semaphore) sized
  to the pool is the simplest enforceable limit.
- **Monitor event-loop lag.** Even with the precommit offload, the
  post-commit path (finalize + response construction) runs on the
  reactor. A `tokio-metrics` `poll_duration` histogram or equivalent
  is the fastest signal that a hot path has slipped back onto the
  reactor.
- **Fall back to full offload** if the deployment cannot afford the
  extra hop granularity: wrap the entire async `authorize` call in
  `spawn_blocking`, accepting the cost of blocking on the JTI/cti
  awaits. The crate does not enforce a choice here.

`benches/async_scale_bench.rs` demonstrates the shape of the async
path under simulated backend latency; it does NOT prove event-loop
safety at production rates. That comes from real-relay soaks with
`tokio-metrics` (or the analogous instrumentation for the chosen
runtime) attached.

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

## 6. `cattpk` pinning and TLS chain validation

`MoqtValidator::authorize` does NOT evaluate `cattpk`. `cattpk` is a
*pin post-check*: it asserts that the peer's SPKI matches an expected
DER blob AFTER the TLS stack has otherwise authenticated the
certificate. Two separate obligations sit on the relay:

- **Run a real path validator upstream.** Invoke `authenticate_and_pin`
  with a `PathValidator` (RFC 5280 chain + revocation +
  hostname/SAN as appropriate for the deployment) and thread the
  resulting `VerifiedPeerCertificate` through the TLS termination
  layer. `cat-token` intentionally does not ship an X.509 path
  validator — the profile is a strict CAT recipient, not a PKI
  library.
- **Fail closed on missing pin evaluation.** A relay that receives a
  `cattpk`-carrying token but has no peer certificate on the request
  MUST reject the request. Silently authorizing without the pin
  check is an authorization bypass; the crate cannot enforce it
  because it does not see the peer certificate.

## 7. `moqt-reval` revalidation deadlines

`MoqtValidator::validate_moqt_claims` enforces the structural
`moqt-reval` obligations from CAT-4-MOQT §3.1.4: a recipient that
does not `.supports_revalidation()` must reject a `moqt-reval`
token; a recipient whose configured minimum interval exceeds the
token's declared interval must also reject it. **What the crate
does not enforce is the running deadline.** Once a request has been
authorized, the relay owns:

- **Ticking the per-session revalidation clock.** Store the token's
  `iat` and `moqt-reval` alongside the session state; on each
  request beyond `iat + moqt-reval` seconds require a re-presented
  token before continuing. A `moqt-reval == 0.0` token asserts "do
  not revalidate" and must be treated as a session-lifetime lease.
- **Threading `catr` renewal instructions through the response
  path.** `AuthorizedRequest.renewal` carries the token's `catr`
  claim (renewal URI, cookie/header carrier, expiration deadline)
  for the same session. The response builder is responsible for
  emitting the renewal hint on the appropriate status code; the
  authorization core does not send bytes on the wire.
- **Enforcing the `catr.deadline` fail-closed contract.** A token
  with `catr.deadline` past whose deadline the client has not
  successfully renewed MUST NOT continue to authorize; the relay
  drops the session. The crate exposes the deadline on the claim
  but does not run its own timer.

---

If any obligation above is unmet, the deployment does not meet the
100,000+ CDN-scale bar described in the audit sign-off, regardless
of what the crate's own test suite reports.
