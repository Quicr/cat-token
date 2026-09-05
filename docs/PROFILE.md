# cat-token strict profile

This crate implements a **narrow, deterministic, fail-closed** profile of
CTA-5007-B Common Access Token and CAT-4-MOQT (`draft-ietf-moq-c4m`). It is
not a full CTA-5007-B recipient. Anywhere the base specifications allow
multiple representational forms for the same semantic content, this crate
accepts exactly one form on input and emits exactly one form on output.

Consumers building a general CDN or content-security tool that must
interoperate with arbitrary third-party CAT issuers should treat this crate
as a strict-profile parser plus authorization core, not as a drop-in
CTA-5007-B implementation.

## Scope

Included:

- CWT (RFC 8392) with COSE_Sign1, COSE_Mac0, and COSE_Encrypt0 (AES-GCM)
- HMAC-SHA-256, ES256, PS256 signing algorithms
- CAT claim set: `catv`, `catnip`, `catu`, `catm`, `catalpn`, `cath`,
  `catgeoiso3166`, `catgeocoord`, `catgeoalt`, `catr`, `catpor`,
  `catreplay`, `catif`, `cattpk`, `catdpop`, `moqt`, `moqt-reval`
- DPoP proof-of-possession per RFC 9449 with issuer-scoped replay
- MOQT scope evaluation (`Publish`, `Subscribe`, wildcard, namespace-exact,
  track-prefix)
- Unified fail-closed authorization pipeline (`MoqtValidator::authorize`)
  that evaluates every signed CAT restriction against a
  `RelayRequestContext` snapshot

Excluded from this profile:

- Full RFC 5280 X.509 path validation. The `cattpk` claim is a *pin post-check*
  that runs only after a caller-supplied `PathValidator` has authenticated
  the peer.
- General CTA `catif` forms with label-string or label-set keys.
- Fractional numeric date forms in `iat`/`exp`/`nbf`/`catr` fields.
- URI parsing with userinfo or fragments.
- Distributed replay-store semantics. Replay guards are represented by the
  `ReplayGuard` trait so a caller can back them with any store; the crate
  ships an in-memory implementation only for testing.

## Supported forms matrix

| Claim | Accepted wire form (this profile) | Rejected forms |
| --- | --- | --- |
| `catv` | integer `1` | any other value, including `0` and `2+` |
| `catnip` | RFC 9164 tagged prefix or `Asn(u32)` | non-canonical host bits in prefix, unknown tag |
| `catu` | array of `UriMatchRule` (component → matches) | text-only rules |
| `catm` | array of ASCII HTTP method tokens | numeric method IDs, non-token characters |
| `catalpn` | array of byte strings | text strings |
| `cath` | array of `HeaderMatchRule` (name → matches) | integer header keys |
| `catr` | map with `type`, `expadd`, `deadline`, `renewal-uri`, `cookie`, `header` per type | fractional numeric dates, unknown `type` |
| `catpor` | array `[probability (0..=1 f64), id (bstr), expiration? (int)]` | maps, text `id`, `probability` out of `[0.0, 1.0]`, non-integer `expiration` |
| `catreplay` | `Permitted`, `Prohibited`, `ReuseDetection` | any other integer value |
| `catif` action | `[status]`, `[status, headers]`, or `[status, headers, kid]` | any longer array, text-string keys, label-set keys |
| `catif` header value | text string | integer, array, CWT-null |
| `cattpk` | SPKI DER bytes | any other encoding |
| `catdpop` | map with `jkt` (bstr) and `window` (int, ≤ 3600) | window > 3600, negative window |
| `moqt` | array of MOQT scopes with integer actions, namespace tuples, and byte-string track prefixes | non-array, non-integer actions |
| `moqt-reval` | positive finite f64 seconds | non-finite, negative, zero |

## Authorization contract

A caller obtaining an `AuthorizedRequest` from `MoqtValidator::authorize` has
proof that **every signed CAT restriction on the token**, plus every MOQT
scope constraint and every configured DPoP binding, matched the supplied
`RelayRequestContext`. In particular:

- `catv` unsupported version → decode-time rejection (before `authorize`).
- `catu` present but no `request_uri` in context → hard failure.
- `catm` present but no `request_method` in context → hard failure.
- `cath` present but request headers don't contain the required rule → hard failure.
- `catnip` present but neither `peer_ip` nor `peer_asn` supplied for a
  matching identifier family → hard failure.
- `catpor` present but no `CatPorBlockList` supplied → hard failure.
- `catreplay = Prohibited` or `ReuseDetection` but no `ReplayGuard`
  supplied → hard failure.
- `catreplay = Prohibited` and cti seen before → `ReplayAttackDetected`.
- `catreplay = ReuseDetection` and cti seen before → success, but
  `AuthorizedRequest::reuse_detected == true`.
- `cattpk` is *not* evaluated by `authorize`; callers must invoke
  `authenticate_and_pin` with a real `PathValidator` and thread the resulting
  `VerifiedPeerCertificate` through their TLS termination layer.

If any signed claim's semantics is not enforceable against the supplied
context, the request is rejected — the crate does not silently permit an
un-checked restriction.

## Key resolution

`SingleKeyResolver` and `KeyRingResolver` require an exact
`(issuer, kid, algorithm_id)` triple match. There is no fallback to a
default key or a key registered without an issuer. The issuer is peeked
from the unverified CBOR payload for resolver dispatch; if the peeked issuer
selects the wrong key, the subsequent signature verification rejects the
token.

## Non-goals

- Cross-implementation interoperability with issuers that emit the broader
  CTA-5007-B forms rejected above. Such tokens will fail to decode.
- Standalone certificate authentication. `cattpk` is a pin check; use a
  real TLS/path validator upstream.
- Distributed replay coherence. The crate ships an in-memory replay guard
  for testing; production callers must supply a distributed backend behind
  the `ReplayGuard` trait.

## Versioning

The profile itself is not versioned separately from the crate. Any change
to the "supported forms" matrix above is a breaking change and will bump
the crate's minor version pre-1.0 and major version post-1.0.
