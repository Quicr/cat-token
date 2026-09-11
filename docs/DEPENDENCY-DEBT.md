# Dependency debt

This document lists the RustSec advisories cat-token knowingly defers
through `[advisories.ignore]` in `deny.toml`, and the migration path
each one is waiting on. **Silencing the advisory is not the fix.**
The exit criterion for every entry is *the debt has been paid* — the
`ignore` block should shrink over time, not accumulate.

Before adding a new entry: audit the actual exposure surface for this
crate specifically, not just the CVSS score. The two entries below
survive that audit; that is why they are here.

## RUSTSEC-2023-0071 — `rsa 0.9` Marvin timing attack

- **Advisory:** <https://rustsec.org/advisories/RUSTSEC-2023-0071>
- **Class:** vulnerability (timing sidechannel on private-key ops)
- **cat-token exposure surface:** **verification only**. This crate
  uses `rsa` to verify PS256 signatures on inbound CAT tokens and
  DPoP proofs. The Marvin attack recovers RSA private keys through
  timing measurements against a private-key oracle (decryption,
  signing). A verifier does not perform private-key operations, so a
  cat-token *recipient* is not on the attack surface.
- **Downstream exposure:** *issuers* using this crate's signing
  helpers to mint PS256 tokens with a real private key ARE exposed.
  If you use cat-token on the issuer side, prefer an ES256 signing
  key or a KMS-backed signer that does not expose the private key to
  process memory.
- **Fix path:** `rsa 0.10` stabilizes the constant-time
  implementation. Track the milestone at
  <https://github.com/RustCrypto/RSA/issues/626>. When `rsa 0.10.0`
  ships as non-pre-release, bump `Cargo.toml` and delete this entry.
- **Alternate exit:** if `rsa 0.10` slips indefinitely, drop PS256
  support entirely. ES256 covers every deployment we currently know
  about; PS256 exists for parity with JWT-native peers.

## Adding a new entry

An `[advisories.ignore]` entry requires all of:

1. A RUSTSEC ID (not a CVE-only reference).
2. An audit of cat-token's actual exposure surface for that
   advisory — is the vulnerable code path reachable from a cat-token
   caller? Under what conditions?
3. A concrete fix path with an upstream tracking issue where
   available, or a documented decision to drop the affected feature.
4. A section in this file that reviewers can point at.

If any of the above is missing, the advisory is not "deferred" — it
is either an unremediated bug (fix it) or a false positive (justify
in the `reason` field, no doc entry needed).
