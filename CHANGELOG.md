# Changelog

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
