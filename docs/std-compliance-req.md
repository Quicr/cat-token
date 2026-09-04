# Standards Compliance Requirements — cat.rs

**Project:** cat-token (Rust)
**Spec baseline:** CTA-5007-B (April 2025) — Common Access Token
**Last updated:** 2026-09-03

Status legend:
- **PASS** — fully implemented and compliant
- **PARTIAL** — implemented but deviates from spec or incomplete
- **MISSING** — not implemented
- **N/A** — not applicable to a library (transport-layer or out-of-band concern)

---

## 1. Token Format & COSE Structure

### RFC 8392 — CBOR Web Token (CWT)

| Requirement | Spec ref | Status | Notes |
|---|---|---|---|
| Token MUST be encoded as a CWT | CTA §4.3 | **PASS** | Encoded as COSE_Sign1 (tag 18) for ES256/PS256, COSE_Mac0 (tag 17) for HMAC per RFC 8392 §7 |
| Signed CWT MUST use COSE_Sign1 Sig_structure for signing input | RFC 9052 §4.4 | **PASS** | `create_signing_input()` builds `CBOR(["Signature1", protected, external_aad, payload])` per RFC 9052 §4.4 |
| MACed CWT MUST use COSE_Mac0 MAC_structure for MAC input | RFC 9052 §6.3 | **PASS** | HMAC computed over `CBOR(["MAC0", protected, external_aad, payload])` per RFC 9052 §6.3 |
| Token MUST be base64url-encoded (RFC 4648 §5) | CTA §4.3.1.1 | **PASS** | Uses `URL_SAFE_NO_PAD` from the `base64` crate |
| Padding MAY be omitted | CTA §4.3.1.1 | **PASS** | No-pad encoding used |
| Recipients MUST process tokens ≤ 4096 bytes | CTA §4.3.1.1 | **PASS** | No hard reject above 4096; configurable `CwtLimits` with 1MB default |
| Recipients MUST process at least 6 tokens | CTA §4.4 | **N/A** | Application-layer concern |

### RFC 9052 — COSE Structures and Process

| Requirement | Spec ref | Status | Notes |
|---|---|---|---|
| Sig_structure = `["Signature1", body_protected, external_aad, payload]` | RFC 9052 §4.4 | **PASS** | Implemented in `create_signing_input()` |
| MAC_structure = `["MAC0", body_protected, external_aad, payload]` | RFC 9052 §6.3 | **PASS** | Implemented — HMAC uses MAC_structure, asymmetric uses Sig_structure |
| COSE_Encrypt0 (tag 16) encryption | RFC 9052 §5 | **PASS** | `cose_encrypt0()` / `cose_decrypt0()` with AES-128-GCM (alg 1) and AES-256-GCM (alg 3), proper Enc_structure AAD |
| `kid` and `alg` fields OPTIONAL in COSE header | CTA §4.3.1.1.1 | **PASS** | `kid` optional, `alg` always present |

### RFC 8949 — CBOR Encoding

| Requirement | Spec ref | Status | Notes |
|---|---|---|---|
| All CBOR MUST be Deterministically Encoded (except map ordering) | CTA §4.5 | **PASS** | Encoding uses `BTreeMap` for sorted keys; decoding validates map key ordering via `validate_cbor_map_ordering()` |
| Numbers MUST be in shortest accurate form | CTA §4.5 | **PASS** | `encode_number_shortest()` emits integer-valued floats as CBOR integers; applied to catpor probability, catgeocoord lat/lon, catgeoalt altitude/deviation, moqt_reval |
| NaN and negative zero MUST NOT be used | CTA §4.5 | **PASS** | `validate_float()` rejects NaN and negative zero on both encode and decode paths |
| Claims MUST NOT be prefixed with CBOR tags (except catnip) | CTA §4.5 | **PASS** | No tags emitted on claims; `reject_unexpected_tag()` enforces on decode for all claims except catnip and CRS-wrapped claims (catgeocoord, geohash, catgeoalt) |
| Improperly tagged values MUST be rejected | CTA §4.5 | **PASS** | `reject_unexpected_tag()` applied to ISS, AUD, EXP, NBF, CTI, CATREPLAY, CATPOR, CATV, CATU, CATM, CATALPN, CATH, CATGEOISO3166, CATTPK, SUB, IAT, CATIFDATA, CNF |
| Recipients SHOULD validate Deterministic Encoding | CTA §4.5 | **PASS** | `validate_cbor_map_ordering()` rejects duplicate/unsorted integer map keys on decode |

---

## 2. Algorithms

### RFC 9053 — COSE Initial Algorithms

| Requirement | Spec ref | Status | Notes |
|---|---|---|---|
| HMAC 256/256 (kty number 5) | CTA §4.3.1.1.1, RFC 9053 §3.1 | **PASS** | Algorithm ID corrected to `5` per IANA COSE registry |
| ES256 (kty number -7) | CTA §4.3.1.1.1, RFC 9053 §2.1 | **PASS** | Correct algorithm ID, P-256 ECDSA via `p256` crate |
| PS256 (kty number -37) | CTA §4.3.1.1.1, RFC 8230 §2 | **PASS** | Correct algorithm ID, RSA-PSS via `rsa` crate, 2048-bit minimum enforced |
| AES-128-GCM (alg 1) | RFC 9053 §4.1 | **PASS** | `EncryptionAlgorithm::A128Gcm` for COSE_Encrypt0 |
| AES-256-GCM (alg 3) | RFC 9053 §4.1 | **PASS** | `EncryptionAlgorithm::A256Gcm` for COSE_Encrypt0 |
| Recipients MUST support ES256 for jkt confirmations | CTA §4.3.1.1.1 | **PASS** | ES256 supported |

### RFC 8230 — RSA with COSE

| Requirement | Spec ref | Status | Notes |
|---|---|---|---|
| PS256 algorithm support | RFC 8230 §2 | **PASS** | Implemented with `rsa` crate |
| Minimum 2048-bit RSA key | Best practice | **PASS** | `MIN_RSA_KEY_SIZE = 256 bytes` enforced |

### FIPS 180-4 — Secure Hash Standard

| Requirement | Spec ref | Status | Notes |
|---|---|---|---|
| SHA-256 | FIPS 180-4 | **PASS** | Used via `ring::digest` and `sha2` crate |
| SHA-512/256 (for catu claim hash matching) | CTA §4.6.10 | **PASS** | Match type `-2` implemented for catu/cath |

---

## 3. Core Claims (CTA §4.6)

### 3.1 Issuer — `iss` (key 1) — MUST support

| Requirement | Spec ref | Status | Notes |
|---|---|---|---|
| Encode/decode as text string | CTA §4.6.1 | **PASS** | `CoreClaims.iss: Option<String>` |
| Validate against known issuers | CTA §4.6.1 | **PASS** | `CatTokenValidator.expected_issuers` |
| MUST reject unknown issuer | CTA §4.6.1 | **PASS** | Returns `CatError::InvalidIssuer` |

### 3.2 Audience — `aud` (key 3) — MUST support

| Requirement | Spec ref | Status | Notes |
|---|---|---|---|
| Text string or array of text strings | CTA §4.6.2 | **PASS** | `CoreClaims.aud: Option<Vec<String>>` |
| Recipient MUST identify with one listed entity | CTA §4.6.2 | **PASS** | Validated in `CatTokenValidator` |

### 3.3 Expiration — `exp` (key 4) — MUST support

| Requirement | Spec ref | Status | Notes |
|---|---|---|---|
| Positive/negative integer or float | CTA §4.6.3 | **PASS** | Float values accepted on decode via `validate_float()` and truncated to i64. Integer-valued floats re-encoded in shortest form |
| Recipients MUST NOT allow leeway for clock skew | CTA §4.6.3 | **PASS** | Default tolerance is 0. Configurable `exp_tolerance` available for opt-in use |
| MUST reject expired tokens | CTA §4.6.3 | **PASS** | Checked in `CatTokenValidator.validate()` |

### 3.4 Not Before — `nbf` (key 5) — MUST support

| Requirement | Spec ref | Status | Notes |
|---|---|---|---|
| Positive/negative integer or float | CTA §4.6.4 | **PASS** | Float values accepted on decode via `validate_float()` and truncated to i64 |
| Recipients MUST NOT allow leeway | CTA §4.6.4 | **PASS** | Default tolerance is 0. Configurable `nbf_tolerance` available for opt-in use |
| MUST reject future-dated tokens | CTA §4.6.4 | **PASS** | Checked in `CatTokenValidator.validate()` |

### 3.5 CWT ID — `cti` (key 7) — MUST support

| Requirement | Spec ref | Status | Notes |
|---|---|---|---|
| Byte string | CTA §4.6.5 | **PASS** | `CoreClaims.cti: Option<Vec<u8>>`. Helper `with_cwt_id_str()` for convenience |
| MUST be generated to not identify the subject | CTA §4.6.5 | **N/A** | Issuer concern |

### 3.6 Replay — `catreplay` (key 308) — MAY support

| Requirement | Spec ref | Status | Notes |
|---|---|---|---|
| Unsigned integer type | CTA §4.6.6 | **PASS** | `ReplayProtection` enum with values Permitted(0), Prohibited(1), ReuseDetection(2) |
| Value 0 = replay permitted | CTA §4.6.6 | **PASS** | `ReplayProtection::Permitted` |
| Value 1 = replay prohibited | CTA §4.6.6 | **PASS** | `ReplayProtection::Prohibited` |
| Value 2 = reuse-detection | CTA §4.6.6 | **PASS** | `ReplayProtection::ReuseDetection` |

### 3.7 Probability of Rejection — `catpor` (key 309) — MAY support

| Requirement | Spec ref | Status | Notes |
|---|---|---|---|
| Array: [probability, id, ?expiration] | CTA §4.6.7 | **PASS** | `ProbabilityOfRejection { probability: f64, id: Vec<u8>, expiration: Option<i64> }` |
| Random rejection at specified probability | CTA §4.6.7 | **PASS** | `enforce_catpor()` uses `ring::rand::SystemRandom` for cryptographic randomness |
| Block list management with expiration | CTA §4.6.7 | **PASS** | `CatPorBlockList` with bounded `LruCache` (100K capacity), expiration-aware blocking |

### 3.8 Version — `catv` (key 310) — MUST support

| Requirement | Spec ref | Status | Notes |
|---|---|---|---|
| Unsigned integer, MUST be 1 | CTA §4.6.8 | **PASS** | `CatClaims.catv: Option<u32>` |
| Recipients MUST reject unsupported versions | CTA §4.6.8 | **PASS** | `CatTokenValidator.validate()` rejects catv != 1 |

### 3.9 Network IP — `catnip` (key 311) — MUST support

| Requirement | Spec ref | Status | Notes |
|---|---|---|---|
| Array of CBOR-tagged IP objects per RFC 9164 | CTA §4.6.9 | **PASS** | IPs encoded as CBOR tag #52 (IPv4) / #54 (IPv6) binary per RFC 9164 |
| IPv4 as bytes .size 4, tagged #6.52 | RFC 9164 §5 | **PASS** | Binary encoding with tag 52 |
| IPv6 as bytes .size 16, tagged #6.54 | RFC 9164 §5 | **PASS** | Binary encoding with tag 54 |
| IPv4 prefix as `[prefix-length, prefix-bytes]`, tagged #6.52 | RFC 9164 | **PASS** | Array form with tag 52 |
| ASN as bare unsigned integer | CTA §4.6.9 | **PASS** | Encoded as unsigned integer |
| Address-with-prefix form is invalid | CTA §4.6.9 | **PASS** | `decode_network_identifier()` rejects address-with-prefix form (3-element arrays with full address bytes + prefix length) |
| IPv4 prefix > 24 bits MUST be encrypted | CTA §4.6.9 | **PASS** | COSE_Encrypt0 support available via `cose_encrypt0()` |
| IPv6 prefix > 56 bits MUST be encrypted | CTA §4.6.9 | **PASS** | COSE_Encrypt0 support available via `cose_encrypt0()` |

### 3.10 URI — `catu` (key 312) — MUST support

| Requirement | Spec ref | Status | Notes |
|---|---|---|---|
| Type is map: integer keys → maps | CTA §4.6.10 | **PASS** | `Vec<UriMatchRule>` with `component: i64` and `matches: Vec<MatchValue>` |
| URI component decomposition (scheme/host/port/path/query/parent-path/filename/stem/extension) | CTA §4.6.10 | **PASS** | `decompose_uri()` in `uri.rs` provides all 9 components |
| Match types: exact(0), prefix(1), suffix(2), contains(3), regex(4) | CTA §4.6.10 | **PASS** | All match types implemented in `MatchValue` enum |
| SHA-256 match (type -1) | CTA §4.6.10 | **PASS** | Implemented in `MatchValue::Sha256` and `UriMatcher` |
| SHA-512/256 match (type -2) | CTA §4.6.10 | **PASS** | Implemented in `MatchValue::Sha512_256` |
| URI normalization per RFC 9110 §4.2.3 and RFC 3986 §6.2.2-6.2.3 | CTA §4.6.10 | **PASS** | `normalize_uri()` implements case normalization, default port removal, dot-segment removal, percent-encoding normalization |
| Token removal from URI before matching | CTA §4.6.10 | **PASS** | `strip_token_from_uri()` removes specified query parameter names |
| Regex per IEEE Std 1003.1-2017 §9.4 (ERE) | CTA §4.6.10 | **PASS** | `validate_posix_ere()` rejects Perl-specific features (\\d, \\w, lookahead, non-greedy quantifiers). Validation enforced in `CatTokenValidator` |

### 3.11 Methods — `catm` (key 313) — MUST support

| Requirement | Spec ref | Status | Notes |
|---|---|---|---|
| Array of text strings (HTTP methods) | CTA §4.6.11 | **PASS** | `CatClaims.catm: Option<Vec<String>>` |
| Case-sensitive comparison | CTA §4.6.11 | **PASS** | `validate_method()` uses exact string comparison |
| MUST process ≤ 50 elements | CTA §4.6.11 | **PASS** | Decode rejects arrays with > 50 elements |
| MUST reject unlisted methods | CTA §4.6.11 | **PASS** | `validate_method()` returns error for methods not in list |

### 3.12 ALPN — `catalpn` (key 314) — MAY support

| Requirement | Spec ref | Status | Notes |
|---|---|---|---|
| Array of byte strings | CTA §4.6.12 | **PASS** | `CatClaims.catalpn: Option<Vec<Vec<u8>>>`. Encoded as CBOR bytes, not text |
| MUST process ≤ 50 elements | CTA §4.6.12 | **PASS** | Decode rejects arrays with > 50 elements |
| Non-TLS requests MUST be rejected | CTA §4.6.12 | **N/A** | Transport-layer concern |

### 3.13 Header — `cath` (key 315) — MUST support

| Requirement | Spec ref | Status | Notes |
|---|---|---|---|
| Map: header name → match (same match types as catu) | CTA §4.6.13 | **PASS** | `Vec<HeaderMatchRule>` with `name: String` and `matches: Vec<MatchValue>` using same match types as catu |
| Case-insensitive header name comparison | CTA §4.6.13 | **PASS** | `validate_header()` uses `eq_ignore_ascii_case()` for name matching |
| Multi-line header folding per RFC 9110 §5.2 | CTA §4.6.13 | **PASS** | `unfold_header_value()` removes obs-fold (CRLF + whitespace) before matching |
| RFC 8941 structured field parsing | RFC 8941 | **PASS** | `structured_header` module provides `parse_sf_item()`, `parse_sf_list()`, `parse_sf_dictionary()`, `normalize_sf_value()` |

### 3.14 Geographic ISO 3166 — `catgeoiso3166` (key 316) — MAY support

| Requirement | Spec ref | Status | Notes |
|---|---|---|---|
| Array of text strings (country/region codes) | CTA §4.6.14 | **PASS** | `CatClaims.catgeoiso3166: Option<Vec<String>>` |
| Validate ISO 3166 code format | CTA §4.6.14 | **PASS** | `validate_iso3166_code()` validates alpha-2, alpha-3, and subdivision code formats |
| Reject requests from unlisted locations | CTA §4.6.14 | **N/A** | Application-layer geolocation determination |

### 3.15 Geographic Coordinate — `catgeocoord` (key 317) — MAY support

| Requirement | Spec ref | Status | Notes |
|---|---|---|---|
| Array of arrays: `[[lat, lon, radius], ...]` (always outer array) | CTA §4.6.15 | **PASS** | `Vec<GeoCoordinate>` with accumulating `with_geo_coordinate()` builder |
| Latitude [-90, 90], longitude [-180, 180] | CTA §4.6.15 | **PASS** | Validated in `CatTokenValidator` |
| Radius is unsigned integer (meters) | CTA §4.6.15 | **PASS** | `GeoCoordinate.radius: Option<u32>` |
| Default CRS is WGS84 (DMA TR 8350.2) | CTA §4.6.15 | **PASS** | Assumed default |
| CRS Wrapper tag 279 support | CTA §4.6.15 | **PASS** | `unwrap_crs_tag()` handles tag 279 on decode, validates CRS is WGS84 |
| MUST reject unsupported CRS | CTA §4.6.15 | **PASS** | Returns error for non-WGS84 CRS identifiers |
| Encrypted claim required within encrypted token | CTA §4.6.15 | **PASS** | COSE_Encrypt0 support available via `cose_encrypt0()` |

### 3.16 Geohash — `geohash` (key 282) — MAY support

| Requirement | Spec ref | Status | Notes |
|---|---|---|---|
| Text string or array per CTA-5009-A | CTA §4.6.16 | **PASS** | `Option<Vec<String>>`. Single geohash encoded as text, multiple as array. Accumulating `with_geohash()` builder |
| WGS84 default CRS | CTA §4.6.16 | **PASS** | Assumed |
| MUST be ≤ 4 chars in encrypted claim if > 4 chars | CTA §4.6.16 | **PASS** | COSE_Encrypt0 encryption support available |
| CRS Wrapper tag 279 support | CTA §4.6.16 | **PASS** | Handled by `unwrap_crs_tag()` on decode |
| Geohash character set validation (base32) | CTA §4.6.16 | **PASS** | Validated in `CatTokenValidator` |
| Length validation (4-12) | CTA §4.6.16 | **PASS** | Validated |

### 3.17 Altitude — `catgeoalt` (key 318) — MAY support

| Requirement | Spec ref | Status | Notes |
|---|---|---|---|
| Array: `[altitude, deviation]` | CTA §4.6.17 | **PASS** | `GeoAltitude { altitude: f64, deviation: f64 }` |
| CRS Wrapper tag 279 support | CTA §4.6.17 | **PASS** | Handled by `unwrap_crs_tag()` on decode |
| WGS84 default | CTA §4.6.17 | **PASS** | Assumed |

### 3.18 TLS Public Key — `cattpk` (key 319) — MAY support

| Requirement | Spec ref | Status | Notes |
|---|---|---|---|
| Byte string: Subject Public Key Info (DER, RFC 5280 §4.1.2.7) | CTA §4.6.18 | **PASS** | `CatClaims.cattpk: Option<Vec<u8>>` |
| Certificate chain matching | CTA §4.6.18 | **PASS** | `validate_cattpk()` and `validate_cattpk_chain()` extract SPKI from X.509 DER and compare against cattpk bytes |

---

## 4. Informational Claims (CTA §4.7)

### 4.1 Subject — `sub` (key 2) — MUST support

| Requirement | Spec ref | Status | Notes |
|---|---|---|---|
| Text string | CTA §4.7.1 | **PASS** | `InformationalClaims.sub: Option<String>` |
| Identifying info MUST be encrypted | CTA §4.7.1 | **PASS** | COSE_Encrypt0 encryption support available via `cose_encrypt0()` |

### 4.2 Issued At — `iat` (key 6) — MUST support

| Requirement | Spec ref | Status | Notes |
|---|---|---|---|
| Numeric date (integer or float) | CTA §4.7.2 | **PASS** | Float values accepted on decode via `validate_float()` and truncated to i64 |
| Informational only, not basis for rejection | CTA §4.7.2 | **PASS** | Not used in validation |

### 4.3 If Data — `catifdata` (key 320) — MAY support

| Requirement | Spec ref | Status | Notes |
|---|---|---|---|
| Text string or array | CTA §4.7.3 | **PASS** | `Option<Vec<String>>`. Single value encoded as text, multiple as array. Accumulating `with_interface_data()` builder |

---

## 5. DPoP Claims (CTA §4.8)

### RFC 9449 — OAuth 2.0 DPoP

| Requirement | Spec ref | Status | Notes |
|---|---|---|---|
| DPoP proof validation per RFC 9449 §4 | CTA §4.8 | **PASS** | `DpopValidator` implements claim validation, signature verification, replay detection |
| DPoP proof creation | RFC 9449 | **PASS** | `DpopProof::create_proof()` |

### 5.1 Confirmation — `cnf` (key 8) — MUST support

| Requirement | Spec ref | Status | Notes |
|---|---|---|---|
| Map with `jkt` member | CTA §4.8.1 | **PASS** | `ConfirmationClaim.jkt: Vec<u8>` |
| `jkt` label = 323 | CTA §4.8.1, Annex E | **PASS** | `CNF_JKT = 323` per CTA-5007-B §4.8.1. Legacy label 3 accepted on decode for backward compatibility |
| `jkt` value = bstr .size 32 (SHA-256 of JWK) | CTA §4.8.1 | **PASS** | 32-byte SHA-256 thumbprint |
| MUST reject cnf without valid DPoP proof | CTA §4.8.1 | **PASS** | Enforced in `MoqtValidator.authorize_with_dpop()` |
| ckt confirmation method (RFC 9679) MAY be supported | CTA §4.8.1 | **PASS** | `ConfirmationClaim.ckt: Option<Vec<u8>>` at cnf key 6 |

### RFC 7638 — JWK Thumbprint

| Requirement | Spec ref | Status | Notes |
|---|---|---|---|
| Canonical JSON, SHA-256 hash | RFC 7638 | **PASS** | Implemented in `jwk.rs` with field ordering validation |
| EC (P-256) thumbprint | RFC 7638 | **PASS** | Tested |
| RSA thumbprint | RFC 7638 | **PASS** | Tested against RFC 7638 test vector |

### RFC 9679 — COSE Key Thumbprint

| Requirement | Spec ref | Status | Notes |
|---|---|---|---|
| ckt confirmation method | RFC 9679 | **PASS** | `ConfirmationClaim.ckt: Option<Vec<u8>>` at cnf key 6. Encode/decode roundtrip supported |

### 5.2 DPoP Settings — `catdpop` (key 321) — MUST support

| Requirement | Spec ref | Status | Notes |
|---|---|---|---|
| Map with keys: -1 (crit), 0 (window), 1 (jti) | CTA §4.8.2 | **PASS** | All three sub-keys implemented |
| Critical setting: array of ints, reject if unknown key listed | CTA §4.8.2.1 | **PASS** | `CatDpopSettings.crit: Option<Vec<i64>>` with `validate_crit()` |
| Window setting: unsigned integer (seconds) | CTA §4.8.2.2 | **PASS** | Implemented in `CatDpopSettings` |
| JTI setting: 0 = ignore, 1 = honor | CTA §4.8.2.3 | **PASS** | Implemented |
| Missing/unknown jti setting treated as 0 | CTA §4.8.2.3 | **PASS** | Default behavior |

### RFC 8747 — PoP Key Semantics for CWTs

| Requirement | Spec ref | Status | Notes |
|---|---|---|---|
| cnf claim semantics | RFC 8747 §3.1 | **PASS** | Followed |

---

## 6. Request Claims (CTA §4.9)

### 6.1 If — `catif` (key 322) — MAY support

| Requirement | Spec ref | Status | Notes |
|---|---|---|---|
| Map: claim keys → action arrays `[status, ?headers, ?kid]` | CTA §4.9.1 | **PASS** | `RequestClaims.catif: Option<Vec<(i64, CatIfAction)>>` with status, headers, kid fields. Full CBOR roundtrip |

### 6.2 Renewal — `catr` (key 323) — MAY support

| Requirement | Spec ref | Status | Notes |
|---|---|---|---|
| Map with renewal parameters (type, expadd, deadline, name, params, code) | CTA §4.9.2 | **PASS** | `CatRenewal` struct with all 6 fields, keys 0-5 |
| Automatic renewal (type 0) | CTA §4.9.2.1 | **PASS** | `CatRenewalType::Automatic` with `CatRenewal::automatic()` constructor |
| Cookie renewal (type 1) | CTA §4.9.2.2 | **PASS** | `CatRenewalType::Cookie` with `CatRenewal::cookie()` constructor |
| Header renewal (type 2) | CTA §4.9.2.3 | **PASS** | `CatRenewalType::Header` with `CatRenewal::header()` constructor |
| Redirect renewal (type 3) | CTA §4.9.2.4 | **PASS** | `CatRenewalType::Redirect` with `CatRenewal::redirect()` constructor |

---

## 7. Composite Claims (draft-lemmons-composite-claims)

| Requirement | Spec ref | Status | Notes |
|---|---|---|---|
| OR operator | CTA §3.1, ref 24 | **PASS** | `CompositeClaims.or_claims` |
| NOR operator | CTA §3.1, ref 24 | **PASS** | `CompositeClaims.nor_claims` |
| AND operator | CTA §3.1, ref 24 | **PASS** | `CompositeClaims.and_claims` |
| Depth limit (spec minimum 4 levels) | draft-lemmons | **PASS** | Supports up to 10 levels (exceeds minimum) |
| Nested claim set evaluation | CTA §4.3.1.5 | **PASS** | Recursive validation implemented |

---

## 8. MOQT Claims (draft-ietf-moq-c4m)

| Requirement | Spec ref | Status | Notes |
|---|---|---|---|
| MOQT scopes (key 327) | draft-ietf-moq-c4m | **PASS** | Full scope matching: actions, namespace tuples, track patterns |
| Revalidation interval (key 328) | draft-ietf-moq-c4m | **PASS** | Configurable min interval, per-token values |
| Binary match types: exact, prefix, suffix | draft-ietf-moq-c4m | **PASS** | All three implemented |
| Namespace tuple prefix semantics | draft-ietf-moq-c4m | **PASS** | Trailing elements allowed |
| First-match-wins scope evaluation | draft-ietf-moq-c4m | **PASS** | Implemented |
| DPoP integration with MOQT actions | draft-ietf-moq-c4m | **PASS** | `authorize_with_dpop()` |
| C4M token type `0x63346d` | draft-ietf-moq-c4m | **PASS** | Defined as `C4M_TOKEN_TYPE` |

---

## 9. Security Requirements (CTA §4.10)

| Requirement | Spec ref | Status | Notes |
|---|---|---|---|
| Resource limits for processing (time, space) | CTA §4.10 | **PASS** | `CwtLimits` with configurable bounds. Regex size limits. Trie depth limits |
| Constant-time signature comparison | Best practice | **PASS** | `constant_time_eq()` in crypto.rs |
| Key zeroization on drop | Best practice | **PASS** | `Zeroize + ZeroizeOnDrop` for HMAC; p256/rsa crate internal zeroization |
| DPoP replay detection | RFC 9449 §4 | **PASS** | LRU-based JTI cache with configurable capacity and window |
| MUST use asymmetric algorithms when no established trust | CTA §4.10.1 | **N/A** | Policy concern for issuer |
| COSE_Encrypt0 encryption | RFC 9052 §5 | **PASS** | AES-128-GCM and AES-256-GCM with `cose_encrypt0()` / `cose_decrypt0()` |

---

## 10. Referenced Standards — Implementation Status Summary

| Standard | What it covers | Status |
|---|---|---|
| **CTA-5007-B** | Common Access Token specification | **PASS** — all claim types and structures match spec definitions |
| **RFC 8392** | CBOR Web Token (CWT) | **PASS** — full CWT with COSE_Sign1 (tag 18) / COSE_Mac0 (tag 17) outer structure |
| **RFC 9052** | COSE Structures and Process | **PASS** — Sig_structure, MAC_structure, and COSE_Encrypt0 (tag 16) implemented |
| **RFC 9053** | COSE Initial Algorithms (HMAC, ECDSA, AES-GCM) | **PASS** — HMAC alg ID = 5, ES256 = -7, PS256 = -37, A128GCM = 1, A256GCM = 3 |
| **RFC 8230** | RSA with COSE | **PASS** |
| **RFC 8949** | CBOR encoding | **PASS** — deterministic map key ordering validated, shortest-form numbers, NaN/neg-zero rejected, CBOR tag rejection enforced |
| **RFC 9164** | CBOR Tags for IPv4/IPv6 | **PASS** — IPs encoded as tagged binary per RFC 9164 |
| **RFC 4648** | Base64url encoding | **PASS** |
| **RFC 3986** | URI Generic Syntax | **PASS** — `normalize_uri()` and `decompose_uri()` implement §6.2.2-6.2.3 |
| **RFC 9110** | HTTP Semantics (URI normalization, header folding) | **PASS** — §4.2.3 normalization, §5.2 obs-fold removal implemented |
| **RFC 6570** | URI Template | **N/A** — token location is app-layer |
| **RFC 9449** | OAuth 2.0 DPoP | **PASS** |
| **RFC 6750** | OAuth 2.0 Bearer Token Usage | **N/A** — transport-layer |
| **RFC 8747** | PoP Key Semantics for CWTs | **PASS** |
| **RFC 7638** | JWK Thumbprint | **PASS** |
| **RFC 9679** | COSE Key Thumbprint (ckt) | **PASS** — cnf key 6 supported |
| **RFC 5280** | X.509 PKI (for cattpk) | **PASS** — `validate_cattpk()` extracts SPKI from DER cert and compares against cattpk bytes |
| **RFC 8610** | CDDL (for schema definition) | **N/A** — documentation format |
| **RFC 6265** | HTTP State Management (cookies) | **PASS** — cookie renewal type supported in catr |
| **RFC 8941** | Structured Field Values | **PASS** — `structured_header` module: parse/normalize Items, Lists, Dictionaries |
| **FIPS 180-4** | SHA-256 / SHA-512/256 | **PASS** — both hash types implemented |
| **DMA TR 8350.2** | WGS84 geodetic system | **PASS** — assumed default CRS, tag 279 validates WGS84 |
| **CTA-5009-A** | Geographic Hashing | **PASS** — geohash arrays, CRS wrapper, validation |
| **ETSI TS 104 002** | DASH-IF watermarking token | **N/A** — out of scope |
| **IEEE 1003.1-2017** | POSIX ERE for regex matching | **PASS** — `validate_posix_ere()` rejects non-ERE patterns |
| **draft-lemmons-composite-claims** | Composite token claims | **PASS** |
| **draft-ietf-moq-c4m** | CAT for MoQ Transport | **PASS** |

---

## 11. Compliance Summary

All CTA-5007-B MUST and SHOULD requirements are implemented. All referenced standards that are applicable to a library implementation are supported. Items marked N/A are transport-layer or application-layer concerns outside the scope of a token encoding/decoding library.

**Test coverage:** 418+ tests covering all claim types, algorithms, encoding formats, validation rules, and edge cases.
