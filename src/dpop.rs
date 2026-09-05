// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

//! DPoP proof-of-possession, CWT wire format.
//!
//! `DpopProof` is a format-neutral in-memory representation: the header, the
//! payload, and the signature. Wire encoding is implemented in submodules so
//! that alternate formats (JWT/JOSE) can be added later without changing the
//! validator or the semantic layer.
//!
//! Current wire format: **COSE_Sign1 CWT** per
//! `draft-nandakumar-moq-generic-dpop-proof-00`. `DpopProof::encode` /
//! `DpopProof::decode` route through [`cwt`]; add a `jwt` sibling module and
//! flip the default when JWT support is needed.

use crate::CatError;
#[cfg(feature = "moqt")]
use crate::claims::CatDpopSettings;
use crate::claims::ConfirmationClaim;
use crate::jwk::Jwk;
#[cfg(feature = "moqt")]
use crate::{CryptographicAlgorithm, Es256Algorithm, MoqtAction, Ps256Algorithm};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
#[cfg(feature = "moqt")]
use lru::LruCache;
#[cfg(feature = "moqt")]
use std::num::NonZeroUsize;
#[cfg(feature = "moqt")]
use std::sync::{Arc, Mutex};
#[cfg(feature = "moqt")]
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// --- Private CWT DPoP profile ---------------------------------------------
//
// draft-nandakumar-moq-generic-dpop-proof-00 leaves the `actx`, `nonce`, and
// `ath` CWT-claim labels marked TBD. Until IANA assigns them we ship a
// frozen private profile keyed by the `typ` string below. Peers that read a
// proof with this exact `typ` MUST use the label constants exported here;
// any IANA-assigned reassignment will ship as a new `typ` version (e.g.
// `dpop-proof+cwt;profile=cta5007b-v2`) so old and new profiles cannot be
// silently confused on the wire.
//
// The `PROFILE` string is included in the `typ` header exactly and is the
// single source of truth for wire-format identity — bump it before shipping
// any change to label numbers, action-name mapping, or actx map shape.

/// Text-string `typ` value in the COSE protected header (RFC 9596 label
/// 16). Includes an explicit `profile=` parameter so that the frozen
/// private-use label assignment below (`actx=400`, `nonce=401`, `ath=402`)
/// is unambiguously identified even if a future IANA registration reuses
/// those numbers for different claims.
pub const DPOP_TYP: &str = "dpop-proof+cwt;profile=cta5007b-v1";

/// Backwards-compatibility alias — earlier revisions accepted a bare
/// `dpop-proof+cwt` in the `typ` header. Callers using pre-v1 proofs must
/// migrate.
#[deprecated(note = "use DPOP_TYP (includes profile=cta5007b-v1)")]
pub const DPOP_TYP_LEGACY: &str = "dpop-proof+cwt";

/// COSE algorithm identifiers accepted for DPoP signing. Symmetric algorithms
/// are forbidden by the draft; asymmetric algorithms only.
///
/// - `-7`  ES256 (RFC 8152)
/// - `-37` PS256 (RFC 8230)
pub const SUPPORTED_DPOP_COSE_ALGORITHMS: &[i64] =
    &[crate::crypto::ALG_ES256, crate::crypto::ALG_PS256];

// --- COSE labels ---------------------------------------------------------
//
// Protected-header labels (RFC 8152 §3.1 / RFC 9596):
pub(crate) const COSE_HDR_ALG: i64 = 1;
pub(crate) const COSE_HDR_COSE_KEY: i64 = 4;
pub(crate) const COSE_HDR_TYP: i64 = 16;

// CWT-payload labels (RFC 8392 + draft-nandakumar-moq-generic-dpop-proof-00).
// Labels 6 and 7 come from the CWT base registry. 400/401/402 are private
// under the profile identifier baked into `DPOP_TYP`; see the module-level
// note above.
pub(crate) const CWT_CLAIM_IAT: i64 = 6;
pub(crate) const CWT_CLAIM_CTI: i64 = 7;
pub(crate) const CWT_CLAIM_ACTX: i64 = 400;
pub(crate) const CWT_CLAIM_NONCE: i64 = 401;
pub(crate) const CWT_CLAIM_ATH: i64 = 402;

// actx inner-map labels (draft §3.2):
pub(crate) const ACTX_TYPE: i64 = 0;
pub(crate) const ACTX_ACTION: i64 = 1;
pub(crate) const ACTX_TNS: i64 = 2;
pub(crate) const ACTX_TN: i64 = 3;
pub(crate) const ACTX_PARAMETERS: i64 = 4;

// COSE_Key labels (RFC 8152 §7):
const COSE_KEY_KTY: i64 = 1;
const COSE_KEY_ALG: i64 = 3;
const COSE_KEY_CRV: i64 = -1;
const COSE_KEY_X: i64 = -2;
const COSE_KEY_Y: i64 = -3;
const COSE_KEY_N: i64 = -1; // RSA n (RFC 8230 §4)
const COSE_KEY_E: i64 = -2; // RSA e (RFC 8230 §4)

const COSE_KTY_EC2: i64 = 2;
const COSE_KTY_RSA: i64 = 3;
const COSE_CRV_P256: i64 = 1;

const COSE_TAG_SIGN1: u64 = 18;

#[cfg(feature = "moqt")]
const MAX_DPOP_WIRE_SIZE: usize = 16 * 1024;

// --- Header --------------------------------------------------------------

/// DPoP protected-header contents. Not the on-wire form: `encode()` maps these
/// fields to the CBOR integer labels required by the CWT wire format.
#[derive(Clone, PartialEq)]
pub struct DpopHeader {
    /// COSE algorithm id (e.g. `-7` for ES256). Symmetric algorithms are
    /// rejected by [`DpopHeader::is_supported_algorithm`].
    pub alg: i64,
    /// Must equal [`DPOP_TYP`] for a valid proof.
    pub typ: String,
    /// Proof-holder's public key. Encoded on the wire as a COSE_Key map under
    /// header label 4; `Jwk` is retained here as the in-memory representation
    /// so JWK-thumbprint (`jkt`) confirmation remains a single implementation.
    pub jwk: Jwk,
}

impl std::fmt::Debug for DpopHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DpopHeader")
            .field("typ", &self.typ)
            .field("alg", &self.alg)
            .field("jwk", &"[REDACTED]")
            .finish()
    }
}

impl DpopHeader {
    pub fn new(alg: i64, jwk: Jwk) -> Self {
        Self {
            alg,
            typ: DPOP_TYP.to_string(),
            jwk,
        }
    }

    pub fn is_valid(&self) -> bool {
        self.typ == DPOP_TYP && self.is_supported_algorithm()
    }

    pub fn is_supported_algorithm(&self) -> bool {
        SUPPORTED_DPOP_COSE_ALGORITHMS.contains(&self.alg)
    }
}

// --- Authorization context ----------------------------------------------

/// DPoP `actx` inner map for CAT-4-MOQT.
///
/// Wire form (CBOR map, integer keys per draft §3.2):
/// - `0 type       = "moqt"` (text)
/// - `1 action     = "SUBSCRIBE" | "PUBLISH" | …` (text, MOQTransport §9)
/// - `2 tns        = canonical MOQ namespace tuple` (text, §1.5.1)
/// - `3 tn         = canonical MOQ track name` (text, §1.5.1)
/// - `4 parameters = additional context` (map, optional)
///
/// `tns` and `tn` are held as raw byte vectors so the authorization layer can
/// compare them against `RelayRequestContext` without re-parsing the wire
/// encoding. Wire serialization is handled by [`cwt::actx_to_cbor`].
#[cfg(feature = "moqt")]
#[derive(Debug, Clone, PartialEq)]
pub struct AuthorizationContext {
    /// Fixed to `"moqt"` for this crate; other protocol namespaces (e.g. a
    /// future `"moqt2"`) can be plugged in without changing the wire format.
    pub ctx_type: String,
    pub action: MoqtAction,
    /// MOQ namespace tuple. Each element is one namespace segment (bytes).
    pub tns: Vec<Vec<u8>>,
    /// MOQ track name (bytes). Empty means "no track" (namespace-only ops).
    pub tn: Vec<u8>,
    /// Optional `moqt://` resource URI. Duplicates information already
    /// present in `tns`/`tn` for audit-log clarity; the two forms must agree
    /// (enforced by `MoqtValidator::authorize`).
    pub resource: Option<String>,
}

#[cfg(feature = "moqt")]
impl AuthorizationContext {
    pub fn new_moqt(action: MoqtAction, namespace: Vec<Vec<u8>>, track: &[u8]) -> Self {
        Self {
            ctx_type: "moqt".to_string(),
            action,
            tns: namespace,
            tn: track.to_vec(),
            resource: None,
        }
    }

    pub fn with_resource(mut self, resource: String) -> Self {
        self.resource = Some(resource);
        self
    }

    pub fn is_valid(&self) -> bool {
        self.ctx_type == "moqt" && !self.tns.is_empty()
    }

    /// MOQTransport §9 action name as it appears in the CBOR-serialized `action`.
    pub fn action_string(&self) -> &'static str {
        moqt_action_wire_name(self.action)
    }
}

/// Text-string wire form of a `MoqtAction`, per MOQTransport §9. This is what
/// the draft's `actx.action` field carries; keep in sync with the enum.
#[cfg(feature = "moqt")]
pub fn moqt_action_wire_name(action: MoqtAction) -> &'static str {
    match action {
        MoqtAction::ClientSetup => "CLIENT_SETUP",
        MoqtAction::ServerSetup => "SERVER_SETUP",
        MoqtAction::PublishNamespace => "PUBLISH_NAMESPACE",
        MoqtAction::SubscribeNamespace => "SUBSCRIBE_NAMESPACE",
        MoqtAction::Subscribe => "SUBSCRIBE",
        MoqtAction::RequestUpdate => "REQUEST_UPDATE",
        MoqtAction::Publish => "PUBLISH",
        MoqtAction::Fetch => "FETCH",
        MoqtAction::TrackStatus => "TRACK_STATUS",
    }
}

/// Parse a MOQTransport §9 action name back into a `MoqtAction`.
#[cfg(feature = "moqt")]
pub fn moqt_action_from_wire_name(name: &str) -> Result<MoqtAction, CatError> {
    match name {
        "CLIENT_SETUP" => Ok(MoqtAction::ClientSetup),
        "SERVER_SETUP" => Ok(MoqtAction::ServerSetup),
        "PUBLISH_NAMESPACE" => Ok(MoqtAction::PublishNamespace),
        "SUBSCRIBE_NAMESPACE" => Ok(MoqtAction::SubscribeNamespace),
        "SUBSCRIBE" => Ok(MoqtAction::Subscribe),
        "REQUEST_UPDATE" => Ok(MoqtAction::RequestUpdate),
        "PUBLISH" => Ok(MoqtAction::Publish),
        "FETCH" => Ok(MoqtAction::Fetch),
        "TRACK_STATUS" => Ok(MoqtAction::TrackStatus),
        other => Err(CatError::InvalidClaimValue(format!(
            "unknown MOQT action '{other}'"
        ))),
    }
}

// --- Payload ------------------------------------------------------------

/// DPoP CWT payload contents. Field names track RFC 8392 / the draft; wire
/// serialization uses integer labels (see [`cwt`]).
#[cfg(feature = "moqt")]
#[derive(Debug, Clone, PartialEq)]
pub struct DpopPayload {
    /// CWT id (`cti`, label 7). Required by the draft. Held as bytes because
    /// the replay layer keys on the raw octets — never on a text decoding.
    pub cti: Option<Vec<u8>>,
    /// Issued-at time in seconds since epoch (label 6).
    pub iat: i64,
    /// MOQT authorization context (label 400).
    pub actx: AuthorizationContext,
    /// Access-token hash (label 402). Raw SHA-256 bytes of the token's exact
    /// wire form. Mandatory when the proof accompanies an access token; see
    /// `MoqtValidator::authorize`.
    pub ath: Option<Vec<u8>>,
    /// Server-provided anti-replay nonce (label 401). Optional.
    pub nonce: Option<String>,
}

#[cfg(feature = "moqt")]
impl DpopPayload {
    pub fn new(actx: AuthorizationContext) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs() as i64;
        Self {
            cti: None,
            iat: now,
            actx,
            ath: None,
            nonce: None,
        }
    }

    pub fn is_valid(&self) -> bool {
        self.actx.is_valid() && self.iat > 0
    }

    pub fn is_fresh(&self, window_seconds: i64) -> bool {
        self.is_fresh_with_future_tolerance(window_seconds, 30)
    }

    pub fn is_fresh_with_future_tolerance(
        &self,
        window_seconds: i64,
        future_tolerance_seconds: i64,
    ) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs() as i64;
        let age = match now.checked_sub(self.iat) {
            Some(a) => a,
            None => return false,
        };
        if age > window_seconds {
            return false;
        }
        if age < -future_tolerance_seconds {
            return false;
        }
        true
    }
}

/// Create a ConfirmationClaim from a JWK
pub fn confirmation_from_jwk(jwk: &Jwk) -> Result<ConfirmationClaim, CatError> {
    let thumbprint = jwk.thumbprint()?;
    Ok(ConfirmationClaim::new(thumbprint))
}

/// Check if a ConfirmationClaim matches a JWK (constant-time comparison)
pub fn confirmation_matches_jwk(cnf: &ConfirmationClaim, jwk: &Jwk) -> Result<bool, CatError> {
    let thumbprint = jwk.thumbprint()?;
    Ok(crate::crypto::constant_time_eq(&cnf.jkt, &thumbprint))
}

// --- Proof --------------------------------------------------------------

/// In-memory DPoP proof. Format-neutral: `encode()`/`decode()` route through
/// the CWT wire codec, but the fields have no wire dependency of their own.
#[cfg(feature = "moqt")]
#[derive(Clone)]
pub struct DpopProof {
    pub(crate) header: DpopHeader,
    pub(crate) payload: DpopPayload,
    pub(crate) signature: Vec<u8>,
    /// Exact protected-header + payload bytes the signature covers, as
    /// received on the wire (COSE `Sig_structure` input, or blank for
    /// locally-built proofs until [`sign`] runs). Preserving these bytes lets
    /// the verifier operate on the received input rather than re-serializing —
    /// see RFC 8152 §4.4.
    pub(crate) signed_bytes: SignedInput,
}

#[cfg(feature = "moqt")]
#[derive(Clone, Default)]
pub(crate) struct SignedInput {
    pub(crate) header_cbor: Vec<u8>,
    pub(crate) payload_cbor: Vec<u8>,
}

#[cfg(feature = "moqt")]
impl SignedInput {
    fn is_empty(&self) -> bool {
        self.header_cbor.is_empty() && self.payload_cbor.is_empty()
    }
}

#[cfg(feature = "moqt")]
impl std::fmt::Debug for DpopProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DpopProof")
            .field("header", &self.header)
            .field("payload", &self.payload)
            .field("signature", &format!("[{} bytes]", self.signature.len()))
            .finish()
    }
}

#[cfg(feature = "moqt")]
impl DpopProof {
    pub fn new(header: DpopHeader, payload: DpopPayload, signature: Vec<u8>) -> Self {
        Self {
            header,
            payload,
            signature,
            signed_bytes: SignedInput::default(),
        }
    }

    pub fn header(&self) -> &DpopHeader {
        &self.header
    }

    pub fn payload(&self) -> &DpopPayload {
        &self.payload
    }

    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// Build an unsigned proof for a MOQT request. Alg is passed as a COSE
    /// algorithm id (e.g. `-7` for ES256).
    pub fn create_for_moqt(
        action: MoqtAction,
        namespace: Vec<Vec<u8>>,
        track: &[u8],
        alg: i64,
        jwk: Jwk,
    ) -> Self {
        let header = DpopHeader::new(alg, jwk);
        let actx = AuthorizationContext::new_moqt(action, namespace, track);
        let payload = DpopPayload::new(actx);
        Self {
            header,
            payload,
            signature: Vec::new(),
            signed_bytes: SignedInput::default(),
        }
    }

    pub fn with_cti(mut self, cti: impl Into<Vec<u8>>) -> Self {
        self.payload.cti = Some(cti.into());
        self.signed_bytes = SignedInput::default();
        self
    }

    /// Kept for compatibility with callers that supply a `jti` as a text
    /// string; stored as UTF-8 bytes in `cti`.
    pub fn with_jti(mut self, jti: String) -> Self {
        self.payload.cti = Some(jti.into_bytes());
        self.signed_bytes = SignedInput::default();
        self
    }

    pub fn with_resource(mut self, resource: String) -> Self {
        self.payload.actx.resource = Some(resource);
        self.signed_bytes = SignedInput::default();
        self
    }

    /// Set the access-token hash (`ath`) as raw SHA-256 bytes. Accepts either
    /// bytes or a base64url-encoded string; the string form is decoded so
    /// callers can pass the output of [`compute_access_token_hash_b64`].
    pub fn with_access_token_hash(mut self, ath: impl Into<AthInput>) -> Self {
        self.payload.ath = Some(ath.into().into_bytes());
        self.signed_bytes = SignedInput::default();
        self
    }

    pub fn with_nonce(mut self, nonce: String) -> Self {
        self.payload.nonce = Some(nonce);
        self.signed_bytes = SignedInput::default();
        self
    }

    /// Returns the COSE `Sig_structure` bytes the signature was (or will be)
    /// computed over. For decoded proofs this reflects the received wire
    /// bytes; for locally-built proofs it is derived at sign time.
    pub fn signing_input(&self) -> Result<Vec<u8>, CatError> {
        let SignedInput {
            header_cbor,
            payload_cbor,
        } = if self.signed_bytes.is_empty() {
            cwt::encode_header_and_payload(&self.header, &self.payload)?
        } else {
            self.signed_bytes.clone()
        };
        crate::crypto::create_signing_input(&header_cbor, &payload_cbor, self.header.alg)
    }

    pub fn sign(&mut self, algorithm: &dyn CryptographicAlgorithm) -> Result<(), CatError> {
        if algorithm.algorithm_id() != self.header.alg {
            return Err(CatError::AlgorithmMismatch {
                expected: self.header.alg,
                found: algorithm.algorithm_id(),
            });
        }
        let bytes = cwt::encode_header_and_payload(&self.header, &self.payload)?;
        let sig_input = crate::crypto::create_signing_input(
            &bytes.header_cbor,
            &bytes.payload_cbor,
            self.header.alg,
        )?;
        self.signature = algorithm.sign(&sig_input)?;
        self.signed_bytes = bytes;
        Ok(())
    }

    /// Encode this proof as a COSE_Sign1 CWT (tag 18). Returns the raw CBOR
    /// bytes suitable for transport (e.g. in a `DPoP` HTTP header carrying a
    /// base64url-encoded copy, or the wire-native form for MOQT control
    /// messages).
    pub fn encode(&self) -> Result<Vec<u8>, CatError> {
        cwt::encode(self)
    }

    /// Decode a proof from COSE_Sign1 CBOR bytes. See [`cwt::decode`] for the
    /// exact acceptance rules.
    pub fn decode(bytes: &[u8]) -> Result<Self, CatError> {
        cwt::decode(bytes)
    }

    pub fn is_valid(&self, settings: &CatDpopSettings) -> bool {
        settings.validate_crit().is_ok()
            && self.header.is_valid()
            && self.payload.is_valid()
            && self.payload.is_fresh(settings.effective_window())
            && !self.signature.is_empty()
    }

    pub fn validate_with_settings(&self, settings: &CatDpopSettings) -> Result<(), CatError> {
        settings.validate_crit()?;
        if !self.header.is_valid() {
            return Err(CatError::DpopValidationFailed("Invalid header".to_string()));
        }
        if !self.payload.is_valid() {
            return Err(CatError::DpopValidationFailed(
                "Invalid payload".to_string(),
            ));
        }
        if !self.payload.is_fresh(settings.effective_window()) {
            return Err(CatError::DpopValidationFailed("Proof expired".to_string()));
        }
        if self.signature.is_empty() {
            return Err(CatError::DpopValidationFailed(
                "Missing signature".to_string(),
            ));
        }
        Ok(())
    }
}

/// Input flavor for [`DpopProof::with_access_token_hash`]. Callers can pass
/// raw bytes or the base64url form produced by [`compute_access_token_hash_b64`].
#[cfg(feature = "moqt")]
pub enum AthInput {
    Bytes(Vec<u8>),
    Base64(String),
}

#[cfg(feature = "moqt")]
impl AthInput {
    fn into_bytes(self) -> Vec<u8> {
        match self {
            AthInput::Bytes(b) => b,
            AthInput::Base64(s) => URL_SAFE_NO_PAD
                .decode(&s)
                .unwrap_or_else(|_| s.into_bytes()),
        }
    }
}

#[cfg(feature = "moqt")]
impl From<Vec<u8>> for AthInput {
    fn from(v: Vec<u8>) -> Self {
        AthInput::Bytes(v)
    }
}

#[cfg(feature = "moqt")]
impl From<&[u8]> for AthInput {
    fn from(v: &[u8]) -> Self {
        AthInput::Bytes(v.to_vec())
    }
}

#[cfg(feature = "moqt")]
impl From<String> for AthInput {
    fn from(s: String) -> Self {
        AthInput::Base64(s)
    }
}

#[cfg(feature = "moqt")]
impl From<&str> for AthInput {
    fn from(s: &str) -> Self {
        AthInput::Base64(s.to_string())
    }
}

// --- CWT wire codec -----------------------------------------------------

/// COSE_Sign1 CWT wire format for DPoP proofs.
///
/// This is the sole wire format shipped with the crate today. A JWT/JOSE
/// alternative can be added as a sibling `jwt` module later — the semantic
/// types above are format-neutral.
#[cfg(feature = "moqt")]
pub mod cwt {
    use super::*;
    use ciborium::Value;

    pub(super) fn encode(proof: &DpopProof) -> Result<Vec<u8>, CatError> {
        let SignedInput {
            header_cbor,
            payload_cbor,
        } = if proof.signed_bytes.is_empty() {
            encode_header_and_payload(&proof.header, &proof.payload)?
        } else {
            proof.signed_bytes.clone()
        };

        let arr = Value::Array(vec![
            Value::Bytes(header_cbor),
            Value::Map(vec![]),
            Value::Bytes(payload_cbor),
            Value::Bytes(proof.signature.clone()),
        ]);
        let tagged = Value::Tag(COSE_TAG_SIGN1, Box::new(arr));

        let mut buf = Vec::new();
        ciborium::ser::into_writer(&tagged, &mut buf)
            .map_err(|e| CatError::InvalidCbor(e.to_string()))?;
        Ok(buf)
    }

    /// Deserialize a single CBOR item and reject trailing data. Every
    /// nested-bstr payload we decode (header map, payload map, actx map,
    /// COSE_Key map) is a self-contained CBOR item — extra bytes after the
    /// item are a strong signal of an encoder attempting to smuggle
    /// alternative interpretations, so we fail closed rather than silently
    /// truncate.
    fn decode_one(bytes: &[u8]) -> Result<Value, CatError> {
        let mut cursor = std::io::Cursor::new(bytes);
        let value: Value = ciborium::de::from_reader(&mut cursor)
            .map_err(|e| CatError::InvalidCbor(e.to_string()))?;
        if (cursor.position() as usize) < bytes.len() {
            return Err(CatError::InvalidCbor(
                "trailing bytes after CBOR item".to_string(),
            ));
        }
        Ok(value)
    }

    /// Convert a CBOR map into a `(i64, Value)` list, rejecting non-integer
    /// keys and duplicates. A hostile encoder cannot use non-integer decoy
    /// keys (silently ignored by naive parsers) or reintroduce a canonical
    /// integer key twice to shadow an earlier assignment.
    fn into_int_keyed_map(map: Vec<(Value, Value)>) -> Result<Vec<(i64, Value)>, CatError> {
        let mut out: Vec<(i64, Value)> = Vec::with_capacity(map.len());
        for (k, v) in map {
            let key = match k {
                Value::Integer(i) => i64::try_from(i).map_err(|_| {
                    CatError::InvalidCbor("CBOR map key out of i64 range".to_string())
                })?,
                _ => {
                    return Err(CatError::InvalidCbor(
                        "CBOR map must have integer keys".to_string(),
                    ));
                }
            };
            if out.iter().any(|(k2, _)| *k2 == key) {
                return Err(CatError::InvalidCbor(format!(
                    "duplicate CBOR map key {key}"
                )));
            }
            out.push((key, v));
        }
        Ok(out)
    }

    pub(super) fn decode(bytes: &[u8]) -> Result<DpopProof, CatError> {
        if bytes.len() > MAX_DPOP_WIRE_SIZE {
            return Err(CatError::InvalidTokenFormat);
        }

        let value = decode_one(bytes)?;

        let arr = match value {
            Value::Tag(tag, inner) => {
                if tag != COSE_TAG_SIGN1 {
                    return Err(CatError::InvalidTokenFormat);
                }
                match *inner {
                    Value::Array(a) if a.len() == 4 => a,
                    _ => return Err(CatError::InvalidTokenFormat),
                }
            }
            _ => return Err(CatError::InvalidTokenFormat),
        };

        let mut it = arr.into_iter();
        let header_bytes = match it.next() {
            Some(Value::Bytes(b)) => b,
            _ => return Err(CatError::InvalidTokenFormat),
        };
        match it.next() {
            Some(Value::Map(m)) if m.is_empty() => {}
            _ => return Err(CatError::InvalidTokenFormat),
        }
        let payload_bytes = match it.next() {
            Some(Value::Bytes(b)) => b,
            _ => return Err(CatError::InvalidTokenFormat),
        };
        let signature = match it.next() {
            Some(Value::Bytes(b)) => b,
            _ => return Err(CatError::InvalidTokenFormat),
        };

        let header = decode_header(&header_bytes)?;
        let payload = decode_payload(&payload_bytes)?;

        Ok(DpopProof {
            header,
            payload,
            signature,
            signed_bytes: SignedInput {
                header_cbor: header_bytes,
                payload_cbor: payload_bytes,
            },
        })
    }

    pub(super) fn encode_header_and_payload(
        header: &DpopHeader,
        payload: &DpopPayload,
    ) -> Result<SignedInput, CatError> {
        Ok(SignedInput {
            header_cbor: encode_header(header)?,
            payload_cbor: encode_payload(payload)?,
        })
    }

    fn encode_header(header: &DpopHeader) -> Result<Vec<u8>, CatError> {
        let cose_key = jwk_to_cose_key(&header.jwk)?;
        let entries: Vec<(Value, Value)> = vec![
            (
                Value::Integer(COSE_HDR_ALG.into()),
                Value::Integer(header.alg.into()),
            ),
            (Value::Integer(COSE_HDR_COSE_KEY.into()), cose_key),
            (
                Value::Integer(COSE_HDR_TYP.into()),
                Value::Text(header.typ.clone()),
            ),
        ];
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&Value::Map(entries), &mut buf)
            .map_err(|e| CatError::InvalidCbor(e.to_string()))?;
        Ok(buf)
    }

    fn decode_header(bytes: &[u8]) -> Result<DpopHeader, CatError> {
        let value = decode_one(bytes)?;
        let map = match value {
            Value::Map(m) => m,
            _ => return Err(CatError::InvalidTokenFormat),
        };

        let mut alg: Option<i64> = None;
        let mut typ: Option<String> = None;
        let mut cose_key: Option<Value> = None;
        for (key, v) in into_int_keyed_map(map)? {
            match key {
                COSE_HDR_ALG => {
                    alg = Some(match v {
                        Value::Integer(i) => {
                            i64::try_from(i).map_err(|_| CatError::InvalidTokenFormat)?
                        }
                        _ => {
                            return Err(CatError::InvalidClaimValue(
                                "alg must be an integer".to_string(),
                            ));
                        }
                    });
                }
                COSE_HDR_TYP => {
                    typ = Some(match v {
                        Value::Text(t) => t,
                        _ => return Err(CatError::InvalidTokenFormat),
                    });
                }
                COSE_HDR_COSE_KEY => cose_key = Some(v),
                _ => {}
            }
        }

        let alg = alg.ok_or_else(|| CatError::MissingRequiredClaim("alg".to_string()))?;
        let typ = typ.ok_or_else(|| CatError::MissingRequiredClaim("typ".to_string()))?;
        let cose_key =
            cose_key.ok_or_else(|| CatError::MissingRequiredClaim("COSE_Key".to_string()))?;
        let jwk = cose_key_to_jwk(cose_key)?;
        Ok(DpopHeader { alg, typ, jwk })
    }

    fn encode_payload(payload: &DpopPayload) -> Result<Vec<u8>, CatError> {
        let mut entries: Vec<(Value, Value)> = Vec::new();
        entries.push((
            Value::Integer(CWT_CLAIM_IAT.into()),
            Value::Integer(payload.iat.into()),
        ));
        if let Some(cti) = &payload.cti {
            entries.push((
                Value::Integer(CWT_CLAIM_CTI.into()),
                Value::Bytes(cti.clone()),
            ));
        }
        entries.push((
            Value::Integer(CWT_CLAIM_ACTX.into()),
            actx_to_cbor(&payload.actx)?,
        ));
        if let Some(nonce) = &payload.nonce {
            entries.push((
                Value::Integer(CWT_CLAIM_NONCE.into()),
                Value::Text(nonce.clone()),
            ));
        }
        if let Some(ath) = &payload.ath {
            entries.push((
                Value::Integer(CWT_CLAIM_ATH.into()),
                Value::Bytes(ath.clone()),
            ));
        }

        let mut buf = Vec::new();
        ciborium::ser::into_writer(&Value::Map(entries), &mut buf)
            .map_err(|e| CatError::InvalidCbor(e.to_string()))?;
        Ok(buf)
    }

    fn decode_payload(bytes: &[u8]) -> Result<DpopPayload, CatError> {
        let value = decode_one(bytes)?;
        let map = match value {
            Value::Map(m) => m,
            _ => return Err(CatError::InvalidTokenFormat),
        };

        let mut iat: Option<i64> = None;
        let mut cti: Option<Vec<u8>> = None;
        let mut actx: Option<AuthorizationContext> = None;
        let mut ath: Option<Vec<u8>> = None;
        let mut nonce: Option<String> = None;
        for (key, v) in into_int_keyed_map(map)? {
            match key {
                CWT_CLAIM_IAT => {
                    iat = Some(match v {
                        Value::Integer(i) => {
                            i64::try_from(i).map_err(|_| CatError::InvalidTokenFormat)?
                        }
                        _ => {
                            return Err(CatError::InvalidClaimValue(
                                "iat must be integer".to_string(),
                            ));
                        }
                    });
                }
                CWT_CLAIM_CTI => {
                    // RFC 8392 §3.1.7 and the CWT DPoP profile require `cti`
                    // to be a byte string. Rejecting text-form cti closes an
                    // encoder-side ambiguity where the same JTI could appear
                    // in two encodings and slip past a naive replay cache.
                    cti = Some(match v {
                        Value::Bytes(b) => b,
                        _ => {
                            return Err(CatError::InvalidClaimValue(
                                "cti must be a byte string".to_string(),
                            ));
                        }
                    });
                }
                CWT_CLAIM_ACTX => actx = Some(cbor_to_actx(v)?),
                CWT_CLAIM_ATH => {
                    ath = Some(match v {
                        Value::Bytes(b) => b,
                        _ => {
                            return Err(CatError::InvalidClaimValue(
                                "ath must be a byte string".to_string(),
                            ));
                        }
                    });
                }
                CWT_CLAIM_NONCE => {
                    nonce = Some(match v {
                        Value::Text(t) => t,
                        _ => return Err(CatError::InvalidTokenFormat),
                    });
                }
                _ => {}
            }
        }

        let iat = iat.ok_or_else(|| CatError::MissingRequiredClaim("iat".to_string()))?;
        let actx = actx.ok_or_else(|| CatError::MissingRequiredClaim("actx".to_string()))?;

        Ok(DpopPayload {
            cti,
            iat,
            actx,
            ath,
            nonce,
        })
    }

    fn actx_to_cbor(actx: &AuthorizationContext) -> Result<Value, CatError> {
        let mut entries: Vec<(Value, Value)> = Vec::new();
        entries.push((
            Value::Integer(ACTX_TYPE.into()),
            Value::Text(actx.ctx_type.clone()),
        ));
        entries.push((
            Value::Integer(ACTX_ACTION.into()),
            Value::Text(moqt_action_wire_name(actx.action).to_string()),
        ));
        entries.push((
            Value::Integer(ACTX_TNS.into()),
            Value::Text(moq_canonical_tns(&actx.tns)),
        ));
        if !actx.tn.is_empty() {
            entries.push((
                Value::Integer(ACTX_TN.into()),
                Value::Text(moq_canonical_element(&actx.tn)),
            ));
        }
        if let Some(resource) = &actx.resource {
            // `parameters` (label 4) is a map by spec; carry the moqt://
            // resource under a well-known text key inside it. Consumers that
            // don't care about `resource` can ignore the entry.
            let params = Value::Map(vec![(
                Value::Text("resource".to_string()),
                Value::Text(resource.clone()),
            )]);
            entries.push((Value::Integer(ACTX_PARAMETERS.into()), params));
        }
        Ok(Value::Map(entries))
    }

    fn cbor_to_actx(v: Value) -> Result<AuthorizationContext, CatError> {
        let map = match v {
            Value::Map(m) => m,
            _ => {
                return Err(CatError::InvalidClaimValue(
                    "actx must be a CBOR map".to_string(),
                ));
            }
        };
        let mut ctx_type: Option<String> = None;
        let mut action: Option<MoqtAction> = None;
        let mut tns: Option<Vec<Vec<u8>>> = None;
        let mut tn: Vec<u8> = Vec::new();
        let mut resource: Option<String> = None;
        for (key, val) in into_int_keyed_map(map)? {
            match key {
                ACTX_TYPE => {
                    ctx_type = Some(match val {
                        Value::Text(t) => t,
                        _ => return Err(CatError::InvalidTokenFormat),
                    });
                }
                ACTX_ACTION => {
                    let name = match val {
                        Value::Text(t) => t,
                        _ => {
                            return Err(CatError::InvalidClaimValue(
                                "actx.action must be text".to_string(),
                            ));
                        }
                    };
                    action = Some(moqt_action_from_wire_name(&name)?);
                }
                ACTX_TNS => {
                    let t = match val {
                        Value::Text(s) => s,
                        _ => {
                            return Err(CatError::InvalidClaimValue(
                                "actx.tns must be text".to_string(),
                            ));
                        }
                    };
                    tns = Some(moq_tns_from_canonical(&t)?);
                }
                ACTX_TN => {
                    let t = match val {
                        Value::Text(s) => s,
                        _ => {
                            return Err(CatError::InvalidClaimValue(
                                "actx.tn must be text".to_string(),
                            ));
                        }
                    };
                    tn = moq_element_from_canonical(&t)?;
                }
                ACTX_PARAMETERS => {
                    if let Value::Map(m) = val {
                        for (pk, pv) in m {
                            if let (Value::Text(name), Value::Text(text)) = (&pk, &pv)
                                && name == "resource"
                            {
                                resource = Some(text.clone());
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        let ctx_type =
            ctx_type.ok_or_else(|| CatError::MissingRequiredClaim("actx.type".to_string()))?;
        let action =
            action.ok_or_else(|| CatError::MissingRequiredClaim("actx.action".to_string()))?;
        let tns = tns.ok_or_else(|| CatError::MissingRequiredClaim("actx.tns".to_string()))?;
        Ok(AuthorizationContext {
            ctx_type,
            action,
            tns,
            tn,
            resource,
        })
    }

    // --- MOQTransport §1.5.1 canonical serialization for tns/tn ---------
    //
    // Each element (namespace segment or track name) is written as a UTF-8
    // string where any byte that is not a safe printable ASCII character is
    // escaped as `.HH` (two hex digits). `tns` joins elements with `-`.
    //
    // "Safe" here means `[A-Za-z0-9_]` — every other byte, including `.`,
    // `-`, and any high-bit octet, is escaped. The dotted-hex form is chosen
    // so the resulting string never contains a bare `-` or `.` that could be
    // confused with a separator or escape sequence.

    fn is_safe(b: u8) -> bool {
        b.is_ascii_alphanumeric() || b == b'_'
    }

    pub(super) fn moq_canonical_element(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len());
        for &b in bytes {
            if is_safe(b) {
                out.push(b as char);
            } else {
                out.push('.');
                out.push_str(&format!("{b:02x}"));
            }
        }
        out
    }

    pub(super) fn moq_canonical_tns(tns: &[Vec<u8>]) -> String {
        let mut parts: Vec<String> = Vec::with_capacity(tns.len());
        for element in tns {
            parts.push(moq_canonical_element(element));
        }
        parts.join("-")
    }

    fn moq_element_from_canonical(s: &str) -> Result<Vec<u8>, CatError> {
        let bytes = s.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            let b = bytes[i];
            if b == b'.' {
                if i + 2 >= bytes.len() {
                    return Err(CatError::InvalidClaimValue(
                        "truncated MOQ escape".to_string(),
                    ));
                }
                let hi = hex_digit(bytes[i + 1])?;
                let lo = hex_digit(bytes[i + 2])?;
                out.push((hi << 4) | lo);
                i += 3;
            } else if is_safe(b) {
                out.push(b);
                i += 1;
            } else {
                return Err(CatError::InvalidClaimValue(format!(
                    "unescaped MOQ byte 0x{b:02x}"
                )));
            }
        }
        Ok(out)
    }

    fn moq_tns_from_canonical(s: &str) -> Result<Vec<Vec<u8>>, CatError> {
        s.split('-')
            .map(moq_element_from_canonical)
            .collect::<Result<Vec<_>, _>>()
    }

    fn hex_digit(b: u8) -> Result<u8, CatError> {
        match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'a'..=b'f' => Ok(b - b'a' + 10),
            b'A'..=b'F' => Ok(b - b'A' + 10),
            _ => Err(CatError::InvalidClaimValue(format!(
                "invalid hex digit 0x{b:02x}"
            ))),
        }
    }

    // --- COSE_Key <-> JWK -----------------------------------------------

    pub(super) fn jwk_to_cose_key(jwk: &Jwk) -> Result<Value, CatError> {
        match jwk.kty.as_str() {
            "EC" => {
                if jwk.crv.as_deref() != Some("P-256") {
                    return Err(CatError::UnsupportedAlgorithm(format!(
                        "unsupported EC curve {:?}",
                        jwk.crv
                    )));
                }
                let x = URL_SAFE_NO_PAD
                    .decode(jwk.x.as_deref().unwrap_or(""))
                    .map_err(|e| CatError::InvalidBase64(e.to_string()))?;
                let y = URL_SAFE_NO_PAD
                    .decode(jwk.y.as_deref().unwrap_or(""))
                    .map_err(|e| CatError::InvalidBase64(e.to_string()))?;
                Ok(Value::Map(vec![
                    (
                        Value::Integer(COSE_KEY_KTY.into()),
                        Value::Integer(COSE_KTY_EC2.into()),
                    ),
                    (
                        Value::Integer(COSE_KEY_ALG.into()),
                        Value::Integer(crate::crypto::ALG_ES256.into()),
                    ),
                    (
                        Value::Integer(COSE_KEY_CRV.into()),
                        Value::Integer(COSE_CRV_P256.into()),
                    ),
                    (Value::Integer(COSE_KEY_X.into()), Value::Bytes(x)),
                    (Value::Integer(COSE_KEY_Y.into()), Value::Bytes(y)),
                ]))
            }
            "RSA" => {
                let n = URL_SAFE_NO_PAD
                    .decode(jwk.n.as_deref().unwrap_or(""))
                    .map_err(|e| CatError::InvalidBase64(e.to_string()))?;
                let e = URL_SAFE_NO_PAD
                    .decode(jwk.e.as_deref().unwrap_or(""))
                    .map_err(|err| CatError::InvalidBase64(err.to_string()))?;
                Ok(Value::Map(vec![
                    (
                        Value::Integer(COSE_KEY_KTY.into()),
                        Value::Integer(COSE_KTY_RSA.into()),
                    ),
                    (
                        Value::Integer(COSE_KEY_ALG.into()),
                        Value::Integer(crate::crypto::ALG_PS256.into()),
                    ),
                    (Value::Integer(COSE_KEY_N.into()), Value::Bytes(n)),
                    (Value::Integer(COSE_KEY_E.into()), Value::Bytes(e)),
                ]))
            }
            other => Err(CatError::UnsupportedAlgorithm(format!(
                "COSE_Key encoding not implemented for kty={other}"
            ))),
        }
    }

    fn cose_key_to_jwk(v: Value) -> Result<Jwk, CatError> {
        let map = match v {
            Value::Map(m) => m,
            _ => {
                return Err(CatError::InvalidClaimValue(
                    "COSE_Key must be a CBOR map".to_string(),
                ));
            }
        };
        let mut kty: Option<i64> = None;
        let mut crv: Option<i64> = None;
        let mut x: Option<Vec<u8>> = None;
        let mut y: Option<Vec<u8>> = None;
        let mut n: Option<Vec<u8>> = None;
        let mut e: Option<Vec<u8>> = None;
        // COSE labels for RSA n/e (RFC 8230) collide numerically with EC x/y
        // (RFC 8152). Disambiguate on kty: read kty first, then decode the
        // remaining fields with the correct label meaning.
        //
        // Since the CBOR map isn't required to place kty first, buffer everything.
        let entries = into_int_keyed_map(map)?;
        let mut buffered: Vec<(i64, Value)> = Vec::with_capacity(entries.len());
        for (key, val) in entries {
            if key == COSE_KEY_KTY {
                kty = Some(match val {
                    Value::Integer(i) => {
                        i64::try_from(i).map_err(|_| CatError::InvalidTokenFormat)?
                    }
                    _ => return Err(CatError::InvalidTokenFormat),
                });
            } else {
                buffered.push((key, val));
            }
        }
        let kty = kty.ok_or_else(|| CatError::MissingRequiredClaim("kty".to_string()))?;
        for (key, val) in buffered {
            match (kty, key) {
                (COSE_KTY_EC2, COSE_KEY_CRV) => {
                    crv = Some(match val {
                        Value::Integer(i) => {
                            i64::try_from(i).map_err(|_| CatError::InvalidTokenFormat)?
                        }
                        _ => return Err(CatError::InvalidTokenFormat),
                    });
                }
                (COSE_KTY_EC2, COSE_KEY_X) => {
                    x = Some(match val {
                        Value::Bytes(b) => b,
                        _ => return Err(CatError::InvalidTokenFormat),
                    });
                }
                (COSE_KTY_EC2, COSE_KEY_Y) => {
                    y = Some(match val {
                        Value::Bytes(b) => b,
                        _ => return Err(CatError::InvalidTokenFormat),
                    });
                }
                (COSE_KTY_RSA, COSE_KEY_N) => {
                    n = Some(match val {
                        Value::Bytes(b) => b,
                        _ => return Err(CatError::InvalidTokenFormat),
                    });
                }
                (COSE_KTY_RSA, COSE_KEY_E) => {
                    e = Some(match val {
                        Value::Bytes(b) => b,
                        _ => return Err(CatError::InvalidTokenFormat),
                    });
                }
                _ => {}
            }
        }

        match kty {
            COSE_KTY_EC2 => {
                let crv = crv.ok_or_else(|| CatError::MissingRequiredClaim("crv".to_string()))?;
                if crv != COSE_CRV_P256 {
                    return Err(CatError::UnsupportedAlgorithm(format!(
                        "unsupported EC crv {crv}"
                    )));
                }
                let x = x.ok_or_else(|| CatError::MissingRequiredClaim("x".to_string()))?;
                let y = y.ok_or_else(|| CatError::MissingRequiredClaim("y".to_string()))?;
                Ok(Jwk {
                    kty: "EC".to_string(),
                    crv: Some("P-256".to_string()),
                    x: Some(URL_SAFE_NO_PAD.encode(&x)),
                    y: Some(URL_SAFE_NO_PAD.encode(&y)),
                    n: None,
                    e: None,
                })
            }
            COSE_KTY_RSA => {
                let n = n.ok_or_else(|| CatError::MissingRequiredClaim("n".to_string()))?;
                let e = e.ok_or_else(|| CatError::MissingRequiredClaim("e".to_string()))?;
                Ok(Jwk {
                    kty: "RSA".to_string(),
                    crv: None,
                    x: None,
                    y: None,
                    n: Some(URL_SAFE_NO_PAD.encode(&n)),
                    e: Some(URL_SAFE_NO_PAD.encode(&e)),
                })
            }
            other => Err(CatError::UnsupportedAlgorithm(format!("kty={other}"))),
        }
    }
}

// --- JTI store (unchanged from prior batch) -----------------------------

#[cfg(feature = "moqt")]
const DEFAULT_JTI_CACHE_SIZE: usize = 100_000;

#[cfg(feature = "moqt")]
const MIN_JTI_CACHE_SIZE: usize = 1000;

/// Upper bound on the byte length of a JTI accepted into the replay cache.
/// A hostile issuer emitting kilobyte-scale JTI strings would otherwise be
/// able to trivially exhaust cache memory or slow every insert through the
/// hashmap. 256 bytes accommodates every canonical form (uuid, base64url of
/// SHA-256, hex of SHA-256) with headroom.
#[cfg(feature = "moqt")]
pub const MAX_JTI_LENGTH_BYTES: usize = 256;

/// Number of independent shards backing the default replay cache. Each
/// shard has its own mutex, so concurrent inserts on distinct JTIs (which
/// hash to different shards with high probability) do not contend on a
/// single lock. 16 is enough to eliminate contention under typical relay
/// load without blowing up per-shard capacity for small deployments.
#[cfg(feature = "moqt")]
pub const DEFAULT_JTI_SHARDS: usize = 16;

/// Backend for JTI-based replay detection.
///
/// # Strictness
///
/// RFC 9449 §11.1 warns that JTI tracking must retain every accepted proof
/// identifier for at least the acceptable freshness window. An implementation
/// that evicts under memory pressure is NOT strict — a proof accepted, then
/// evicted, then replayed will re-authorize.
///
/// Implementations that guarantee every accepted JTI is retained for its
/// full freshness window (typically via TTL-backed distributed storage)
/// MUST override [`JtiStore::is_strict`] to return `true`. The in-process
/// [`LruJtiStore`] returned by [`DpopValidator::new`] returns `false` and
/// is suitable for development, single-node deployments, and tests only.
/// CDN-scale deployments MUST plug in a strict backend (e.g. Redis with
/// per-JTI TTL) via [`DpopValidator::with_jti_store_strict`].
#[cfg(feature = "moqt")]
pub trait JtiStore: Send + Sync {
    fn check_and_insert(&self, key: String, iat: i64) -> Result<(), CatError>;
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    fn cleanup(&self, max_age_seconds: i64) {
        let _ = max_age_seconds;
    }
    fn premature_evictions(&self) -> u64 {
        0
    }
    /// Return `true` only when the store guarantees no accepted JTI is
    /// dropped before its freshness window elapses. Eviction-based stores
    /// (LRU, bounded HashSet) MUST return `false`. Used by
    /// [`DpopValidator::with_jti_store_strict`] to refuse construction
    /// with a non-strict store.
    fn is_strict(&self) -> bool {
        false
    }
}

#[cfg(feature = "moqt")]
struct LruShard {
    cache: Mutex<LruCache<String, i64>>,
}

#[cfg(feature = "moqt")]
impl LruShard {
    fn new(capacity: usize) -> Self {
        let nz = NonZeroUsize::new(capacity.max(1)).expect("capacity >= 1");
        Self {
            cache: Mutex::new(LruCache::new(nz)),
        }
    }
}

/// Sharded, LRU-evicting replay-JTI store for in-process deployments.
///
/// **Not strict.** When the cache is full, oldest entries are evicted even
/// if their freshness window has not elapsed — an evicted JTI can then be
/// replayed. This store is appropriate for development, tests, and single-
/// node deployments where memory-bounded replay reduction is acceptable.
///
/// **Do not use as the sole replay defense at CDN scale.** RFC 9449 §11.1
/// requires strict retention for the full freshness window; a CDN
/// deployment must plug in a distributed TTL-backed store (e.g. Redis with
/// per-JTI expiry) that returns `true` from [`JtiStore::is_strict`], and
/// construct the validator via [`DpopValidator::with_jti_store_strict`].
/// Monitor [`LruJtiStore::premature_evictions`] as a canary for cache
/// pressure regardless.
#[cfg(feature = "moqt")]
pub struct LruJtiStore {
    shards: Vec<LruShard>,
    hasher_state: std::collections::hash_map::RandomState,
    premature_evictions: std::sync::atomic::AtomicU64,
    freshness_window_seconds: i64,
}

#[cfg(feature = "moqt")]
impl LruJtiStore {
    pub fn new(capacity: usize) -> Self {
        Self::with_shards_and_window(capacity, DEFAULT_JTI_SHARDS, 300)
    }

    pub fn with_shards(capacity: usize, shards: usize) -> Self {
        Self::with_shards_and_window(capacity, shards, 300)
    }

    pub fn with_shards_and_window(
        capacity: usize,
        shards: usize,
        freshness_window_seconds: i64,
    ) -> Self {
        let effective_capacity = capacity.max(MIN_JTI_CACHE_SIZE);
        let shard_count = shards.max(1);
        let per_shard = (effective_capacity / shard_count).max(1);
        let shards = (0..shard_count).map(|_| LruShard::new(per_shard)).collect();
        Self {
            shards,
            hasher_state: std::collections::hash_map::RandomState::new(),
            premature_evictions: std::sync::atomic::AtomicU64::new(0),
            freshness_window_seconds,
        }
    }

    fn shard_for(&self, key: &str) -> &LruShard {
        use std::hash::{BuildHasher, Hasher};
        let mut hasher = self.hasher_state.build_hasher();
        hasher.write(key.as_bytes());
        let idx = (hasher.finish() as usize) % self.shards.len();
        &self.shards[idx]
    }
}

#[cfg(feature = "moqt")]
impl JtiStore for LruJtiStore {
    fn check_and_insert(&self, key: String, iat: i64) -> Result<(), CatError> {
        if key.len() > MAX_JTI_LENGTH_BYTES {
            return Err(CatError::DpopValidationFailed(format!(
                "JTI exceeds {MAX_JTI_LENGTH_BYTES} byte cap"
            )));
        }
        let shard = self.shard_for(&key);
        let mut cache = shard
            .cache
            .lock()
            .map_err(|_| CatError::CryptoError("Lock poisoned".to_string()))?;
        if cache.contains(&key) {
            return Err(CatError::ReplayAttackDetected);
        }
        if let Some((_, evicted_iat)) = cache.push(key, iat) {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::ZERO)
                .as_secs() as i64;
            let age = now.saturating_sub(evicted_iat);
            if age < self.freshness_window_seconds {
                self.premature_evictions
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
        Ok(())
    }

    fn len(&self) -> usize {
        self.shards
            .iter()
            .map(|s| s.cache.lock().map(|c| c.len()).unwrap_or(0))
            .sum()
    }

    fn cleanup(&self, max_age_seconds: i64) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs() as i64;

        for shard in &self.shards {
            if let Ok(mut cache) = shard.cache.lock() {
                let expired: Vec<String> = cache
                    .iter()
                    .filter(|(_, iat): &(&String, &i64)| now - **iat >= max_age_seconds)
                    .map(|(k, _)| k.clone())
                    .collect();
                for key in expired {
                    cache.pop(&key);
                }
            }
        }
    }

    fn premature_evictions(&self) -> u64 {
        self.premature_evictions
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}

#[cfg(feature = "moqt")]
#[derive(Debug, Clone, Default)]
pub struct JtiCacheStats {
    pub size: usize,
    pub capacity: usize,
    pub under_pressure: bool,
    pub premature_evictions: u64,
}

// --- Validator ----------------------------------------------------------

#[cfg(feature = "moqt")]
pub struct DpopValidator {
    settings: CatDpopSettings,
    jti_store: Arc<dyn JtiStore>,
    jti_expiry_seconds: i64,
    cache_capacity: usize,
}

#[cfg(feature = "moqt")]
impl Clone for DpopValidator {
    fn clone(&self) -> Self {
        Self {
            settings: self.settings.clone(),
            jti_store: Arc::clone(&self.jti_store),
            jti_expiry_seconds: self.jti_expiry_seconds,
            cache_capacity: self.cache_capacity,
        }
    }
}

#[cfg(feature = "moqt")]
impl DpopValidator {
    /// Construct a validator backed by the in-process eviction-based
    /// [`LruJtiStore`].
    ///
    /// **Not strict.** Suitable for development, tests, and single-node
    /// deployments. CDN-scale deployments MUST use
    /// [`DpopValidator::with_jti_store_strict`] with a distributed
    /// TTL-backed store — see the [`JtiStore`] trait documentation for the
    /// strictness contract.
    pub fn new(settings: CatDpopSettings) -> Self {
        Self::with_cache_size(settings, DEFAULT_JTI_CACHE_SIZE)
    }

    /// Same as [`DpopValidator::new`] with an explicit cache capacity.
    /// **Not strict** — see [`DpopValidator::new`].
    pub fn with_cache_size(settings: CatDpopSettings, cache_size: usize) -> Self {
        let effective_size = cache_size.max(MIN_JTI_CACHE_SIZE);
        let window = settings.effective_window();
        Self {
            jti_expiry_seconds: window.checked_mul(2).unwrap_or(i64::MAX),
            jti_store: Arc::new(LruJtiStore::with_shards_and_window(
                effective_size,
                DEFAULT_JTI_SHARDS,
                window,
            )),
            cache_capacity: effective_size,
            settings,
        }
    }

    /// Plug in a custom [`JtiStore`] without asserting strictness. Use
    /// [`DpopValidator::with_jti_store_strict`] instead when the caller has
    /// verified the store meets the RFC 9449 §11.1 retention requirement.
    pub fn with_jti_store(settings: CatDpopSettings, store: Arc<dyn JtiStore>) -> Self {
        Self {
            jti_expiry_seconds: settings
                .effective_window()
                .checked_mul(2)
                .unwrap_or(i64::MAX),
            cache_capacity: 0,
            jti_store: store,
            settings,
        }
    }

    /// Construct a validator backed by a strict JTI store. The store MUST
    /// return `true` from [`JtiStore::is_strict`] — otherwise this
    /// constructor returns [`CatError::CryptoError`] to force the caller
    /// to either mark the store strict or fall back to
    /// [`DpopValidator::with_jti_store`] with eyes-open.
    ///
    /// A "strict" store retains every accepted JTI for at least the
    /// freshness window. Typical implementations use a distributed
    /// TTL-backed backend (Redis, DynamoDB with TTL, etc.).
    pub fn with_jti_store_strict(
        settings: CatDpopSettings,
        store: Arc<dyn JtiStore>,
    ) -> Result<Self, CatError> {
        if !store.is_strict() {
            return Err(CatError::CryptoError(
                "JtiStore::is_strict() returned false; strict CDN deployments \
                 require a distributed TTL-backed store"
                    .to_string(),
            ));
        }
        Ok(Self::with_jti_store(settings, store))
    }

    pub fn jti_cache_stats(&self) -> JtiCacheStats {
        let size = self.jti_store.len();
        let under_pressure = self.cache_capacity > 0 && size >= (self.cache_capacity * 9 / 10);
        JtiCacheStats {
            size,
            capacity: self.cache_capacity,
            under_pressure,
            premature_evictions: self.jti_store.premature_evictions(),
        }
    }

    fn validate_claims_pre_sig(
        &self,
        proof: &DpopProof,
        expected_action: MoqtAction,
        expected_thumbprint: &[u8],
        access_token_hash: Option<&[u8]>,
    ) -> Result<(), CatError> {
        if !proof.header.is_valid() {
            return Err(CatError::DpopValidationFailed("Invalid header".to_string()));
        }
        if !proof.payload.is_valid() {
            return Err(CatError::DpopValidationFailed(
                "Invalid payload".to_string(),
            ));
        }
        if proof.payload.cti.is_none() {
            return Err(CatError::DpopValidationFailed(
                "DPoP proof missing required cti claim".to_string(),
            ));
        }
        if !proof.payload.is_fresh(self.settings.effective_window()) {
            return Err(CatError::DpopValidationFailed("Proof expired".to_string()));
        }
        if proof.payload.actx.action != expected_action {
            return Err(CatError::DpopValidationFailed(format!(
                "Action mismatch: expected {expected_action:?}"
            )));
        }
        let jwk_thumbprint = proof.header.jwk.thumbprint()?;
        if !crate::crypto::constant_time_eq(&jwk_thumbprint, expected_thumbprint) {
            return Err(CatError::InvalidDpopBinding);
        }
        if let Some(expected_ath) = access_token_hash {
            match &proof.payload.ath {
                Some(ath) => {
                    if !crate::crypto::constant_time_eq(ath, expected_ath) {
                        return Err(CatError::DpopValidationFailed(
                            "Access token hash mismatch".to_string(),
                        ));
                    }
                }
                None => {
                    return Err(CatError::DpopValidationFailed(
                        "Missing access token hash (ath) in proof".to_string(),
                    ));
                }
            }
        }
        Ok(())
    }

    fn insert_jti(
        &self,
        proof: &DpopProof,
        thumbprint: &[u8],
        issuer: Option<&str>,
    ) -> Result<(), CatError> {
        if self.settings.should_honor_jti()
            && let Some(ref cti) = proof.payload.cti
        {
            let iss = issuer.unwrap_or("_");
            // Composite key: (issuer, holder-key, cti bytes hex). Hex of cti
            // keeps the key printable and bounded regardless of the raw byte
            // content (which may include NULs or non-UTF-8 sequences).
            let composite_key = format!("{}:{}:{}", iss, hex::encode(thumbprint), hex::encode(cti));
            self.jti_store
                .check_and_insert(composite_key, proof.payload.iat)?;
        }
        Ok(())
    }

    fn verify_with_embedded_key(&self, proof: &DpopProof) -> Result<(), CatError> {
        let signing_input = proof.signing_input()?;
        match proof.header.alg {
            crate::crypto::ALG_ES256 => {
                let verifying_key = proof.header.jwk.to_verifying_key()?;
                let alg = Es256Algorithm::new_verifier(verifying_key);
                alg.verify(&signing_input, &proof.signature)?;
            }
            crate::crypto::ALG_PS256 => {
                let rsa_pub = proof.header.jwk.to_rsa_public_key()?;
                let alg = Ps256Algorithm::new_verifier(rsa_pub)?;
                alg.verify(&signing_input, &proof.signature)?;
            }
            other => {
                return Err(CatError::DpopAlgorithmNotSupported(format!("{other}")));
            }
        }
        Ok(())
    }

    pub(crate) fn validate_without_jti_commit(
        &self,
        proof: &DpopProof,
        expected_action: MoqtAction,
        expected_thumbprint: &[u8],
        _issuer: Option<&str>,
        access_token_hash: Option<&[u8]>,
    ) -> Result<(), CatError> {
        self.validate_claims_pre_sig(
            proof,
            expected_action,
            expected_thumbprint,
            access_token_hash,
        )?;
        if !proof.header.is_supported_algorithm() {
            return Err(CatError::DpopAlgorithmNotSupported(format!(
                "{}",
                proof.header.alg
            )));
        }
        let computed_thumbprint = proof.header.jwk.thumbprint()?;
        if !crate::crypto::constant_time_eq(&computed_thumbprint, expected_thumbprint) {
            return Err(CatError::DpopKeyMismatch);
        }
        self.verify_with_embedded_key(proof)?;
        Ok(())
    }

    pub(crate) fn commit_jti(
        &self,
        proof: &DpopProof,
        thumbprint: &[u8],
        issuer: Option<&str>,
    ) -> Result<(), CatError> {
        self.insert_jti(proof, thumbprint, issuer)
    }

    pub fn validate(
        &self,
        proof: &DpopProof,
        expected_action: MoqtAction,
        expected_thumbprint: &[u8],
        issuer: Option<&str>,
    ) -> Result<(), CatError> {
        self.validate_without_jti_commit(
            proof,
            expected_action,
            expected_thumbprint,
            issuer,
            None,
        )?;
        self.insert_jti(proof, expected_thumbprint, issuer)?;
        Ok(())
    }

    pub fn validate_with_ath(
        &self,
        proof: &DpopProof,
        expected_action: MoqtAction,
        expected_thumbprint: &[u8],
        access_token_hash: Option<&[u8]>,
        issuer: Option<&str>,
    ) -> Result<(), CatError> {
        self.validate_claims_pre_sig(
            proof,
            expected_action,
            expected_thumbprint,
            access_token_hash,
        )?;
        if !proof.header.is_supported_algorithm() {
            return Err(CatError::DpopAlgorithmNotSupported(format!(
                "{}",
                proof.header.alg
            )));
        }
        let computed_thumbprint = proof.header.jwk.thumbprint()?;
        if !crate::crypto::constant_time_eq(&computed_thumbprint, expected_thumbprint) {
            return Err(CatError::DpopKeyMismatch);
        }
        self.verify_with_embedded_key(proof)?;
        self.insert_jti(proof, expected_thumbprint, issuer)?;
        Ok(())
    }

    pub fn cleanup_expired_jtis(&self) {
        self.jti_store.cleanup(self.jti_expiry_seconds);
    }
}

// --- MOQT resource URI ---------------------------------------------------

#[cfg(feature = "moqt")]
pub fn construct_moqt_uri(
    endpoint: &str,
    namespace: Option<&[u8]>,
    track: Option<&[u8]>,
) -> Result<String, CatError> {
    if endpoint.contains('?') || endpoint.contains('#') || endpoint.contains('/') {
        return Err(CatError::InvalidClaimValue(
            "MOQT endpoint must not contain '?', '#', or '/'".to_string(),
        ));
    }
    let mut uri = format!("moqt://{endpoint}");
    if let Some(ns) = namespace {
        let ns_encoded = URL_SAFE_NO_PAD.encode(ns);
        uri.push_str("?tns=");
        uri.push_str(&ns_encoded);
        if let Some(t) = track {
            let t_encoded = URL_SAFE_NO_PAD.encode(t);
            uri.push_str("&tn=");
            uri.push_str(&t_encoded);
        }
    }
    Ok(uri)
}

// --- Free helpers --------------------------------------------------------

pub fn generate_jti() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Compute access-token-hash (`ath`) bytes.
///
/// Returns raw SHA-256 of the access token's serialized wire bytes. Store
/// this directly on `DpopPayload.ath` — the CWT wire format carries `ath`
/// as a byte string.
pub fn compute_access_token_hash(access_token: impl AsRef<[u8]>) -> Vec<u8> {
    crate::crypto::hash_sha256(access_token.as_ref())
}

/// Base64url-encoded SHA-256 of the access token, for legacy JWT/JOSE
/// tooling that expects the text form. Prefer [`compute_access_token_hash`]
/// for the CWT wire path.
pub fn compute_access_token_hash_b64(access_token: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(compute_access_token_hash(access_token))
}

// --- Tests --------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Es256Algorithm;

    #[cfg(feature = "moqt")]
    #[test]
    fn test_dpop_cwt_roundtrip() {
        let alg = Es256Algorithm::new_with_key_pair().unwrap();
        let jwk = Jwk::from_es256_verifying_key(alg.verifying_key()).unwrap();

        let mut proof = DpopProof::create_for_moqt(
            MoqtAction::Subscribe,
            vec![b"namespace".to_vec()],
            b"track",
            crate::crypto::ALG_ES256,
            jwk,
        )
        .with_jti(generate_jti());
        proof.sign(&alg).unwrap();

        let encoded = proof.encode().unwrap();
        assert!(
            encoded.starts_with(&[0xd2]) || encoded[0] & 0xe0 == 0xc0,
            "encoded proof must be a CBOR-tagged value: {:02x?}",
            &encoded[..std::cmp::min(4, encoded.len())]
        );

        let decoded = DpopProof::decode(&encoded).unwrap();
        assert_eq!(decoded.header.typ, DPOP_TYP);
        assert_eq!(decoded.header.alg, crate::crypto::ALG_ES256);
        assert_eq!(decoded.payload.actx.action, MoqtAction::Subscribe);
        assert_eq!(decoded.payload.actx.tns, vec![b"namespace".to_vec()]);
        assert_eq!(decoded.payload.actx.tn, b"track".to_vec());
    }

    #[cfg(feature = "moqt")]
    #[test]
    fn test_decode_rejects_trailing_bytes() {
        let alg = Es256Algorithm::new_with_key_pair().unwrap();
        let jwk = Jwk::from_es256_verifying_key(alg.verifying_key()).unwrap();
        let mut proof = DpopProof::create_for_moqt(
            MoqtAction::Subscribe,
            vec![b"ns".to_vec()],
            b"t",
            crate::crypto::ALG_ES256,
            jwk,
        )
        .with_jti(generate_jti());
        proof.sign(&alg).unwrap();

        let mut encoded = proof.encode().unwrap();
        encoded.push(0x00);
        let err = DpopProof::decode(&encoded).unwrap_err();
        assert!(
            matches!(&err, CatError::InvalidCbor(msg) if msg.contains("trailing")),
            "trailing bytes must be rejected: {err:?}"
        );
    }

    #[cfg(feature = "moqt")]
    #[test]
    fn test_decode_rejects_duplicate_header_key() {
        use ciborium::Value;
        // Build a header map with a duplicate `alg` key. `ciborium` allows
        // this at the CBOR layer — our parser must reject it.
        let jwk = Jwk::from_es256_verifying_key(
            Es256Algorithm::new_with_key_pair().unwrap().verifying_key(),
        )
        .unwrap();
        let cose_key = cwt::jwk_to_cose_key(&jwk).unwrap();
        let header = Value::Map(vec![
            (
                Value::Integer(COSE_HDR_ALG.into()),
                Value::Integer(crate::crypto::ALG_ES256.into()),
            ),
            (
                Value::Integer(COSE_HDR_ALG.into()),
                Value::Integer(crate::crypto::ALG_ES256.into()),
            ),
            (Value::Integer(COSE_HDR_COSE_KEY.into()), cose_key),
            (
                Value::Integer(COSE_HDR_TYP.into()),
                Value::Text(DPOP_TYP.to_string()),
            ),
        ]);
        let mut hbuf = Vec::new();
        ciborium::ser::into_writer(&header, &mut hbuf).unwrap();
        let arr = Value::Array(vec![
            Value::Bytes(hbuf),
            Value::Map(vec![]),
            Value::Bytes(vec![0xa0]), // empty payload map
            Value::Bytes(vec![]),
        ]);
        let tagged = Value::Tag(COSE_TAG_SIGN1, Box::new(arr));
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&tagged, &mut buf).unwrap();
        let err = DpopProof::decode(&buf).unwrap_err();
        assert!(
            matches!(&err, CatError::InvalidCbor(msg) if msg.contains("duplicate")),
            "duplicate map keys must be rejected: {err:?}"
        );
    }

    #[cfg(feature = "moqt")]
    #[test]
    fn test_decode_rejects_text_cti() {
        use ciborium::Value;
        let alg = Es256Algorithm::new_with_key_pair().unwrap();
        let jwk = Jwk::from_es256_verifying_key(alg.verifying_key()).unwrap();
        let cose_key = cwt::jwk_to_cose_key(&jwk).unwrap();
        let header = Value::Map(vec![
            (
                Value::Integer(COSE_HDR_ALG.into()),
                Value::Integer(crate::crypto::ALG_ES256.into()),
            ),
            (Value::Integer(COSE_HDR_COSE_KEY.into()), cose_key),
            (
                Value::Integer(COSE_HDR_TYP.into()),
                Value::Text(DPOP_TYP.to_string()),
            ),
        ]);
        let mut hbuf = Vec::new();
        ciborium::ser::into_writer(&header, &mut hbuf).unwrap();

        let actx = Value::Map(vec![
            (
                Value::Integer(ACTX_TYPE.into()),
                Value::Text("moqt".to_string()),
            ),
            (
                Value::Integer(ACTX_ACTION.into()),
                Value::Text("SUBSCRIBE".to_string()),
            ),
            (
                Value::Integer(ACTX_TNS.into()),
                Value::Text("ns".to_string()),
            ),
        ]);
        // cti as Text instead of Bytes — must be rejected.
        let payload = Value::Map(vec![
            (
                Value::Integer(CWT_CLAIM_IAT.into()),
                Value::Integer(0.into()),
            ),
            (
                Value::Integer(CWT_CLAIM_CTI.into()),
                Value::Text("as-text".to_string()),
            ),
            (Value::Integer(CWT_CLAIM_ACTX.into()), actx),
        ]);
        let mut pbuf = Vec::new();
        ciborium::ser::into_writer(&payload, &mut pbuf).unwrap();

        let arr = Value::Array(vec![
            Value::Bytes(hbuf),
            Value::Map(vec![]),
            Value::Bytes(pbuf),
            Value::Bytes(vec![]),
        ]);
        let tagged = Value::Tag(COSE_TAG_SIGN1, Box::new(arr));
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&tagged, &mut buf).unwrap();

        let err = DpopProof::decode(&buf).unwrap_err();
        assert!(
            matches!(&err, CatError::InvalidClaimValue(msg) if msg.contains("cti")),
            "text-form cti must be rejected: {err:?}"
        );
    }

    #[cfg(feature = "moqt")]
    #[test]
    fn test_decode_rejects_non_integer_header_key() {
        use ciborium::Value;
        let jwk = Jwk::from_es256_verifying_key(
            Es256Algorithm::new_with_key_pair().unwrap().verifying_key(),
        )
        .unwrap();
        let cose_key = cwt::jwk_to_cose_key(&jwk).unwrap();
        // Insert a spurious text-key entry — a strict parser must fail
        // rather than silently ignore the field.
        let header = Value::Map(vec![
            (
                Value::Integer(COSE_HDR_ALG.into()),
                Value::Integer(crate::crypto::ALG_ES256.into()),
            ),
            (Value::Integer(COSE_HDR_COSE_KEY.into()), cose_key),
            (
                Value::Integer(COSE_HDR_TYP.into()),
                Value::Text(DPOP_TYP.to_string()),
            ),
            (
                Value::Text("extra".to_string()),
                Value::Text("junk".to_string()),
            ),
        ]);
        let mut hbuf = Vec::new();
        ciborium::ser::into_writer(&header, &mut hbuf).unwrap();
        let arr = Value::Array(vec![
            Value::Bytes(hbuf),
            Value::Map(vec![]),
            Value::Bytes(vec![0xa0]),
            Value::Bytes(vec![]),
        ]);
        let tagged = Value::Tag(COSE_TAG_SIGN1, Box::new(arr));
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&tagged, &mut buf).unwrap();
        let err = DpopProof::decode(&buf).unwrap_err();
        assert!(
            matches!(&err, CatError::InvalidCbor(msg) if msg.contains("integer keys")),
            "non-integer header key must be rejected: {err:?}"
        );
    }

    #[cfg(feature = "moqt")]
    #[test]
    fn test_dpop_cwt_verify_with_embedded_key() {
        let alg = Es256Algorithm::new_with_key_pair().unwrap();
        let jwk = Jwk::from_es256_verifying_key(alg.verifying_key()).unwrap();
        let thumbprint = jwk.thumbprint().unwrap();

        let mut proof = DpopProof::create_for_moqt(
            MoqtAction::Subscribe,
            vec![b"namespace".to_vec()],
            b"track",
            crate::crypto::ALG_ES256,
            jwk,
        )
        .with_jti(generate_jti());
        proof.sign(&alg).unwrap();

        let encoded = proof.encode().unwrap();
        let decoded = DpopProof::decode(&encoded).unwrap();

        let settings = CatDpopSettings::new().with_window(300).unwrap();
        let validator = DpopValidator::new(settings);
        validator
            .validate(&decoded, MoqtAction::Subscribe, &thumbprint, None)
            .expect("decoded proof must verify");
    }

    #[cfg(feature = "moqt")]
    #[test]
    fn test_moq_canonical_element_escapes() {
        assert_eq!(cwt::moq_canonical_element(b"opus"), "opus");
        assert_eq!(cwt::moq_canonical_element(b"audio.opus"), "audio.2eopus");
        assert_eq!(cwt::moq_canonical_element(&[0xff, 0x01]), ".ff.01");
    }

    #[cfg(feature = "moqt")]
    #[test]
    fn test_moq_canonical_tns_joins_with_hyphen() {
        assert_eq!(
            cwt::moq_canonical_tns(&[b"example.net".to_vec(), b"team2".to_vec()]),
            "example.2enet-team2"
        );
    }

    #[cfg(feature = "moqt")]
    #[test]
    fn test_moqt_uri_construction() {
        let uri = construct_moqt_uri("relay.example.com", None, None).unwrap();
        assert_eq!(uri, "moqt://relay.example.com");
        let uri = construct_moqt_uri("relay.example.com", Some(b"ns"), Some(b"track")).unwrap();
        assert!(uri.contains("?tns="));
        assert!(uri.contains("&tn="));
        assert!(construct_moqt_uri("relay.example.com/path", None, None).is_err());
    }

    #[cfg(feature = "moqt")]
    #[test]
    fn test_authorization_context() {
        let actx = AuthorizationContext::new_moqt(
            MoqtAction::Publish,
            vec![b"my-namespace".to_vec()],
            b"my-track",
        );
        assert_eq!(actx.ctx_type, "moqt");
        assert_eq!(actx.action, MoqtAction::Publish);
        assert!(actx.is_valid());
        assert_eq!(actx.action_string(), "PUBLISH");
    }

    #[cfg(feature = "moqt")]
    #[test]
    fn test_jti_store_lru_evicts_instead_of_rejecting() {
        let store = LruJtiStore::with_shards_and_window(MIN_JTI_CACHE_SIZE, 1, 3600);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs() as i64;
        for i in 0..(MIN_JTI_CACHE_SIZE + 100) {
            store
                .check_and_insert(format!("jti-{i}"), now)
                .expect("insert should not fail with LRU eviction");
        }
        assert_eq!(store.len(), MIN_JTI_CACHE_SIZE);
        assert!(
            store.premature_evictions() >= 100,
            "premature evictions should be counted; got {}",
            store.premature_evictions()
        );
    }

    #[cfg(feature = "moqt")]
    #[test]
    fn test_jti_store_rejects_oversized_jti() {
        let store = LruJtiStore::new(MIN_JTI_CACHE_SIZE);
        let long_jti = "x".repeat(MAX_JTI_LENGTH_BYTES + 1);
        let result = store.check_and_insert(long_jti, 0);
        assert!(matches!(result, Err(CatError::DpopValidationFailed(_))));
    }

    #[cfg(feature = "moqt")]
    #[test]
    fn test_jti_store_still_detects_replay_after_lru_promotion() {
        let store = LruJtiStore::with_shards_and_window(MIN_JTI_CACHE_SIZE, 4, 300);
        store.check_and_insert("keeper".to_string(), 0).unwrap();
        for i in 0..(MIN_JTI_CACHE_SIZE / 4) {
            store
                .check_and_insert(format!("jti-{i}"), 0)
                .expect("insert");
        }
        let result = store.check_and_insert("keeper".to_string(), 0);
        assert!(
            matches!(result, Err(CatError::ReplayAttackDetected)),
            "cached JTI must still be detected as replay"
        );
    }

    #[test]
    fn test_confirmation_claim() {
        let alg = Es256Algorithm::new_with_key_pair().unwrap();
        let jwk = Jwk::from_es256_verifying_key(alg.verifying_key()).unwrap();

        let cnf = confirmation_from_jwk(&jwk).unwrap();
        assert_eq!(cnf.jkt.len(), 32);
        assert!(confirmation_matches_jwk(&cnf, &jwk).unwrap());
    }
}
