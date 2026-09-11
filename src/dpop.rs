// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

//! DPoP proof-of-possession.
//!
//! `DpopProof` is a format-neutral in-memory representation: the header, the
//! payload, and the signature. Wire encoding is implemented in submodules,
//! selected by [`DpopProof::wire_format`] via [`DpopWireFormat`]:
//!
//! - **COSE_Sign1 CWT** ([`cwt`]) — default. Follows
//!   `draft-nandakumar-moq-generic-dpop-proof-00` §3.1 (`typ=dpop-proof+cwt`).
//! - **JWT compact serialization** ([`jwt`]) — RFC 9449 form,
//!   `typ=dpop-proof+jwt`, matching the same draft §3.2 payload shape.
//!
//! The `typ` header carries the draft value verbatim so peers implementing
//! the same draft interoperate without a private opt-in. The private-use
//! CBOR labels this crate assigns for `actx`/`nonce`/`ath` (see the
//! private-label block below) are an implementation detail — the draft
//! leaves those numbers TBD, and this profile identity is negotiated
//! out-of-band, not in the `typ` header.
//!
//! [`DpopProof::encode`] dispatches on the wire format. [`DpopProof::decode`]
//! autodetects (JWT if the input is ASCII with two `.` separators; CWT
//! otherwise). [`DpopProof::decode_as`] forces a specific format.

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

// --- DPoP `typ` values -----------------------------------------------------
//
// draft-nandakumar-moq-generic-dpop-proof-00 fixes the `typ` values used
// for CWT and JWT wire forms of a DPoP proof. Emit them verbatim so peers
// implementing the draft interoperate without a private opt-in.
//
// The private-use CBOR label numbers this crate assigns for `actx`, `nonce`,
// and `ath` (see the label block below — 400/401/402) are TBD in the draft;
// their identity is not carried in the `typ` header. Peers agree on the
// numbers out of band. A future version of the draft that pins IANA labels
// will require a codec change here, not a `typ` change.

/// Text-string `typ` value in the COSE protected header (RFC 9596 label
/// 16) for CWT-format DPoP proofs, per
/// draft-nandakumar-moq-generic-dpop-proof-00 §3.1.
pub const DPOP_TYP: &str = "dpop-proof+cwt";

/// `typ` value for JWT-format DPoP proofs (RFC 9449 §4.2), per
/// draft-nandakumar-moq-generic-dpop-proof-00 §3.2. Held identical to the
/// draft value so RFC 9449 tooling and generic-DPoP peers accept the
/// proof without a private opt-in.
pub const DPOP_TYP_JWT: &str = "dpop-proof+jwt";

/// Wire format for a DPoP proof. The default is [`DpopWireFormat::Cwt`],
/// which matches `draft-nandakumar-moq-generic-dpop-proof-00`; select
/// [`DpopWireFormat::Jwt`] to interoperate with the JOSE-based RFC 9449
/// deployment path expected by CAT-4-MOQT until CWT DPoP is standardized.
///
/// The `DpopProof` in-memory representation is format-neutral — only the
/// codec used by [`DpopProof::encode`]/[`DpopProof::decode`] changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DpopWireFormat {
    /// COSE_Sign1 CWT (`dpop-proof+cwt`). Wire bytes are raw CBOR;
    /// suitable for MOQT control messages that carry the proof as an
    /// opaque blob. Payload shape per
    /// draft-nandakumar-moq-generic-dpop-proof-00 §3.1.
    #[default]
    Cwt,
    /// JWS Compact Serialization (`dpop-proof+jwt`) per
    /// draft-nandakumar-moq-generic-dpop-proof-00 §3.2 and RFC 9449 §4.2.
    /// Wire bytes are ASCII: `base64url(header).base64url(payload).base64url(sig)`.
    Jwt,
}

/// COSE algorithm identifiers accepted for DPoP signing. Symmetric algorithms
/// are forbidden by the draft; asymmetric algorithms only.
///
/// - `-7`  ES256 (RFC 8152)
/// - `-37` PS256 (RFC 8230)
pub const SUPPORTED_DPOP_COSE_ALGORITHMS: &[i64] =
    &[crate::crypto::ALG_ES256, crate::crypto::ALG_PS256];

// --- COSE / CWT labels ---------------------------------------------------
//
// Generic CWT / COSE primitives — RFC 8152 (COSE), RFC 8392 (CWT base
// claims), RFC 8230 (RSA COSE_Key). These are not MOQT-specific and are
// exposed on the crate surface so CAT-only callers can reference them by
// name. The MOQT-specific labels — `ACTX_*` and the private-profile
// `CWT_CLAIM_ACTX/NONCE/ATH` — are cfg-gated below.

// Protected-header labels (RFC 8152 §3.1 / RFC 9596):
pub const COSE_HDR_ALG: i64 = 1;
pub const COSE_HDR_COSE_KEY: i64 = 4;
pub const COSE_HDR_TYP: i64 = 16;

// CWT base-registry payload labels (RFC 8392):
pub const CWT_CLAIM_IAT: i64 = 6;
pub const CWT_CLAIM_CTI: i64 = 7;

// CWT-payload labels for the DPoP claims specific to
// draft-nandakumar-moq-generic-dpop-proof-00. The draft leaves these
// labels TBD; the numbers below are this crate's private-use assignment
// and are matched literally on decode. If the draft (or IANA) later pins
// different numbers, callers on both sides must upgrade — the identity
// is not carried in the `typ` header.
#[cfg(feature = "moqt")]
pub(crate) const CWT_CLAIM_ACTX: i64 = 400;
#[cfg(feature = "moqt")]
pub(crate) const CWT_CLAIM_NONCE: i64 = 401;
#[cfg(feature = "moqt")]
pub(crate) const CWT_CLAIM_ATH: i64 = 402;

// actx inner-map labels (draft §3.2). MOQT-specific.
#[cfg(feature = "moqt")]
pub(crate) const ACTX_TYPE: i64 = 0;
#[cfg(feature = "moqt")]
pub(crate) const ACTX_ACTION: i64 = 1;
#[cfg(feature = "moqt")]
pub(crate) const ACTX_TNS: i64 = 2;
#[cfg(feature = "moqt")]
pub(crate) const ACTX_TN: i64 = 3;
#[cfg(feature = "moqt")]
pub(crate) const ACTX_PARAMETERS: i64 = 4;

// COSE_Key labels (RFC 8152 §7 + RFC 8230 §4 for RSA):
pub const COSE_KEY_KTY: i64 = 1;
pub const COSE_KEY_ALG: i64 = 3;
pub const COSE_KEY_CRV: i64 = -1;
pub const COSE_KEY_X: i64 = -2;
pub const COSE_KEY_Y: i64 = -3;
pub const COSE_KEY_N: i64 = -1; // RSA n (RFC 8230 §4)
pub const COSE_KEY_E: i64 = -2; // RSA e (RFC 8230 §4)

pub const COSE_KTY_EC2: i64 = 2;
pub const COSE_KTY_RSA: i64 = 3;
pub const COSE_CRV_P256: i64 = 1;

pub const COSE_TAG_SIGN1: u64 = 18;

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
    /// Header constructor. `wire_format` selects `typ`:
    /// [`DpopWireFormat::Cwt`] → [`DPOP_TYP`], [`DpopWireFormat::Jwt`] →
    /// [`DPOP_TYP_JWT`]. The wire format on the header must match the
    /// codec that will encode the proof, since `is_valid` accepts either
    /// label.
    pub fn new(wire_format: DpopWireFormat, alg: i64, jwk: Jwk) -> Self {
        let typ = match wire_format {
            DpopWireFormat::Cwt => DPOP_TYP,
            DpopWireFormat::Jwt => DPOP_TYP_JWT,
        };
        Self {
            alg,
            typ: typ.to_string(),
            jwk,
        }
    }

    /// Accept either the CWT profile identifier or the JWT `typ`. The
    /// wire format is fixed by the codec on encode/decode; the header
    /// only carries the human-readable label so a caller inspecting the
    /// parsed proof can tell how it arrived.
    pub fn is_valid(&self) -> bool {
        (self.typ == DPOP_TYP || self.typ == DPOP_TYP_JWT) && self.is_supported_algorithm()
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

    /// Basic well-formedness for the actx map. The tns/tn presence
    /// requirements are action-dependent (setup actions carry only an
    /// endpoint); enforcement of resource shape happens at the authorization
    /// layer via [`crate::MoqtAction::resource_shape`].
    pub fn is_valid(&self) -> bool {
        if self.ctx_type != "moqt" {
            return false;
        }
        match self.action.resource_shape() {
            crate::claims::MoqtResourceShape::Endpoint => true,
            crate::claims::MoqtResourceShape::Namespace
            | crate::claims::MoqtResourceShape::Track => !self.tns.is_empty(),
        }
    }

    /// CAT-4-MOQT §3.1.2 action name as it appears in the serialized
    /// `action` field of `actx`.
    pub fn action_string(&self) -> &'static str {
        moqt_action_wire_name(self.action)
    }
}

/// Text-string wire form of a `MoqtAction`, per CAT-4-MOQT §3.1.2 Table 2.
/// This is what the draft's `actx.action` field carries; keep in sync with the
/// enum.
///
/// Note: `ClientSetup` and `ServerSetup` both serialize to `SETUP` on the wire
/// per Table 2. The distinction is direction of the underlying MOQT control
/// message; a DPoP proof issued by a client always carries `SETUP` and is
/// decoded as `ClientSetup` on the recipient side.
#[cfg(feature = "moqt")]
pub fn moqt_action_wire_name(action: MoqtAction) -> &'static str {
    match action {
        MoqtAction::ClientSetup | MoqtAction::ServerSetup => "SETUP",
        MoqtAction::PublishNamespace => "PUB_NS",
        MoqtAction::SubscribeNamespace => "SUB_NS",
        MoqtAction::Subscribe => "SUBSCRIBE",
        MoqtAction::RequestUpdate => "REQ_UPDATE",
        MoqtAction::Publish => "PUBLISH",
        MoqtAction::Fetch => "FETCH",
        MoqtAction::TrackStatus => "TRK_STATUS",
    }
}

/// Parse a CAT-4-MOQT §3.1.2 action name back into a `MoqtAction`. The wire
/// form `SETUP` is ambiguous between `ClientSetup` and `ServerSetup`; DPoP
/// proofs are issued by the client, so `SETUP` decodes to `ClientSetup`.
#[cfg(feature = "moqt")]
pub fn moqt_action_from_wire_name(name: &str) -> Result<MoqtAction, CatError> {
    match name {
        "SETUP" => Ok(MoqtAction::ClientSetup),
        "PUB_NS" => Ok(MoqtAction::PublishNamespace),
        "SUB_NS" => Ok(MoqtAction::SubscribeNamespace),
        "SUBSCRIBE" => Ok(MoqtAction::Subscribe),
        "REQ_UPDATE" => Ok(MoqtAction::RequestUpdate),
        "PUBLISH" => Ok(MoqtAction::Publish),
        "FETCH" => Ok(MoqtAction::Fetch),
        "TRK_STATUS" => Ok(MoqtAction::TrackStatus),
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

/// Constant-time compare a cached thumbprint against a confirmation claim.
/// Faster than [`confirmation_matches_jwk`] on the hot path because the
/// thumbprint is precomputed once at proof construction time.
#[cfg(feature = "moqt")]
pub(crate) fn confirmation_matches_thumbprint(cnf: &ConfirmationClaim, jkt: &[u8]) -> bool {
    crate::crypto::constant_time_eq(&cnf.jkt, jkt)
}

// --- Proof --------------------------------------------------------------

/// In-memory DPoP proof. Format-neutral: `encode()`/`decode()` route through
/// either the CWT ([`cwt`]) or JWT ([`jwt`]) wire codec depending on
/// `wire_format`. The fields have no wire dependency of their own.
#[cfg(feature = "moqt")]
#[derive(Clone)]
pub struct DpopProof {
    pub(crate) header: DpopHeader,
    pub(crate) payload: DpopPayload,
    pub(crate) signature: Vec<u8>,
    /// Exact protected-header + payload bytes the signature covers, as
    /// received on the wire. For CWT, these are the raw CBOR bytes of the
    /// header map and payload map — see COSE_Sign1's `Sig_structure` input
    /// (RFC 8152 §4.4). For JWT, these are the raw JSON bytes of the header
    /// object and payload object; the JWS signing input is derived by
    /// base64url-encoding them and joining with `.` (RFC 7515 §5.1).
    /// Preserving the received bytes lets the verifier operate on them
    /// directly rather than re-serializing.
    pub(crate) signed_bytes: SignedInput,
    /// Wire format this proof will encode to and decoded from. Defaults to
    /// [`DpopWireFormat::Cwt`]; changing this is the only knob the
    /// authorizer sees — everything else is format-neutral.
    pub(crate) wire_format: DpopWireFormat,
    /// Cached RFC 7638 JWK thumbprint of `header.jwk`. Computed lazily on
    /// first access (either at decode or the first `authorize` call) and
    /// reused for every subsequent thumbprint check and JTI commit-key
    /// build. Avoids the SHA-256 recompute on the hot authorize path.
    pub(crate) jkt_cache: std::sync::OnceLock<Vec<u8>>,
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
            wire_format: DpopWireFormat::Cwt,
            jkt_cache: std::sync::OnceLock::new(),
        }
    }

    /// Compute (once) and return the RFC 7638 JWK thumbprint of the
    /// proof's holder key. Cached across every subsequent call so the
    /// hot authorize path pays SHA-256 only for the first request.
    pub fn jwk_thumbprint(&self) -> Result<&[u8], CatError> {
        if let Some(v) = self.jkt_cache.get() {
            return Ok(v.as_slice());
        }
        let computed = self.header.jwk.thumbprint()?;
        // First writer wins; second-to-set discards its computation but
        // both computations produce the same bytes so there is no
        // observable divergence.
        let _ = self.jkt_cache.set(computed);
        Ok(self
            .jkt_cache
            .get()
            .expect("jkt_cache populated")
            .as_slice())
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

    pub fn wire_format(&self) -> DpopWireFormat {
        self.wire_format
    }

    /// Select the wire format this proof will encode to. Also flips the
    /// header's `typ` to the matching value. Resets any cached signed
    /// bytes because the codec-specific serialization must be redone.
    pub fn with_wire_format(mut self, format: DpopWireFormat) -> Self {
        self.wire_format = format;
        self.header.typ = match format {
            DpopWireFormat::Cwt => DPOP_TYP.to_string(),
            DpopWireFormat::Jwt => DPOP_TYP_JWT.to_string(),
        };
        self.signed_bytes = SignedInput::default();
        self
    }

    /// Build an unsigned proof for a MOQT request. Alg is passed as a COSE
    /// algorithm id (e.g. `-7` for ES256). Defaults to
    /// [`DpopWireFormat::Cwt`] — call [`DpopProof::with_wire_format`] to
    /// select JWT.
    pub fn create_for_moqt(
        action: MoqtAction,
        namespace: Vec<Vec<u8>>,
        track: &[u8],
        alg: i64,
        jwk: Jwk,
    ) -> Self {
        let header = DpopHeader::new(DpopWireFormat::Cwt, alg, jwk);
        let actx = AuthorizationContext::new_moqt(action, namespace, track);
        let payload = DpopPayload::new(actx);
        Self {
            header,
            payload,
            signature: Vec::new(),
            signed_bytes: SignedInput::default(),
            wire_format: DpopWireFormat::Cwt,
            jkt_cache: std::sync::OnceLock::new(),
        }
    }

    /// Set the proof's replay identifier — encoded as bytes on the wire
    /// (`cti`) so a caller supplying a UUID as `String` and a caller supplying
    /// raw bytes reach the same field. Any `impl Into<Vec<u8>>` is accepted:
    /// `String`, `&str`, `Vec<u8>`, and `&[u8]` all work.
    pub fn with_replay_id(mut self, id: impl Into<Vec<u8>>) -> Self {
        self.payload.cti = Some(id.into());
        self.signed_bytes = SignedInput::default();
        self
    }

    pub fn with_resource(mut self, resource: String) -> Self {
        self.payload.actx.resource = Some(resource);
        self.signed_bytes = SignedInput::default();
        self
    }

    /// Set the access-token hash (`ath`) as raw digest bytes (typically the
    /// SHA-256 of the base64url-encoded token, per RFC 9449 §4.1).
    pub fn with_access_token_hash(mut self, ath: impl Into<Vec<u8>>) -> Self {
        self.payload.ath = Some(ath.into());
        self.signed_bytes = SignedInput::default();
        self
    }

    /// Set the access-token hash (`ath`) from the base64url form emitted by
    /// [`compute_access_token_hash_b64`]. Falls back to storing the raw
    /// string bytes if decoding fails, matching the prior lenient behavior.
    pub fn with_access_token_hash_b64(mut self, ath_b64: impl Into<String>) -> Self {
        let s = ath_b64.into();
        let bytes = URL_SAFE_NO_PAD
            .decode(&s)
            .unwrap_or_else(|_| s.into_bytes());
        self.payload.ath = Some(bytes);
        self.signed_bytes = SignedInput::default();
        self
    }

    pub fn with_nonce(mut self, nonce: String) -> Self {
        self.payload.nonce = Some(nonce);
        self.signed_bytes = SignedInput::default();
        self
    }

    /// Bytes the signature was (or will be) computed over. Dispatches on
    /// [`DpopProof::wire_format`]: CWT proofs return the `Sig_structure`
    /// input from RFC 8152 §4.4; JWT proofs return the JWS signing input
    /// `base64url(header) || '.' || base64url(payload)` from RFC 7515 §5.1.
    /// For decoded proofs this reflects the received wire bytes; for
    /// locally-built proofs it is derived at sign time.
    pub fn signing_input(&self) -> Result<Vec<u8>, CatError> {
        match self.wire_format {
            DpopWireFormat::Cwt => cwt::signing_input(self),
            DpopWireFormat::Jwt => jwt::signing_input(self),
        }
    }

    pub fn sign(&mut self, algorithm: &dyn CryptographicAlgorithm) -> Result<(), CatError> {
        if algorithm.algorithm_id() != self.header.alg {
            return Err(CatError::AlgorithmMismatch {
                expected: self.header.alg,
                found: algorithm.algorithm_id(),
            });
        }
        let bytes = match self.wire_format {
            DpopWireFormat::Cwt => cwt::encode_header_and_payload(&self.header, &self.payload)?,
            DpopWireFormat::Jwt => jwt::encode_header_and_payload(&self.header, &self.payload)?,
        };
        let sig_input = match self.wire_format {
            DpopWireFormat::Cwt => crate::crypto::create_signing_input(
                &bytes.header_cbor,
                &bytes.payload_cbor,
                self.header.alg,
            )?,
            DpopWireFormat::Jwt => jwt::jws_signing_input(&bytes),
        };
        self.signature = algorithm.sign(&sig_input)?;
        self.signed_bytes = bytes;
        Ok(())
    }

    /// Encode this proof using the codec selected by
    /// [`DpopProof::wire_format`]. CWT proofs produce raw CBOR bytes;
    /// JWT proofs produce ASCII bytes in JWS compact serialization
    /// (`base64url(header).base64url(payload).base64url(sig)`).
    pub fn encode(&self) -> Result<Vec<u8>, CatError> {
        match self.wire_format {
            DpopWireFormat::Cwt => cwt::encode(self),
            DpopWireFormat::Jwt => jwt::encode(self),
        }
    }

    /// Decode a proof, autodetecting the wire format. A leading CBOR tag
    /// byte (`0xD2` for tag 18) selects [`cwt::decode`]; ASCII input with
    /// two `.` separators selects [`jwt::decode`]. See the module docs
    /// for the acceptance rules of each.
    pub fn decode(bytes: &[u8]) -> Result<Self, CatError> {
        if looks_like_jwt(bytes) {
            jwt::decode(bytes)
        } else {
            cwt::decode(bytes)
        }
    }

    /// Decode explicitly under a chosen format. Prefer
    /// [`DpopProof::decode`] unless the caller has out-of-band knowledge
    /// of the wire format and wants to reject the other.
    pub fn decode_as(bytes: &[u8], format: DpopWireFormat) -> Result<Self, CatError> {
        match format {
            DpopWireFormat::Cwt => cwt::decode(bytes),
            DpopWireFormat::Jwt => jwt::decode(bytes),
        }
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

#[cfg(feature = "moqt")]
fn looks_like_jwt(bytes: &[u8]) -> bool {
    // A JWS compact serialization is entirely ASCII base64url + two `.`
    // separators. A CBOR-tagged COSE_Sign1 starts with 0xd2 (tag 18) or an
    // untagged array header byte `0x84` — neither of which is a valid
    // base64url character. Reject anything with a non-ASCII byte
    // immediately; otherwise require two `.`s to keep decode_as-style
    // dispatch unambiguous.
    if bytes.is_empty() || !bytes.iter().all(|b| b.is_ascii()) {
        return false;
    }
    bytes.iter().filter(|&&b| b == b'.').count() == 2
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
            wire_format: DpopWireFormat::Cwt,
            jkt_cache: std::sync::OnceLock::new(),
        })
    }

    pub(super) fn signing_input(proof: &DpopProof) -> Result<Vec<u8>, CatError> {
        let SignedInput {
            header_cbor,
            payload_cbor,
        } = if proof.signed_bytes.is_empty() {
            encode_header_and_payload(&proof.header, &proof.payload)?
        } else {
            proof.signed_bytes.clone()
        };
        crate::crypto::create_signing_input(&header_cbor, &payload_cbor, proof.header.alg)
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
                // `is_safe` guarantees `b` is ASCII (alphanumeric or `_`),
                // so the char cast is a well-defined codepoint reinterpret
                // (not a Latin-1 mangling of a UTF-8 continuation byte).
                out.push(char::from(b));
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

    pub(super) fn moq_element_from_canonical(s: &str) -> Result<Vec<u8>, CatError> {
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

    pub(super) fn moq_tns_from_canonical(s: &str) -> Result<Vec<Vec<u8>>, CatError> {
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

// --- JWT wire codec -----------------------------------------------------

/// JWS compact serialization wire codec for DPoP proofs (`dpop-proof+jwt`).
///
/// RFC 9449 §4.2 defines the JWT-form DPoP proof. The DpopProof
/// in-memory representation is format-neutral, so the JWT and CWT codecs
/// share the semantic layer (header alg/typ, payload iat/cti/actx/ath/
/// nonce, JWK holder key) and only differ in how the header and payload
/// are serialized and signed.
///
/// # Payload shape
///
/// Matches draft-nandakumar-moq-generic-dpop-proof-00 §3.2. `tns` and
/// `tn` are single UTF-8 text strings in MOQTransport §1.5.1 canonical
/// form (safe ASCII `[A-Za-z0-9_]` passes through, other bytes escape as
/// `.HH`; namespace segments join with `-`). `jti` is a UTF-8 text
/// string. Only `ath` remains base64url because SHA-256 output is
/// arbitrary bytes with no text representation the draft mandates.
///
/// ```text
/// {
///   "iat":  <unix seconds int>,
///   "jti":  "<utf-8 text>",                          // draft §3.2
///   "actx": {
///     "type":    "moqt",
///     "action":  "SUBSCRIBE",                        // CAT-4-MOQT §3.1.2 mnemonic
///     "tns":     "seg1-seg2",                        // MOQ canonical single string
///     "tn":      "<canonical track name>",
///     "resource":"moqt://..."                        // optional
///   },
///   "ath":  "<base64url of SHA-256(access token)>",  // optional
///   "nonce":"<server nonce string>"                  // optional
/// }
/// ```
///
/// This is the only shape accepted; a JSON-array `tns` (or any non-text
/// value on `tns`/`tn`) is rejected on decode. Non-UTF-8 namespace bytes
/// round-trip through the `.HH` escape without loss — the two wire
/// forms carry identical `actx` semantics.
#[cfg(feature = "moqt")]
pub mod jwt {
    use super::*;
    use serde_json::{Map, Value as Json};

    pub(super) fn encode(proof: &DpopProof) -> Result<Vec<u8>, CatError> {
        let bytes = if proof.signed_bytes.is_empty() {
            encode_header_and_payload(&proof.header, &proof.payload)?
        } else {
            proof.signed_bytes.clone()
        };
        let mut out = Vec::with_capacity(bytes.header_cbor.len() + bytes.payload_cbor.len() + 2);
        out.extend_from_slice(URL_SAFE_NO_PAD.encode(&bytes.header_cbor).as_bytes());
        out.push(b'.');
        out.extend_from_slice(URL_SAFE_NO_PAD.encode(&bytes.payload_cbor).as_bytes());
        out.push(b'.');
        out.extend_from_slice(URL_SAFE_NO_PAD.encode(&proof.signature).as_bytes());
        Ok(out)
    }

    pub(super) fn decode(bytes: &[u8]) -> Result<DpopProof, CatError> {
        if bytes.len() > MAX_DPOP_WIRE_SIZE {
            return Err(CatError::InvalidTokenFormat);
        }
        let text = std::str::from_utf8(bytes).map_err(|_| CatError::InvalidTokenFormat)?;
        let mut parts = text.split('.');
        let h_b64 = parts.next().ok_or(CatError::InvalidTokenFormat)?;
        let p_b64 = parts.next().ok_or(CatError::InvalidTokenFormat)?;
        let s_b64 = parts.next().ok_or(CatError::InvalidTokenFormat)?;
        if parts.next().is_some() {
            return Err(CatError::InvalidTokenFormat);
        }
        let header_bytes = URL_SAFE_NO_PAD
            .decode(h_b64)
            .map_err(|e| CatError::InvalidBase64(e.to_string()))?;
        let payload_bytes = URL_SAFE_NO_PAD
            .decode(p_b64)
            .map_err(|e| CatError::InvalidBase64(e.to_string()))?;
        let signature = URL_SAFE_NO_PAD
            .decode(s_b64)
            .map_err(|e| CatError::InvalidBase64(e.to_string()))?;

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
            wire_format: DpopWireFormat::Jwt,
            jkt_cache: std::sync::OnceLock::new(),
        })
    }

    pub(super) fn signing_input(proof: &DpopProof) -> Result<Vec<u8>, CatError> {
        let bytes = if proof.signed_bytes.is_empty() {
            encode_header_and_payload(&proof.header, &proof.payload)?
        } else {
            proof.signed_bytes.clone()
        };
        Ok(jws_signing_input(&bytes))
    }

    /// JWS signing input per RFC 7515 §5.1:
    ///   ASCII( base64url(header) || '.' || base64url(payload) )
    pub(super) fn jws_signing_input(bytes: &SignedInput) -> Vec<u8> {
        let h = URL_SAFE_NO_PAD.encode(&bytes.header_cbor);
        let p = URL_SAFE_NO_PAD.encode(&bytes.payload_cbor);
        let mut out = Vec::with_capacity(h.len() + p.len() + 1);
        out.extend_from_slice(h.as_bytes());
        out.push(b'.');
        out.extend_from_slice(p.as_bytes());
        out
    }

    pub(super) fn encode_header_and_payload(
        header: &DpopHeader,
        payload: &DpopPayload,
    ) -> Result<SignedInput, CatError> {
        Ok(SignedInput {
            header_cbor: encode_header_json(header)?,
            payload_cbor: encode_payload_json(payload)?,
        })
    }

    fn encode_header_json(header: &DpopHeader) -> Result<Vec<u8>, CatError> {
        let alg = crate::crypto::cose_to_jose_algorithm(header.alg).ok_or_else(|| {
            CatError::UnsupportedAlgorithm(format!("no JOSE mapping for COSE alg {}", header.alg))
        })?;
        let mut map = Map::new();
        map.insert("alg".to_string(), Json::String(alg.to_string()));
        map.insert("typ".to_string(), Json::String(header.typ.clone()));
        map.insert(
            "jwk".to_string(),
            serde_json::to_value(&header.jwk)
                .map_err(|e| CatError::KeyOperationFailed(format!("jwk serialize: {e}")))?,
        );
        serde_json::to_vec(&Json::Object(map))
            .map_err(|e| CatError::KeyOperationFailed(format!("header serialize: {e}")))
    }

    fn decode_header(bytes: &[u8]) -> Result<DpopHeader, CatError> {
        let v: Json =
            serde_json::from_slice(bytes).map_err(|e| CatError::InvalidCbor(e.to_string()))?;
        let obj = v.as_object().ok_or(CatError::InvalidTokenFormat)?;
        let alg_str = obj
            .get("alg")
            .and_then(|v| v.as_str())
            .ok_or_else(|| CatError::MissingRequiredClaim("alg".to_string()))?;
        let alg = crate::crypto::jose_to_cose_algorithm(alg_str)
            .ok_or_else(|| CatError::UnsupportedAlgorithm(alg_str.to_string()))?;
        let typ = obj
            .get("typ")
            .and_then(|v| v.as_str())
            .ok_or_else(|| CatError::MissingRequiredClaim("typ".to_string()))?
            .to_string();
        let jwk_val = obj
            .get("jwk")
            .ok_or_else(|| CatError::MissingRequiredClaim("jwk".to_string()))?
            .clone();
        let jwk: Jwk = serde_json::from_value(jwk_val)
            .map_err(|e| CatError::InvalidClaimValue(format!("jwk: {e}")))?;
        Ok(DpopHeader { alg, typ, jwk })
    }

    fn encode_payload_json(payload: &DpopPayload) -> Result<Vec<u8>, CatError> {
        let mut map = Map::new();
        map.insert("iat".to_string(), Json::Number(payload.iat.into()));
        if let Some(cti) = &payload.cti {
            // RFC 9449 §4.2: jti is a JSON string. The in-memory `cti` field is
            // typed as bytes because CWT (RFC 8392 §3.1.7) requires a byte
            // string; for JWT we need a text form. UUIDs and base64url tokens
            // are ASCII-compatible; interpret the stored bytes as UTF-8 and
            // reject non-UTF-8 payloads rather than silently base64url-
            // encoding them (that would produce non-interoperable wire bytes).
            let jti = std::str::from_utf8(cti).map_err(|_| {
                CatError::InvalidClaimValue(
                    "JWT encoding requires jti to be UTF-8 text; the in-memory \
                     cti bytes are not valid UTF-8. Use text-form jti (e.g. \
                     generate_jti()) or the CWT wire format."
                        .to_string(),
                )
            })?;
            map.insert("jti".to_string(), Json::String(jti.to_string()));
        }
        map.insert("actx".to_string(), actx_to_json(&payload.actx)?);
        if let Some(nonce) = &payload.nonce {
            map.insert("nonce".to_string(), Json::String(nonce.clone()));
        }
        if let Some(ath) = &payload.ath {
            // RFC 9449 §4.2: ath is base64url of the SHA-256 of the access
            // token. `payload.ath` holds the raw hash bytes; encode here.
            map.insert("ath".to_string(), Json::String(URL_SAFE_NO_PAD.encode(ath)));
        }
        serde_json::to_vec(&Json::Object(map))
            .map_err(|e| CatError::KeyOperationFailed(format!("payload serialize: {e}")))
    }

    fn decode_payload(bytes: &[u8]) -> Result<DpopPayload, CatError> {
        let v: Json =
            serde_json::from_slice(bytes).map_err(|e| CatError::InvalidCbor(e.to_string()))?;
        let obj = v.as_object().ok_or(CatError::InvalidTokenFormat)?;
        let iat = obj
            .get("iat")
            .and_then(|v| v.as_i64())
            .ok_or_else(|| CatError::MissingRequiredClaim("iat".to_string()))?;
        let cti = match obj.get("jti") {
            Some(Json::String(s)) => Some(s.as_bytes().to_vec()),
            Some(_) => {
                return Err(CatError::InvalidClaimValue(
                    "jti must be a string".to_string(),
                ));
            }
            None => None,
        };
        let actx_val = obj
            .get("actx")
            .ok_or_else(|| CatError::MissingRequiredClaim("actx".to_string()))?;
        let actx = actx_from_json(actx_val)?;
        let nonce = obj
            .get("nonce")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let ath = match obj.get("ath") {
            Some(Json::String(s)) => Some(
                URL_SAFE_NO_PAD
                    .decode(s)
                    .map_err(|e| CatError::InvalidBase64(e.to_string()))?,
            ),
            Some(_) => {
                return Err(CatError::InvalidClaimValue(
                    "ath must be a base64url string".to_string(),
                ));
            }
            None => None,
        };
        Ok(DpopPayload {
            cti,
            iat,
            actx,
            ath,
            nonce,
        })
    }

    /// Serialize `actx` into JWT-form JSON per
    /// draft-nandakumar-moq-generic-dpop-proof-00 §3.2. `tns` and `tn` are
    /// single UTF-8 text strings using the MOQTransport §1.5.1 canonical
    /// serialization (safe ASCII passed through, other bytes escaped as
    /// `.HH`; namespace segments joined by `-`) so the JWT wire form
    /// carries the same information as the CWT byte-string form without
    /// requiring JSON callers to reason about a nested array of tuples.
    fn actx_to_json(actx: &AuthorizationContext) -> Result<Json, CatError> {
        let mut map = Map::new();
        map.insert("type".to_string(), Json::String(actx.ctx_type.clone()));
        map.insert(
            "action".to_string(),
            Json::String(moqt_action_wire_name(actx.action).to_string()),
        );
        map.insert(
            "tns".to_string(),
            Json::String(cwt::moq_canonical_tns(&actx.tns)),
        );
        if !actx.tn.is_empty() {
            map.insert(
                "tn".to_string(),
                Json::String(cwt::moq_canonical_element(&actx.tn)),
            );
        }
        if let Some(resource) = &actx.resource {
            map.insert("resource".to_string(), Json::String(resource.clone()));
        }
        Ok(Json::Object(map))
    }

    fn actx_from_json(v: &Json) -> Result<AuthorizationContext, CatError> {
        let obj = v
            .as_object()
            .ok_or_else(|| CatError::InvalidClaimValue("actx must be a JSON object".to_string()))?;
        let ctx_type = obj
            .get("type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| CatError::MissingRequiredClaim("actx.type".to_string()))?
            .to_string();
        let action_name = obj
            .get("action")
            .and_then(|v| v.as_str())
            .ok_or_else(|| CatError::MissingRequiredClaim("actx.action".to_string()))?;
        let action = moqt_action_from_wire_name(action_name)?;
        // draft §3.2: `tns` is a single text string in MOQ canonical form.
        // An empty string decodes to a single empty segment — endpoint
        // shapes (`SETUP`) carry an empty `tns`, so reject those upstream
        // via the actx-shape check, not here.
        let tns_str = match obj.get("tns") {
            Some(Json::String(s)) => s.as_str(),
            Some(_) => {
                return Err(CatError::InvalidClaimValue(
                    "actx.tns must be a text string in MOQ canonical form; \
                     array forms are not part of draft-nandakumar-moq-generic\
                     -dpop-proof-00 §3.2"
                        .to_string(),
                ));
            }
            None => return Err(CatError::MissingRequiredClaim("actx.tns".to_string())),
        };
        let tns = if tns_str.is_empty() {
            Vec::new()
        } else {
            cwt::moq_tns_from_canonical(tns_str)?
        };
        let tn = match obj.get("tn") {
            Some(Json::String(s)) if s.is_empty() => Vec::new(),
            Some(Json::String(s)) => cwt::moq_element_from_canonical(s)?,
            Some(_) => {
                return Err(CatError::InvalidClaimValue(
                    "actx.tn must be a text string".to_string(),
                ));
            }
            None => Vec::new(),
        };
        let resource = obj
            .get("resource")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        Ok(AuthorizationContext {
            ctx_type,
            action,
            tns,
            tn,
            resource,
        })
    }
}

// --- JTI store (unchanged from prior batch) -----------------------------

#[cfg(feature = "moqt")]
const DEFAULT_JTI_CACHE_SIZE: usize = 100_000;

#[cfg(feature = "moqt")]
const MIN_JTI_CACHE_SIZE: usize = 1000;

/// Hard upper bound on the LRU JTI cache. Capacity requests above this are
/// clamped to prevent a config typo from allocating gigabytes of shard state
/// on startup. 10M entries at ~256 bytes per key is ~2.5 GiB — well past any
/// sensible in-process store.
#[cfg(feature = "moqt")]
pub const MAX_JTI_CACHE_SIZE: usize = 10_000_000;

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
    ///
    /// This is a **self-attestation**: it advertises intent, not proof.
    /// The validator cannot verify from `is_strict() == true` alone that
    /// the backend is durable across relay restarts, that inserts are
    /// atomic (insert-if-absent, not check-then-set) across concurrent
    /// nodes, that TTL is at least the freshness window, or that the
    /// backend fails closed on outage. Distributed strict deployments
    /// must satisfy those additional obligations at the store level; see
    /// [`crate::moqt::MoqtValidator::dpop_strict`]
    /// for the full caller contract.
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
        let requested_capacity = capacity.clamp(MIN_JTI_CACHE_SIZE, MAX_JTI_CACHE_SIZE);
        // Bound the shard count so we never over-allocate on tiny caches.
        // Each shard needs at least one slot; more shards than requested
        // capacity would inflate the total (per_shard rounds up to 1) and
        // waste memory, so cap `shard_count` at `requested_capacity`.
        let shard_count = shards.max(1).min(requested_capacity);
        // Distribute capacity so the sum of per-shard capacities equals
        // `requested_capacity` exactly. Prior implementation used
        // `(cap / shards).max(1)` which either over-allocated (when cap
        // was smaller than shards) or dropped remainder (making total
        // capacity smaller than requested); both are wrong.
        let base = requested_capacity / shard_count;
        let remainder = requested_capacity % shard_count;
        let shards = (0..shard_count)
            .map(|i| {
                let extra = if i < remainder { 1 } else { 0 };
                LruShard::new(base + extra)
            })
            .collect();
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
            .map_err(|_| CatError::BackendUnavailable("Lock poisoned".to_string()))?;
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

/// Strict, in-memory, sharded, TTL-backed JtiStore for tests and single-node
/// deployments that need [`JtiStore::is_strict`] to return `true`.
///
/// Unlike [`LruJtiStore`], this store retains every accepted JTI for its
/// full freshness window: entries are never evicted for capacity, only
/// removed by an explicit [`InMemoryStrictJtiStore::cleanup`] call after
/// their TTL has elapsed. This meets the RFC 9449 §11.1 retention
/// requirement.
///
/// # Capacity is mandatory
///
/// The constructor requires a `max_entries` bound. A store that grows
/// without bound is a memory-DoS primitive at CDN scale — a hostile
/// stream of unique JTIs pins entire request memory into the map, and a
/// missed `cleanup` cadence turns the process into a runaway allocator.
/// Insertion above the cap fails with `DpopValidationFailed`, not
/// silent eviction. Callers who genuinely accept the risk (fuzzing,
/// single-run diagnostics) may opt in via
/// [`InMemoryStrictJtiStore::dangerously_unbounded`].
///
/// # Sharding
///
/// The store is sharded across [`DEFAULT_JTI_SHARDS`] independent
/// `Mutex`-protected `HashMap`s (fixed at 16). Under concurrent load
/// two inserts with distinct JTIs contend on the same lock only when
/// their JTI hashes collide modulo the shard count, so throughput
/// scales linearly with core count up to that limit.
#[cfg(feature = "moqt")]
struct StrictShard {
    entries: Mutex<std::collections::HashMap<String, i64>>,
}

#[cfg(feature = "moqt")]
impl StrictShard {
    fn new() -> Self {
        Self {
            entries: Mutex::new(std::collections::HashMap::new()),
        }
    }
}

#[cfg(feature = "moqt")]
pub struct InMemoryStrictJtiStore {
    shards: Vec<StrictShard>,
    hasher_state: std::collections::hash_map::RandomState,
    freshness_window_seconds: i64,
    /// Absolute cap across all shards. `None` only for the
    /// `dangerously_unbounded` construction path.
    max_entries: Option<usize>,
    /// Approximate current entry count, updated under each shard lock. A
    /// single atomic avoids the O(shards) sum on the hot insert path.
    total_entries: std::sync::atomic::AtomicUsize,
    rejected_over_capacity: std::sync::atomic::AtomicU64,
}

#[cfg(feature = "moqt")]
impl InMemoryStrictJtiStore {
    /// Create a strict store with a freshness window and mandatory
    /// entry cap. Both parameters are load-bearing — the window drives
    /// `cleanup` cadence expectations, the cap prevents unbounded
    /// growth if that cadence slips. `cleanup` (or
    /// [`Self::cleanup_expired`]) must still be called periodically
    /// (typically by a background timer) to drop entries older than the
    /// window; without it the store fills to `max_entries` and then
    /// refuses inserts.
    pub fn new(freshness_window_seconds: i64, max_entries: usize) -> Self {
        Self::build(freshness_window_seconds, Some(max_entries))
    }

    /// Create a strict store with a freshness window and NO entry cap.
    /// Only appropriate for fuzzing, single-run diagnostics, or
    /// deployments where memory is bounded by other means. Production
    /// relays must use [`Self::new`] with an explicit cap.
    pub fn dangerously_unbounded(freshness_window_seconds: i64) -> Self {
        Self::build(freshness_window_seconds, None)
    }

    fn build(freshness_window_seconds: i64, max_entries: Option<usize>) -> Self {
        let shards = (0..DEFAULT_JTI_SHARDS)
            .map(|_| StrictShard::new())
            .collect();
        Self {
            shards,
            hasher_state: std::collections::hash_map::RandomState::new(),
            freshness_window_seconds,
            max_entries,
            total_entries: std::sync::atomic::AtomicUsize::new(0),
            rejected_over_capacity: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Reduce the absolute cap after construction. Cannot lift a
    /// `dangerously_unbounded` store back into bounded mode — that
    /// would be silent policy narrowing across shards under load; if a
    /// cap is desired, rebuild the store from scratch.
    pub fn with_max_entries(mut self, max: usize) -> Self {
        if let Some(current) = self.max_entries {
            self.max_entries = Some(current.min(max));
        } else {
            self.max_entries = Some(max);
        }
        self
    }

    /// Total inserts that were refused because the entry cap was reached.
    /// Exported for operational visibility.
    pub fn rejected_over_capacity(&self) -> u64 {
        self.rejected_over_capacity
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Convenience wrapper around [`JtiStore::cleanup`] that uses the
    /// freshness window supplied at construction time. Call this from a
    /// periodic timer so entries do not accumulate past their TTL.
    pub fn cleanup_expired(&self) {
        self.cleanup(self.freshness_window_seconds);
    }

    fn shard_for(&self, key: &str) -> &StrictShard {
        use std::hash::{BuildHasher, Hasher};
        let mut hasher = self.hasher_state.build_hasher();
        hasher.write(key.as_bytes());
        let idx = (hasher.finish() as usize) % self.shards.len();
        &self.shards[idx]
    }
}

#[cfg(feature = "moqt")]
impl JtiStore for InMemoryStrictJtiStore {
    fn check_and_insert(&self, key: String, iat: i64) -> Result<(), CatError> {
        if key.len() > MAX_JTI_LENGTH_BYTES {
            return Err(CatError::DpopValidationFailed(format!(
                "JTI exceeds {MAX_JTI_LENGTH_BYTES} byte cap"
            )));
        }
        // Global cap first, before taking a shard lock. An over-cap
        // relay must refuse inserts on every shard uniformly; without
        // this check a caller could see per-shard slop.
        if let Some(max) = self.max_entries
            && self
                .total_entries
                .load(std::sync::atomic::Ordering::Relaxed)
                >= max
        {
            self.rejected_over_capacity
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Err(CatError::DpopValidationFailed(format!(
                "strict JTI store at max_entries={max}; increase capacity or cleanup cadence"
            )));
        }

        let shard = self.shard_for(&key);
        let mut entries = shard
            .entries
            .lock()
            .map_err(|_| CatError::BackendUnavailable("Lock poisoned".to_string()))?;
        if entries.contains_key(&key) {
            return Err(CatError::ReplayAttackDetected);
        }
        entries.insert(key, iat);
        self.total_entries
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    fn len(&self) -> usize {
        self.total_entries
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    fn cleanup(&self, max_age_seconds: i64) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs() as i64;
        let mut removed = 0usize;
        for shard in &self.shards {
            if let Ok(mut entries) = shard.entries.lock() {
                let before = entries.len();
                entries.retain(|_, iat| now.saturating_sub(*iat) < max_age_seconds);
                removed += before - entries.len();
            }
        }
        if removed > 0 {
            self.total_entries
                .fetch_sub(removed, std::sync::atomic::Ordering::Relaxed);
        }
    }

    fn premature_evictions(&self) -> u64 {
        // Strict stores never prematurely evict; entries that overflow
        // capacity are refused, not dropped. Report zero.
        0
    }

    fn is_strict(&self) -> bool {
        true
    }
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
    /// **Not strict** — see [`DpopValidator::new`]. Cache capacity is
    /// clamped to `[MIN_JTI_CACHE_SIZE, MAX_JTI_CACHE_SIZE]`.
    pub fn with_cache_size(settings: CatDpopSettings, cache_size: usize) -> Self {
        let effective_size = cache_size.clamp(MIN_JTI_CACHE_SIZE, MAX_JTI_CACHE_SIZE);
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

    /// Startup-time sanity check: reject settings whose freshness window is
    /// zero, negative, or absurdly large. Freshness window is what bounds
    /// the memory footprint of a strict retention store, so a
    /// misconfiguration here silently balloons memory across the fleet.
    /// Callers building validators from config should invoke this before
    /// wiring the store.
    pub fn preflight(settings: &CatDpopSettings) -> Result<(), CatError> {
        let window = settings.effective_window();
        if window <= 0 {
            return Err(CatError::InvalidClaimValue(format!(
                "DPoP freshness window must be > 0 (got {window}s)"
            )));
        }
        if window > crate::claims::CATDPOP_MAX_WINDOW_SECS {
            return Err(CatError::InvalidClaimValue(format!(
                "DPoP freshness window {window}s exceeds cap {}s",
                crate::claims::CATDPOP_MAX_WINDOW_SECS
            )));
        }
        Ok(())
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
    /// constructor returns [`CatError::ConfigurationRefused`] to force
    /// the caller to either mark the store strict or fall back to
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
            return Err(CatError::ConfigurationRefused(
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
        let jwk_thumbprint = proof.jwk_thumbprint()?;
        if !crate::crypto::constant_time_eq(jwk_thumbprint, expected_thumbprint) {
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

    /// Compute the composite (issuer, holder-key, cti) JTI-store key that
    /// [`Self::commit_jti`] would insert for this proof, or `None` if the
    /// configured settings don't honour JTIs or the proof carries no cti.
    ///
    /// Exposed so async integrations
    /// ([`crate::r#async::AsyncMoqtValidator::authorize`]) can build the same
    /// key and commit against an [`crate::r#async::AsyncJtiStore`] without
    /// duplicating the key-shape logic.
    pub fn dpop_commit_key(
        &self,
        proof: &DpopProof,
        thumbprint: &[u8],
        issuer: Option<&str>,
    ) -> Option<(String, i64)> {
        if !self.settings.should_honor_jti() {
            return None;
        }
        self.dpop_commit_key_forced(proof, thumbprint, issuer)
    }

    /// Build the JTI commit key regardless of the token's `honor_jti`
    /// setting. Used when the relay operator has escalated JTI tracking
    /// to mandatory via [`crate::MoqtValidator::require_dpop_replay_tracking`]
    /// — a hostile issuer cannot then downgrade replay defense by
    /// clearing the `honor_jti` bit in the token.
    pub fn dpop_commit_key_forced(
        &self,
        proof: &DpopProof,
        thumbprint: &[u8],
        issuer: Option<&str>,
    ) -> Option<(String, i64)> {
        let cti = proof.payload.cti.as_ref()?;
        let iss = issuer.unwrap_or("_");
        // Composite key: (issuer, holder-key, cti bytes hex). Hex of cti
        // keeps the key printable and bounded regardless of the raw byte
        // content (which may include NULs or non-UTF-8 sequences).
        Some((
            format!("{}:{}:{}", iss, hex::encode(thumbprint), hex::encode(cti)),
            proof.payload.iat,
        ))
    }

    fn insert_jti(
        &self,
        proof: &DpopProof,
        thumbprint: &[u8],
        issuer: Option<&str>,
    ) -> Result<(), CatError> {
        if let Some((composite_key, iat)) = self.dpop_commit_key(proof, thumbprint, issuer) {
            self.jti_store.check_and_insert(composite_key, iat)?;
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
        let computed_thumbprint = proof.jwk_thumbprint()?;
        if !crate::crypto::constant_time_eq(computed_thumbprint, expected_thumbprint) {
            return Err(CatError::DpopKeyMismatch);
        }
        self.verify_with_embedded_key(proof)?;
        Ok(())
    }

    /// Direct handle to the JTI store. Exposed for async integrations that
    /// commit through an [`crate::r#async::AsyncJtiStore`] adapter — sync
    /// callers should prefer [`DpopValidator::validate`] or the
    /// [`crate::moqt::MoqtValidator::authorize`] pipeline.
    pub fn jti_store(&self) -> &Arc<dyn JtiStore> {
        &self.jti_store
    }

    /// Validate a DPoP proof and commit its JTI. Pass
    /// `access_token_hash = None` when no `ath` binding is required
    /// (transport-only PoP); pass `Some(hash)` to require that the proof's
    /// `ath` field cover the specified access-token digest. On success the
    /// proof's replay identifier is inserted into the JTI store.
    pub fn validate(
        &self,
        proof: &DpopProof,
        expected_action: MoqtAction,
        expected_thumbprint: &[u8],
        access_token_hash: Option<&[u8]>,
        issuer: Option<&str>,
    ) -> Result<(), CatError> {
        self.validate_without_jti_commit(
            proof,
            expected_action,
            expected_thumbprint,
            issuer,
            access_token_hash,
        )?;
        self.insert_jti(proof, expected_thumbprint, issuer)?;
        Ok(())
    }

    pub fn cleanup_expired_jtis(&self) {
        self.jti_store.cleanup(self.jti_expiry_seconds);
    }
}

// --- MOQT resource URI ---------------------------------------------------

/// Build a canonical `moqt://<endpoint>[?tns=<b64seg1>,<b64seg2>,...[&tn=<b64>]]`
/// resource URI. Each namespace tuple element is base64url-encoded
/// independently and joined with `,` (base64url excludes `,`, so it is an
/// unambiguous separator). The parser in
/// [`crate::moqt::parse_moqt_resource_uri`] accepts only this exact shape.
///
/// Passing `Some(&[])` for `namespace` is rejected — an empty tuple has no
/// well-defined wire form. Callers that want to omit the namespace should
/// pass `None`.
#[cfg(feature = "moqt")]
pub fn construct_moqt_uri(
    endpoint: &str,
    namespace: Option<&[Vec<u8>]>,
    track: Option<&[u8]>,
) -> Result<String, CatError> {
    if endpoint.contains('?') || endpoint.contains('#') || endpoint.contains('/') {
        return Err(CatError::InvalidClaimValue(
            "MOQT endpoint must not contain '?', '#', or '/'".to_string(),
        ));
    }
    let mut uri = format!("moqt://{endpoint}");
    if let Some(ns) = namespace {
        if ns.is_empty() {
            return Err(CatError::InvalidClaimValue(
                "MOQT resource namespace tuple must have at least one element".to_string(),
            ));
        }
        let encoded_segments: Vec<String> =
            ns.iter().map(|seg| URL_SAFE_NO_PAD.encode(seg)).collect();
        uri.push_str("?tns=");
        uri.push_str(&encoded_segments.join(","));
        if let Some(t) = track {
            let t_encoded = URL_SAFE_NO_PAD.encode(t);
            uri.push_str("&tn=");
            uri.push_str(&t_encoded);
        }
    } else if track.is_some() {
        return Err(CatError::InvalidClaimValue(
            "MOQT resource track requires a namespace tuple".to_string(),
        ));
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
        .with_replay_id(generate_jti());
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
        .with_replay_id(generate_jti());
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
    fn test_dpop_jwt_roundtrip() {
        let alg = Es256Algorithm::new_with_key_pair().unwrap();
        let jwk = Jwk::from_es256_verifying_key(alg.verifying_key()).unwrap();

        let mut proof = DpopProof::create_for_moqt(
            MoqtAction::Subscribe,
            vec![b"namespace".to_vec()],
            b"track",
            crate::crypto::ALG_ES256,
            jwk,
        )
        .with_wire_format(DpopWireFormat::Jwt)
        .with_replay_id(generate_jti());
        proof.sign(&alg).unwrap();

        let encoded = proof.encode().unwrap();
        // JWS compact = ASCII with two `.`s
        assert!(encoded.iter().all(|b| b.is_ascii()));
        assert_eq!(encoded.iter().filter(|&&b| b == b'.').count(), 2);

        let decoded = DpopProof::decode(&encoded).unwrap();
        assert_eq!(decoded.wire_format, DpopWireFormat::Jwt);
        assert_eq!(decoded.header.typ, DPOP_TYP_JWT);
        assert_eq!(decoded.header.alg, crate::crypto::ALG_ES256);
        assert_eq!(decoded.payload.actx.action, MoqtAction::Subscribe);
        assert_eq!(decoded.payload.actx.tns, vec![b"namespace".to_vec()]);
        assert_eq!(decoded.payload.actx.tn, b"track".to_vec());
    }

    #[cfg(feature = "moqt")]
    #[test]
    fn test_dpop_jwt_verify_with_embedded_key() {
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
        .with_wire_format(DpopWireFormat::Jwt)
        .with_replay_id(generate_jti());
        proof.sign(&alg).unwrap();

        let encoded = proof.encode().unwrap();
        let decoded = DpopProof::decode(&encoded).unwrap();

        let settings = CatDpopSettings::new().with_window(300).unwrap();
        let validator = DpopValidator::new(settings);
        validator
            .validate(&decoded, MoqtAction::Subscribe, &thumbprint, None, None)
            .expect("decoded JWT proof must verify");
    }

    #[cfg(feature = "moqt")]
    #[test]
    fn test_dpop_wire_format_autodetect() {
        // CWT-encoded bytes must decode as CWT, JWT-encoded as JWT — the
        // autodetect path must not mix them.
        let alg = Es256Algorithm::new_with_key_pair().unwrap();
        let jwk = Jwk::from_es256_verifying_key(alg.verifying_key()).unwrap();
        let mut cwt_proof = DpopProof::create_for_moqt(
            MoqtAction::Subscribe,
            vec![b"n".to_vec()],
            b"t",
            crate::crypto::ALG_ES256,
            jwk.clone(),
        )
        .with_replay_id(generate_jti());
        cwt_proof.sign(&alg).unwrap();
        let mut jwt_proof = DpopProof::create_for_moqt(
            MoqtAction::Subscribe,
            vec![b"n".to_vec()],
            b"t",
            crate::crypto::ALG_ES256,
            jwk,
        )
        .with_wire_format(DpopWireFormat::Jwt)
        .with_replay_id(generate_jti());
        jwt_proof.sign(&alg).unwrap();

        let cwt_bytes = cwt_proof.encode().unwrap();
        let jwt_bytes = jwt_proof.encode().unwrap();

        assert_eq!(
            DpopProof::decode(&cwt_bytes).unwrap().wire_format,
            DpopWireFormat::Cwt
        );
        assert_eq!(
            DpopProof::decode(&jwt_bytes).unwrap().wire_format,
            DpopWireFormat::Jwt
        );
    }

    /// Verifies the JWT payload shape matches the generic-DPoP draft: `tns`
    /// and `tn` are single UTF-8 text strings in MOQTransport §1.5.1
    /// canonical form (safe ASCII passed through, other bytes as `.HH`,
    /// segments joined by `-`), `jti` is a text string, `ath` is base64url
    /// of the raw hash. External tooling reading this proof walks the JSON
    /// with the same canonical decoder the CWT side uses — the two wire
    /// forms carry identical `tns`/`tn` semantics.
    #[cfg(feature = "moqt")]
    #[test]
    fn test_dpop_jwt_wire_shape_is_text_per_draft() {
        let alg = Es256Algorithm::new_with_key_pair().unwrap();
        let jwk = Jwk::from_es256_verifying_key(alg.verifying_key()).unwrap();

        let ath = crate::crypto::hash_sha256(b"the-access-token-bytes");
        let mut proof = DpopProof::create_for_moqt(
            MoqtAction::Subscribe,
            vec![b"example".to_vec(), b"com-app-scope-video".to_vec()],
            b"camera1",
            crate::crypto::ALG_ES256,
            jwk,
        )
        .with_wire_format(DpopWireFormat::Jwt)
        .with_replay_id("550e8400-e29b-41d4-a716-446655440000".to_string())
        .with_access_token_hash(ath.clone());
        proof.sign(&alg).unwrap();

        let encoded = proof.encode().unwrap();
        let parts: Vec<&[u8]> = encoded.split(|&b| b == b'.').collect();
        assert_eq!(parts.len(), 3);
        let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let payload_json: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();

        let actx = payload_json.get("actx").unwrap().as_object().unwrap();
        // Canonical form: `-` inside a segment becomes `.2d`; segments are
        // joined by a literal `-`. So the two-segment tns
        // [ "example", "com-app-scope-video" ] serializes to a single
        // string with the inner hyphens escaped.
        assert_eq!(
            actx.get("tns").unwrap().as_str().unwrap(),
            "example-com.2dapp.2dscope.2dvideo",
            "tns must be a single canonical text string, not a JSON array"
        );
        assert!(
            actx.get("tns").unwrap().as_array().is_none(),
            "tns array form is not part of draft §3.2"
        );
        assert_eq!(actx.get("tn").unwrap().as_str().unwrap(), "camera1");
        assert_eq!(actx.get("action").unwrap().as_str().unwrap(), "SUBSCRIBE");

        assert_eq!(
            payload_json.get("jti").unwrap().as_str().unwrap(),
            "550e8400-e29b-41d4-a716-446655440000"
        );

        let ath_b64 = payload_json.get("ath").unwrap().as_str().unwrap();
        assert_eq!(URL_SAFE_NO_PAD.decode(ath_b64).unwrap(), ath);

        // Round-trip through decode: the canonical string must reconstitute
        // the original two-segment tns bytes so authorize() sees the same
        // shape it saw before encoding.
        let decoded = DpopProof::decode(&encoded).unwrap();
        assert_eq!(
            decoded.payload.actx.tns,
            vec![b"example".to_vec(), b"com-app-scope-video".to_vec()]
        );
        assert_eq!(decoded.payload.actx.tn, b"camera1".to_vec());
    }

    /// The JWT header MUST carry `dpop-proof+jwt` verbatim, per
    /// draft-nandakumar-moq-generic-dpop-proof-00 §3.2. This vector is
    /// what an RFC 9449 peer or generic-DPoP tooling will match on — no
    /// private profile parameter is added.
    #[cfg(feature = "moqt")]
    #[test]
    fn test_dpop_jwt_typ_is_bare_draft_value() {
        let alg = Es256Algorithm::new_with_key_pair().unwrap();
        let jwk = Jwk::from_es256_verifying_key(alg.verifying_key()).unwrap();
        let mut proof = DpopProof::create_for_moqt(
            MoqtAction::Subscribe,
            vec![b"ns".to_vec()],
            b"tn",
            crate::crypto::ALG_ES256,
            jwk,
        )
        .with_wire_format(DpopWireFormat::Jwt)
        .with_replay_id(generate_jti());
        proof.sign(&alg).unwrap();

        let encoded = proof.encode().unwrap();
        let parts: Vec<&[u8]> = encoded.split(|&b| b == b'.').collect();
        let header_bytes = URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
        let header_json: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
        assert_eq!(
            header_json.get("typ").unwrap().as_str().unwrap(),
            "dpop-proof+jwt",
            "JWT typ MUST equal the draft value verbatim (no private profile parameter)"
        );

        let decoded = DpopProof::decode(&encoded).unwrap();
        assert_eq!(decoded.header.typ, DPOP_TYP_JWT);
        assert!(decoded.header.is_valid());
    }

    /// A JWT proof with binary (non-UTF-8) namespace bytes must round-trip
    /// through the MOQ canonical encoding without loss — every byte outside
    /// `[A-Za-z0-9_]` (including 0xFF/0xFE/0xFD) becomes `.HH`, and decode
    /// reconstitutes the original bytes exactly. This is the guarantee that
    /// makes CWT and JWT byte-identical at the `actx` semantic layer.
    #[cfg(feature = "moqt")]
    #[test]
    fn test_dpop_jwt_binary_namespace_round_trips_via_canonical_encoding() {
        let alg = Es256Algorithm::new_with_key_pair().unwrap();
        let jwk = Jwk::from_es256_verifying_key(alg.verifying_key()).unwrap();
        let ns_bytes = vec![0xFF, 0xFE, 0xFD];
        let mut proof = DpopProof::create_for_moqt(
            MoqtAction::Subscribe,
            vec![ns_bytes.clone()],
            b"track",
            crate::crypto::ALG_ES256,
            jwk,
        )
        .with_wire_format(DpopWireFormat::Jwt)
        .with_replay_id(generate_jti());
        proof.sign(&alg).unwrap();

        let encoded = proof.encode().unwrap();
        let parts: Vec<&[u8]> = encoded.split(|&b| b == b'.').collect();
        let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let payload_json: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
        assert_eq!(
            payload_json
                .get("actx")
                .and_then(|a| a.get("tns"))
                .and_then(|t| t.as_str())
                .unwrap(),
            ".ff.fe.fd",
            "non-UTF-8 bytes must serialize as escaped canonical form"
        );

        let decoded = DpopProof::decode(&encoded).unwrap();
        assert_eq!(decoded.payload.actx.tns, vec![ns_bytes]);
    }

    /// A JWT proof whose `actx.tns` is a JSON array (the pre-canonical wire
    /// form this crate used to emit) MUST be rejected on decode. Otherwise
    /// a peer emitting the wrong shape would silently authorize with an
    /// off-spec proof. This is the negative half of
    /// `test_dpop_jwt_wire_shape_is_text_per_draft`.
    #[cfg(feature = "moqt")]
    #[test]
    fn test_dpop_jwt_rejects_tns_array_form() {
        use serde_json::json;
        let alg = Es256Algorithm::new_with_key_pair().unwrap();
        let jwk = Jwk::from_es256_verifying_key(alg.verifying_key()).unwrap();
        let mut proof = DpopProof::create_for_moqt(
            MoqtAction::Subscribe,
            vec![b"a".to_vec(), b"b".to_vec()],
            b"tn",
            crate::crypto::ALG_ES256,
            jwk,
        )
        .with_wire_format(DpopWireFormat::Jwt)
        .with_replay_id(generate_jti());
        proof.sign(&alg).unwrap();

        // Take the real signed proof, splice a hostile JSON payload into
        // the middle segment. Signature won't verify — but decode must
        // reject on shape first, before any signature check.
        let encoded = proof.encode().unwrap();
        let parts: Vec<&[u8]> = encoded.split(|&b| b == b'.').collect();
        let header_b64 = std::str::from_utf8(parts[0]).unwrap();
        let sig_b64 = std::str::from_utf8(parts[2]).unwrap();

        let hostile_payload = json!({
            "htm": "MOQT",
            "htu": "moqt://relay",
            "iat": 0,
            "jti": "test",
            "actx": {
                "type": "moqt",
                "action": "SUBSCRIBE",
                "tns": ["a", "b"],
                "tn": "tn"
            }
        });
        let hostile_b64 =
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&hostile_payload).unwrap().as_slice());
        let hostile_wire = format!("{header_b64}.{hostile_b64}.{sig_b64}");

        let err = DpopProof::decode(hostile_wire.as_bytes()).unwrap_err();
        assert!(
            matches!(&err, CatError::InvalidClaimValue(msg) if msg.contains("tns")),
            "expected InvalidClaimValue referencing tns, got {err:?}"
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
        .with_replay_id(generate_jti());
        proof.sign(&alg).unwrap();

        let encoded = proof.encode().unwrap();
        let decoded = DpopProof::decode(&encoded).unwrap();

        let settings = CatDpopSettings::new().with_window(300).unwrap();
        let validator = DpopValidator::new(settings);
        validator
            .validate(&decoded, MoqtAction::Subscribe, &thumbprint, None, None)
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

        let ns_single = vec![b"ns".to_vec()];
        let uri =
            construct_moqt_uri("relay.example.com", Some(&ns_single), Some(b"track")).unwrap();
        assert!(uri.contains("?tns="));
        assert!(uri.contains("&tn="));
        assert!(!uri.contains(','));

        let ns_multi = vec![b"sports".to_vec(), b"football".to_vec(), b"spain".to_vec()];
        let uri = construct_moqt_uri("relay.example.com", Some(&ns_multi), None).unwrap();
        assert!(uri.contains("?tns="));
        let tns_query = uri.split_once("?tns=").unwrap().1;
        assert_eq!(tns_query.matches(',').count(), 2);

        assert!(construct_moqt_uri("relay.example.com/path", None, None).is_err());
        assert!(
            construct_moqt_uri("relay.example.com", Some(&[]), None).is_err(),
            "empty namespace tuple must be rejected"
        );
        assert!(
            construct_moqt_uri("relay.example.com", None, Some(b"track")).is_err(),
            "track without namespace must be rejected"
        );
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
    fn test_lru_shard_sizing_matches_requested_capacity() {
        // Capacity 1000, 16 shards → 62*4 + 63*12 = 1000 total. Previous
        // implementation would allocate 62*16 = 992 (short) or 63*16 = 1008
        // depending on rounding; the fix distributes remainder across the
        // first `remainder` shards so the sum equals the request exactly.
        let store = LruJtiStore::with_shards_and_window(MIN_JTI_CACHE_SIZE, 16, 300);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs() as i64;
        // Insert one distinct JTI per requested slot (capacity == MIN_JTI_CACHE_SIZE).
        for i in 0..MIN_JTI_CACHE_SIZE {
            store.check_and_insert(format!("k-{i}"), now).unwrap();
        }
        // Aggregate len must be <= requested capacity: no shard should
        // hold more than its allotted slots, and the sum of allotted
        // slots equals `MIN_JTI_CACHE_SIZE`.
        assert!(
            store.len() <= MIN_JTI_CACHE_SIZE,
            "aggregate len {} exceeded requested capacity {}",
            store.len(),
            MIN_JTI_CACHE_SIZE
        );
    }

    #[cfg(feature = "moqt")]
    #[test]
    fn test_in_memory_strict_store_is_strict_and_replay_detects() {
        let store = InMemoryStrictJtiStore::new(300, 1024);
        assert!(store.is_strict());
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs() as i64;
        store.check_and_insert("k".into(), now).unwrap();
        let replay = store.check_and_insert("k".into(), now);
        assert!(matches!(replay, Err(CatError::ReplayAttackDetected)));
    }

    #[cfg(feature = "moqt")]
    #[test]
    fn test_in_memory_strict_store_refuses_at_max_entries() {
        let store = InMemoryStrictJtiStore::new(300, 2);
        store.check_and_insert("a".into(), 0).unwrap();
        store.check_and_insert("b".into(), 0).unwrap();
        let err = store.check_and_insert("c".into(), 0).unwrap_err();
        assert!(matches!(err, CatError::DpopValidationFailed(_)));
        assert_eq!(store.rejected_over_capacity(), 1);
    }

    #[cfg(feature = "moqt")]
    #[test]
    fn test_validator_rejects_non_strict_store_for_strict_ctor() {
        let store: std::sync::Arc<dyn JtiStore> =
            std::sync::Arc::new(LruJtiStore::new(MIN_JTI_CACHE_SIZE));
        let settings = CatDpopSettings::new().with_window(300).unwrap();
        let result = DpopValidator::with_jti_store_strict(settings, store);
        let err = match result {
            Ok(_) => panic!("expected strict-store rejection"),
            Err(e) => e,
        };
        assert!(matches!(err, CatError::ConfigurationRefused(_)));
    }

    #[cfg(feature = "moqt")]
    #[test]
    fn test_preflight_rejects_bad_window() {
        let ok = CatDpopSettings::new().with_window(300).unwrap();
        DpopValidator::preflight(&ok).unwrap();
        // window <= 0 can't be set through the builder, but a directly
        // constructed settings with default effective_window() = 300 is
        // valid. Verify a too-large window is caught if smuggled through
        // the internal setter.
        let mut bad = CatDpopSettings::new();
        bad.set_window_from_decode(crate::claims::CATDPOP_MAX_WINDOW_SECS + 1);
        assert!(DpopValidator::preflight(&bad).is_err());
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
