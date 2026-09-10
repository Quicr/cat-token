// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

//! # cat-token
//!
//! CAT-4-MOQT strict fail-closed profile of CTA-5007-B.
//!
//! Integrators should reach for [`prelude`] first — it exposes the small
//! set of types needed to write a relay validator (or a token issuer).
//! Advanced types (COSE header constants, wire-format helpers, internal
//! plumbing) live in their module and must be imported by full path, e.g.
//! `cat_token::dpop::AuthorizationContext`. This keeps `cat_token::<Tab>`
//! autocomplete focused on the API a first-time reader actually uses.
//!
//! ## Feature profiles
//!
//! The default profile enables `builtin-trie` and `moqt` — the full
//! CAT-4-MOQT relay validator. Turning default features off gives a
//! generic CWT / CTA-5007-B CAT library: the CBOR + COSE + signature/
//! MAC + claim-evaluation core is intact, but MoQT-scope matching
//! ([`crate::MoqtValidator`], MOQT claim helpers, DPoP validator entry
//! points), the URI trie, and the async surface are gone. Use the
//! feature-less build when integrating cat-token into a non-MoQT
//! authorization system; use `--features moqt` (or the default) when
//! terminating CAT-4-MOQT at a relay.

#[cfg(feature = "async")]
pub mod r#async;
pub mod claims;
pub mod crypto;
pub mod cwt;
pub mod dpop;
pub mod encrypt;
pub mod error;
pub mod geo;
#[cfg(feature = "moqt")]
pub mod jti_contract;
pub mod jwk;
pub mod key_resolver;
#[cfg(feature = "moqt")]
pub mod moqt;
pub mod pipeline;
pub mod prelude;
pub mod response;
pub mod structured_header;
pub mod token;
pub mod uri;
pub mod x509;

// Conditional trie module selection based on features
// qp-trie takes precedence if both are enabled
#[cfg(feature = "qp-trie")]
mod trie_qp;

#[cfg(all(feature = "builtin-trie", not(feature = "qp-trie")))]
mod trie;

// Curated crate-root re-exports. The `prelude` module surfaces a tighter
// subset for `use cat_token::prelude::*`; the crate-root set is broader
// to accommodate legacy `use cat_token::*` callers (tests, examples,
// downstream integrators) that reach for CBOR label constants, wire-
// format types, and encoded claim structs. Explicit lists — not
// `pub use module::*` — keep this surface auditable.
#[cfg(feature = "moqt")]
pub use crate::claims::{
    BinaryMatch, MoqtAction, MoqtClaims, MoqtResourceShape, MoqtScope, NamespaceMatch,
};
pub use crate::claims::{
    CATDPOP_MAX_WINDOW_SECS, CLAIM_AND, CLAIM_AUD, CLAIM_CATALPN, CLAIM_CATDPOP, CLAIM_CATGEOALT,
    CLAIM_CATGEOCOORD, CLAIM_CATGEOISO3166, CLAIM_CATH, CLAIM_CATIF, CLAIM_CATIFDATA, CLAIM_CATM,
    CLAIM_CATNIP, CLAIM_CATPOR, CLAIM_CATR, CLAIM_CATREPLAY, CLAIM_CATTPK, CLAIM_CATU, CLAIM_CATV,
    CLAIM_CNF, CLAIM_CTI, CLAIM_EXP, CLAIM_GEOHASH, CLAIM_IAT, CLAIM_ISS, CLAIM_MOQT,
    CLAIM_MOQT_REVAL, CLAIM_NBF, CLAIM_NOR, CLAIM_OR, CLAIM_SUB, CNF_JKT, CatClaims,
    CatDpopSettings, CatIfAction, CatRenewal, CatRenewalType, CatToken, ConfirmationClaim,
    CoreClaims, GeoAltitude, GeoCoordinate, HeaderMatchRule, MATCH_CONTAINS, MATCH_EXACT,
    MATCH_PREFIX, MATCH_REGEX, MATCH_SHA256, MATCH_SHA512_256, MATCH_SUFFIX, MatchValue,
    NetworkIdentifier, ProbabilityOfRejection, ReplayProtection, URI_COMPONENT_EXTENSION,
    URI_COMPONENT_FILENAME, URI_COMPONENT_HOST, URI_COMPONENT_PARENT_PATH, URI_COMPONENT_PATH,
    URI_COMPONENT_PORT, URI_COMPONENT_QUERY, URI_COMPONENT_SCHEME, URI_COMPONENT_STEM,
    UriMatchRule, UriPattern, validate_iso3166_code, validate_posix_ere,
};
pub use crate::crypto::{
    ALG_ES256, ALG_HMAC256_256, ALG_PS256, CryptographicAlgorithm, Es256Algorithm,
    Es256VerifyingKey, HmacSha256Algorithm, Ps256Algorithm,
};
pub use crate::cwt::{Cwt, CwtLimits};
#[cfg(feature = "moqt")]
pub use crate::dpop::{DpopProof, DpopValidator, InMemoryStrictJtiStore, JtiStore, LruJtiStore};
pub use crate::dpop::{
    DpopWireFormat, compute_access_token_hash, compute_access_token_hash_b64,
    confirmation_from_jwk, confirmation_matches_jwk, generate_jti,
};
pub use crate::encrypt::{EncryptionAlgorithm, cose_decrypt0, cose_encrypt0};
pub use crate::error::CatError;
pub use crate::geo::{GeoLocationProvider, RequestLocation};
pub use crate::jwk::Jwk;
pub use crate::key_resolver::{KeyHint, KeyResolver, KeyRingResolver, SingleKeyResolver};
#[cfg(feature = "moqt")]
pub use crate::moqt::{
    AuthorizedRequest, MoqtScopeBuilder, MoqtValidator, RelayRequestContext, roles,
};
pub use crate::pipeline::{
    AdmissionPolicy, TokenHeader, TokenProvenance, ValidatedToken, VerifiedToken,
};
pub use crate::response::{CacheScope, CatResponsePolicy, sanitize_uri_for_cache};
pub use crate::structured_header::{
    get_sf_dictionary_member, normalize_sf_value, parse_sf_dictionary, parse_sf_item, parse_sf_list,
};
pub use crate::token::{
    CatPorBlockList, CatTokenBuilder, CatTokenValidator, Decoder, MAX_CLOCK_SKEW_TOLERANCE_SECS,
    ReplayGuard, encode_token, encode_token_base64,
};
pub use crate::x509::{
    PathValidator, VerifiedPeerCertificate, authenticate_and_pin, check_cattpk_pin,
    extract_spki_from_cert,
};

#[cfg(feature = "qp-trie")]
pub use crate::trie_qp::{PrefixTrie, SuffixTrie, UriMatcher, UriMatcherLimits};

#[cfg(all(feature = "builtin-trie", not(feature = "qp-trie")))]
pub use crate::trie::{PrefixTrie, SuffixTrie, UriMatcher, UriMatcherLimits};

#[cfg(feature = "async")]
pub use r#async::{
    AsyncInMemoryStrictJtiStore, AsyncJtiStore, AsyncJtiStoreAdapter, AsyncMoqtValidator,
    AsyncReplayGuard,
};
