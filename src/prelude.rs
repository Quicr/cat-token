// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

//! Prelude module for convenient imports
//!
//! ```rust,ignore
//! use cat_token::prelude::*;
//! ```

// Core CAT types (generic, non-MOQT)
pub use crate::claims::{
    CatDpopSettings, CatToken, ConfirmationClaim, GeoCoordinate, NetworkIdentifier, UriPattern,
};
pub use crate::crypto::{
    CryptographicAlgorithm, Es256Algorithm, HmacSha256Algorithm, Ps256Algorithm,
};
#[cfg(feature = "moqt")]
pub use crate::dpop::{DpopProof, DpopValidator, JtiStore, LruJtiStore};
pub use crate::dpop::{
    compute_access_token_hash, confirmation_from_jwk, confirmation_matches_jwk, generate_jti,
};
pub use crate::encrypt::{EncryptionAlgorithm, cose_decrypt0, cose_encrypt0};
pub use crate::error::CatError;
pub use crate::geo::{GeoLocationProvider, RequestLocation, validate_geographic_enforcement};
pub use crate::jwk::Jwk;
pub use crate::key_resolver::{KeyHint, KeyResolver, KeyRingResolver, SingleKeyResolver};
pub use crate::pipeline::{
    AdmissionPolicy, TokenHeader, TokenProvenance, ValidatedToken, VerifiedToken,
};
pub use crate::response::{CacheScope, CatResponsePolicy, sanitize_uri_for_cache};
pub use crate::structured_header::{
    get_sf_dictionary_member, normalize_sf_value, parse_sf_dictionary, parse_sf_item, parse_sf_list,
};
pub use crate::token::{
    CatPorBlockList, CatTokenBuilder, CatTokenValidator, Decoder, ReplayGuard,
    decode_encrypted_token, decode_token, encode_token, encode_token_base64,
};
pub use crate::x509::{
    PathValidator, VerifiedPeerCertificate, authenticate_and_pin, check_cattpk_pin,
    extract_spki_from_cert,
};

// MOQT-specific types (only when moqt feature is enabled)
#[cfg(feature = "moqt")]
pub use crate::claims::{BinaryMatch, MoqtAction, MoqtClaims, MoqtScope, NamespaceMatch};
#[cfg(feature = "moqt")]
pub use crate::moqt::{
    AuthorizedRequest, HttpRequest, MoqtScopeBuilder, MoqtValidator, RelayRequestContext,
    TransportInfo,
};
