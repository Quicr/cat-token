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
pub use crate::dpop::{DpopProof, DpopValidator};
pub use crate::dpop::{
    compute_access_token_hash, confirmation_from_jwk, confirmation_matches_jwk, generate_jti,
};
pub use crate::encrypt::{EncryptionAlgorithm, cose_decrypt0, cose_encrypt0};
pub use crate::error::CatError;
pub use crate::structured_header::{
    get_sf_dictionary_member, normalize_sf_value, parse_sf_dictionary, parse_sf_item,
    parse_sf_list,
};
pub use crate::x509::{extract_spki_from_cert, validate_cattpk, validate_cattpk_chain};
pub use crate::jwk::Jwk;
pub use crate::token::{
    CatPorBlockList, CatTokenBuilder, CatTokenValidator, apply_match_value, decode_token,
    decode_token_base64, encode_token, encode_token_base64, enforce_catpor, strip_token_from_uri,
    unfold_header_value, validate_header, validate_method,
};

// MOQT-specific types (only when moqt feature is enabled)
#[cfg(feature = "moqt")]
pub use crate::claims::{BinaryMatch, MoqtAction, MoqtClaims, MoqtScope, NamespaceMatch};
#[cfg(feature = "moqt")]
pub use crate::moqt::{MoqtAuthRequest, MoqtAuthResult, MoqtScopeBuilder, MoqtValidator};
