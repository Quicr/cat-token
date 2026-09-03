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
pub use crate::error::CatError;
pub use crate::jwk::Jwk;
pub use crate::token::{
    CatTokenBuilder, CatTokenValidator, decode_token, decode_token_base64, encode_token,
    encode_token_base64,
};

// MOQT-specific types (only when moqt feature is enabled)
#[cfg(feature = "moqt")]
pub use crate::claims::{BinaryMatch, MoqtAction, MoqtClaims, MoqtScope, NamespaceMatch};
#[cfg(feature = "moqt")]
pub use crate::moqt::{MoqtAuthRequest, MoqtAuthResult, MoqtScopeBuilder, MoqtValidator};
