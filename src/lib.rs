// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

pub mod claims;
pub mod crypto;
pub mod cwt;
pub mod dpop;
pub mod encrypt;
pub mod error;
pub mod geo;
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
#[cfg(feature = "qp-trie")]
pub use trie_qp::*;

#[cfg(all(feature = "builtin-trie", not(feature = "qp-trie")))]
mod trie;
#[cfg(all(feature = "builtin-trie", not(feature = "qp-trie")))]
pub use trie::*;

pub use claims::*;
pub use crypto::*;
pub use cwt::*;
pub use dpop::*;
pub use encrypt::*;
pub use error::*;
pub use geo::*;
pub use jwk::*;
pub use key_resolver::*;
#[cfg(feature = "moqt")]
pub use moqt::*;
pub use pipeline::*;
pub use response::*;
pub use structured_header::*;
pub use token::*;
pub use uri::*;
pub use x509::*;
