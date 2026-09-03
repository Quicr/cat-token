// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

pub mod claims;
pub mod crypto;
pub mod cwt;
pub mod dpop;
pub mod encrypt;
pub mod error;
pub mod jwk;
#[cfg(feature = "moqt")]
pub mod moqt;
pub mod prelude;
pub mod token;
pub mod uri;

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
pub use jwk::*;
#[cfg(feature = "moqt")]
pub use moqt::*;
pub use token::*;
pub use uri::*;
