// BP Core Library implementing LNP/BP specifications & standards related to
// bitcoin protocol
//
// Written in 2020-2021 by
//     Dr. Maxim Orlovsky <orlovsky@pandoracore.com>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the Apache 2.0 License
// along with this software.
// If not, see <https://opensource.org/licenses/Apache-2.0>.

// Coding conventions
#![recursion_limit = "256"]
#![deny(dead_code, /* missing_docs, */ warnings)]

#[macro_use]
extern crate amplify;
#[macro_use]
extern crate strict_encoding;
#[cfg(feature = "serde")]
#[macro_use]
extern crate serde_crate as serde;

mod error;
pub mod keyset;
pub mod lnpbp1;
pub mod lockscript;
pub mod pubkey;
pub mod spk;
pub mod taproot;
pub mod tx;
pub mod txout;
pub mod types;

pub use error::Error;
pub use keyset::{KeysetCommitment, KeysetContainer};
pub use lockscript::{LockscriptCommitment, LockscriptContainer};
pub use pubkey::{PubkeyCommitment, PubkeyContainer};
pub use spk::{
    ScriptEncodeData, ScriptEncodeMethod, SpkCommitment, SpkContainer,
};
pub use taproot::{TaprootCommitment, TaprootContainer};
pub use tx::{TxCommitment, TxContainer, TxSupplement};
pub use txout::{TxoutCommitment, TxoutContainer};
pub use types::{Container, Proof};
