// Deterministic bitcoin commitments library, implementing LNPBP standards
// Part of bitcoin protocol core library (BP Core Lib)
//
// Written in 2020-2022 by
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

//! Taproot OP_RETURN-based deterministic bitcoin commitment scheme.
//!
//! EmbedCommit: `TapTree + Message -> TapTree* + Proof`
//! Verify: `ScriptPubkey + Proof + Message -> bool`
//! Find: `descriptor::Tr<PublicKey> + TapretTweak -> descriptor::Tapret`
//! Spend: `TapretTweak + ControlBlock -> ControlBlock*`
//!   where `Message + Proof + TapTree -> TapretTweak`
//!
//! Find & spend procedures are wallet-specific, embed-commit and verify -
//! are not.

mod partial_tree;
pub mod psbt;
mod taptree;

pub use taptree::{TapTreeContainer, TapTreeError};
