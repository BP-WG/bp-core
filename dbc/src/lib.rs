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

// Coding conventions
#![recursion_limit = "256"]
#![deny(dead_code, missing_docs, warnings)]

//! Deterministic bitcoin commitments library.
//!
//! Deterministic bitcoin commitments are part of the client-side-validation.
//! They allow to embed commitment to extra-transaction data into a bitcoin
//! transaction in a provable way, such that it can always be proven that a
//! given transaction contains one and only one commitment of a specific type
//! for a given commitment protocol.

#[macro_use]
extern crate amplify;
#[cfg(feature = "miniscript")]
extern crate miniscript_crate as miniscript;
#[cfg(feature = "serde")]
//#[macro_use]
extern crate serde_crate as serde;
#[macro_use]
extern crate strict_encoding;

pub mod keytweak;
pub mod opret;
pub mod sigtweak;
pub mod tapret;

mod _temp {
    #![allow(missing_docs, dead_code)]

    use amplify::Slice32;
    use bitcoin::schnorr::UntweakedPublicKey;
    use bitcoin::secp256k1::Parity;
    use bitcoin::util::taproot::TaprootMerkleBranch;
    use strict_encoding::{StrictDecode, StrictEncode};

    pub trait CommitmentProof: StrictEncode + StrictDecode {}

    pub enum TxoutCommitmentProof {
        OpReturn,
        TapRet(TapRetProof),
        P2cPubkey(P2cPubkeyProof),
        P2cScript(P2cScriptProof),
    }

    pub struct TapRetProof {
        /// Parity of the output taproot key
        pub output_parity: Parity,

        /// Internal taproot key
        pub internal_key: UntweakedPublicKey,

        /// Merkle path in the script key to the last leaf containing `OP_RETURN`
        /// commitment
        pub merkle_path: TaprootMerkleBranch,
    }

    pub struct P2cPubkeyProof {
        pub original_pubkey: bitcoin::PublicKey,
    }

    pub struct P2cScriptProof {
        pub original_pubkey_sum: secp256k1::PublicKey,
    }

    pub struct ProvableCommitment<Proof>
    where
        Proof: CommitmentProof,
    {
        commitment: Slice32,
        proof: Proof,
    }
}
