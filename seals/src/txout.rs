// Bitcoin protocol single-use-seals library.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2024 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Bitcoin single-use-seals defined by a transaction output and closed by
//! spending that output ("TxOut seals").

use core::cmp::Ordering;
use core::error::Error;
use core::fmt::Debug;
use core::marker::PhantomData;

use amplify::{ByteArray, Bytes, Bytes32};
use bc::{Outpoint, Tx, Txid, Vout};
use commit_verify::{CommitId, DigestExt, ReservedBytes, Sha256, StrictHash};
use single_use_seals::{ClientSideWitness, PublishedWitness, SealWitness, SingleUseSeal};
use strict_encoding::StrictDumb;

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = dbc::LIB_NAME_BPCORE)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(transparent))]
pub struct Noise(Bytes<40>);

pub mod mmb {
    use amplify::confinement::SmallOrdMap;
    use commit_verify::{CommitmentId, DigestExt, Sha256};

    use super::*;

    #[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From, Default)]
    #[wrapper(Deref, BorrowSlice, Display, FromStr, Hex, Index, RangeOps)]
    #[derive(StrictType, StrictEncode, StrictDecode)]
    #[strict_type(lib = dbc::LIB_NAME_BPCORE)]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(transparent))]
    pub struct Message(
        #[from]
        #[from([u8; 32])]
        Bytes32,
    );

    #[derive(Wrapper, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, From)]
    #[wrapper(Deref, BorrowSlice, Hex, Index, RangeOps)]
    #[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
    #[strict_type(lib = dbc::LIB_NAME_BPCORE)]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(transparent))]
    pub struct Commitment(
        #[from]
        #[from([u8; 32])]
        Bytes32,
    );
    impl CommitmentId for Commitment {
        const TAG: &'static str = "urn:lnp-bp:mmb:bundle#2024-11-18";
    }
    impl From<Sha256> for Commitment {
        fn from(hasher: Sha256) -> Self { hasher.finish().into() }
    }

    impl From<Commitment> for mpc::Message {
        fn from(msg: Commitment) -> Self { mpc::Message::from_byte_array(msg.to_byte_array()) }
    }

    #[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
    #[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
    #[strict_type(lib = dbc::LIB_NAME_BPCORE)]
    #[derive(CommitEncode)]
    #[commit_encode(strategy = strict, id = Commitment)]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    pub struct BundleProof {
        pub map: SmallOrdMap<u32, Message>,
    }

    impl BundleProof {
        pub fn verify(&self, seal: Outpoint, msg: Message, tx: &Tx) -> bool {
            let Some(input_index) = tx.inputs().position(|input| input.prev_output == seal) else {
                return false;
            };
            let Ok(input_index) = u32::try_from(input_index) else {
                return false;
            };
            let Some(expected) = self.map.get(&input_index) else {
                return false;
            };
            *expected == msg
        }
    }
}

/// Module extends [`commit_verify::mpc`] module with multi-message bundle commitments.
pub mod mpc {
    use amplify::confinement::MediumOrdMap;
    use amplify::num::u5;
    use amplify::ByteArray;
    pub use commit_verify::mpc::{
        Commitment, Error, InvalidProof, Leaf, LeafNotKnown, MergeError, MerkleBlock,
        MerkleConcealed, MerkleProof, MerkleTree, Message, Method, Proof, ProtocolId,
        MPC_MINIMAL_DEPTH,
    };
    use commit_verify::{CommitId, TryCommitVerify};

    use crate::mmb;

    #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, From)]
    #[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
    #[strict_type(lib = dbc::LIB_NAME_BPCORE, tags = custom, dumb = Self::Single(strict_dumb!()))]
    #[cfg_attr(
        feature = "serde",
        derive(Serialize, Deserialize),
        serde(rename_all = "camelCase", untagged)
    )]
    pub enum MessageSource {
        #[from]
        #[strict_type(tag = 1)]
        Single(Message),
        #[from]
        #[strict_type(tag = 2)]
        Mmb(mmb::BundleProof),
    }

    impl MessageSource {
        pub fn mpc_message(&self) -> Message {
            match self {
                MessageSource::Single(message) => *message,
                MessageSource::Mmb(proof) => {
                    Message::from_byte_array(proof.commit_id().to_byte_array())
                }
            }
        }
    }

    #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
    #[derive(StrictType, StrictEncode, StrictDecode)]
    #[strict_type(lib = dbc::LIB_NAME_BPCORE)]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(transparent))]
    pub struct MessageMap(MediumOrdMap<ProtocolId, MessageSource>);

    #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
    #[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
    #[strict_type(lib = dbc::LIB_NAME_BPCORE)]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all = "camelCase"))]
    pub struct Source {
        pub min_depth: u5,
        pub entropy: u64,
        pub messages: MessageMap,
    }

    impl Source {
        pub fn into_merkle_tree(self) -> Result<MerkleTree, Error> {
            let messages = self.messages.0.iter().map(|(id, src)| {
                let msg = src.mpc_message();
                (*id, msg)
            });
            let source = commit_verify::mpc::MultiSource {
                method: Method::Sha256t,
                min_depth: self.min_depth,
                messages: MediumOrdMap::from_iter_checked(messages),
                static_entropy: Some(self.entropy),
            };
            MerkleTree::try_commit(&source)
        }
    }
}

/// Anchor is a client-side witness for the bitcoin txout seals.
///
/// Anchor is a set of data required for the client-side validation of a bitcoin txout single-use
/// seal, which can't be recovered from the transaction and other public information itself.
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = dbc::LIB_NAME_BPCORE)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all = "camelCase"))]
pub struct Anchor<D: dbc::Proof> {
    pub mmb_proof: mmb::BundleProof,
    pub mpc_protocol: mpc::ProtocolId,
    pub mpc_proof: mpc::MerkleProof,
    pub dbc_proof: D,
    #[cfg_attr(feature = "serde", serde(skip))]
    // TODO: This should become an option once fallback proofs are ready
    pub fallback_proof: ReservedBytes<1>,
}

impl<D: dbc::Proof> Anchor<D> {
    // TODO: Change when the fallback proofs are ready
    pub fn is_fallback(&self) -> bool { false }
    // TODO: Change when the fallback proofs are ready
    pub fn verify_fallback(&self) -> Result<(), AnchorError> { Ok(()) }
}

/// Proof data for verification of deterministic bitcoin commitment produced from anchor.
pub struct Proof<D: dbc::Proof> {
    pub mpc_commit: mpc::Commitment,
    pub dbc_proof: D,
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = dbc::LIB_NAME_BPCORE, tags = custom)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(untagged))]
pub enum TxoSealExt {
    #[display("~")]
    #[strict_type(tag = 0)]
    Noise(Noise),

    #[display(inner)]
    #[strict_type(tag = 1)]
    Fallback(Outpoint),
}

impl StrictDumb for TxoSealExt {
    fn strict_dumb() -> Self { TxoSealExt::Noise(Noise::from(Bytes::from_byte_array([0u8; 40]))) }
}

/// Seal definition which is not specific to a used single-use seal protocol.
///
/// Seals of this type can't be used in seal validation or in closing seals, and are used for
/// informational purposes only. For all other uses please check [`TxoSeal`].
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Display)]
#[display("{primary}/{secondary}")]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = dbc::LIB_NAME_BPCORE)]
#[derive(CommitEncode)]
#[commit_encode(strategy = strict, id = StrictHash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TxoSealDef {
    pub primary: Outpoint,
    pub secondary: TxoSealExt,
}

impl<D: dbc::Proof> From<TxoSeal<D>> for TxoSealDef {
    fn from(seal: TxoSeal<D>) -> Self {
        TxoSealDef {
            primary: seal.primary,
            secondary: seal.secondary,
        }
    }
}

impl TxoSealDef {
    /// Creates a new witness output-based seal definition without fallback.
    ///
    /// # Arguments
    ///
    /// `nonce` is a deterministic incremental number, preventing from creating the same seal if the
    /// same output is used.
    pub fn vout_no_fallback(vout: Vout, noise_engine: Sha256, nonce: u64) -> Self {
        Self::no_fallback(Outpoint::new(Txid::from([0xFFu8; 32]), vout), noise_engine, nonce)
    }

    /// Creates a new witness output-based seal definition without fallback.
    ///
    /// # Arguments
    ///
    /// `nonce` is a deterministic incremental number, preventing from creating the same seal if the
    /// same output is used.
    pub fn no_fallback(outpoint: Outpoint, mut noise_engine: Sha256, nonce: u64) -> Self {
        noise_engine.input_raw(&nonce.to_be_bytes());
        noise_engine.input_raw(outpoint.txid.as_ref());
        noise_engine.input_raw(&outpoint.vout.to_u32().to_be_bytes());
        let mut noise = [0xFFu8; 40];
        noise[..32].copy_from_slice(&noise_engine.finish());
        Self {
            primary: outpoint,
            secondary: TxoSealExt::Noise(Noise(noise.into())),
        }
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, Display)]
#[display("{primary}/{secondary}")]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = dbc::LIB_NAME_BPCORE)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TxoSeal<D: dbc::Proof> {
    pub primary: Outpoint,
    pub secondary: TxoSealExt,
    #[strict_type(skip)]
    #[cfg_attr(feature = "serde", serde(skip))]
    _phantom: PhantomData<D>,
}

// Manual impl is needed since we need to avoid D: Copy bound
impl<D: dbc::Proof> Copy for TxoSeal<D> {}
impl<D: dbc::Proof> PartialOrd for TxoSeal<D> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}
impl<D: dbc::Proof> Ord for TxoSeal<D> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.primary.cmp(&other.primary).then(self.secondary.cmp(&other.secondary))
    }
}

impl<D: dbc::Proof> TxoSeal<D> {
    /// Creates a new witness output-based seal definition without fallback.
    ///
    /// # Arguments
    ///
    /// `nonce` is a deterministic incremental number, preventing from creating the same seal if the
    /// same output is used.
    pub fn vout_no_fallback(vout: Vout, noise_engine: Sha256, nonce: u64) -> Self {
        Self::from_definition(TxoSealDef::vout_no_fallback(vout, noise_engine, nonce))
    }

    /// Creates a new witness output-based seal definition without fallback.
    ///
    /// # Arguments
    ///
    /// `nonce` is a deterministic incremental number, preventing from creating the same seal if the
    /// same output is used.
    pub fn no_fallback(outpoint: Outpoint, noise_engine: Sha256, nonce: u64) -> Self {
        Self::from_definition(TxoSealDef::no_fallback(outpoint, noise_engine, nonce))
    }

    pub fn from_definition(seal: TxoSealDef) -> Self {
        Self {
            primary: seal.primary,
            secondary: seal.secondary,
            _phantom: PhantomData,
        }
    }

    pub fn to_definition(&self) -> TxoSealDef { TxoSealDef::from(*self) }
}

impl<D: dbc::Proof> SingleUseSeal for TxoSeal<D> {
    type Message = mmb::Message;
    type PubWitness = Tx;
    type CliWitness = Anchor<D>;

    fn is_included(&self, message: Self::Message, witness: &SealWitness<Self>) -> bool {
        match self.secondary {
            TxoSealExt::Noise(_) | TxoSealExt::Fallback(_) if !witness.client.is_fallback() => {
                witness.client.mmb_proof.verify(self.primary, message, &witness.published)
            }
            TxoSealExt::Fallback(fallback) => {
                witness.client.mmb_proof.verify(fallback, message, &witness.published)
            }
            // If we are provided a fallback proof but no fallback seal were defined
            TxoSealExt::Noise(_) => false,
        }
    }
}

// TODO: It's not just a transaction, it should be an SPV proof
impl<D: dbc::Proof> PublishedWitness<TxoSeal<D>> for Tx {
    type PubId = Txid;
    type Error = D::Error;

    fn pub_id(&self) -> Txid { self.txid() }
    fn verify_commitment(&self, proof: Proof<D>) -> Result<(), Self::Error> {
        proof.dbc_proof.verify(&proof.mpc_commit, self)
    }
}

impl<D: dbc::Proof> ClientSideWitness for Anchor<D> {
    type Proof = Proof<D>;
    type Seal = TxoSeal<D>;
    type Error = AnchorError;

    fn convolve_commit(&self, mmb_message: mmb::Message) -> Result<Proof<D>, Self::Error> {
        self.verify_fallback()?;
        if self.mmb_proof.map.values().all(|msg| *msg != mmb_message) {
            return Err(AnchorError::Mmb(mmb_message));
        }
        let bundle_id = self.mmb_proof.commit_id();
        let mpc_message = mpc::Message::from_byte_array(bundle_id.to_byte_array());
        let mpc_commit = self.mpc_proof.convolve(self.mpc_protocol, mpc_message)?;
        Ok(Proof {
            mpc_commit,
            dbc_proof: self.dbc_proof.clone(),
        })
    }

    fn merge(&mut self, other: Self) -> Result<(), impl Error>
    where Self: Sized {
        if self.mpc_protocol != other.mpc_protocol
            || self.mpc_proof != other.mpc_proof
            || self.dbc_proof != other.dbc_proof
            || self.fallback_proof != other.fallback_proof
        {
            return Err(AnchorMergeError::AnchorMismatch);
        }
        self.mmb_proof
            .map
            .extend(other.mmb_proof.map)
            .map_err(|_| AnchorMergeError::TooManyInputs)?;
        Ok(())
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Error, Debug, Display, From)]
#[display(doc_comments)]
pub enum AnchorMergeError {
    /// anchor mismatch in merge procedure
    AnchorMismatch,

    /// anchor is invalid: too many inputs
    TooManyInputs,
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Error, Debug, Display, From)]
#[display(inner)]
pub enum AnchorError {
    #[from]
    Mpc(mpc::InvalidProof),
    #[display("message {0} is not part of the anchor")]
    Mmb(mmb::Message),
}
