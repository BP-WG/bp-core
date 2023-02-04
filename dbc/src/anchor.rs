// Deterministic bitcoin commitments library.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2023 by
//     Dr. Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2023 LNP/BP Standards Association. All rights reserved.
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

//! Anchors are data structures used in deterministic bitcoin commitments for
//! keeping information about the proof of the commitment in connection to the
//! transaction which contains the commitment, and multi-protocol merkle tree as
//! defined by LNPBP-4.

use std::cmp::Ordering;

use amplify::{Bytes32, Wrapper};
use bc::{ScriptPubkey, Tx, Txid, LIB_NAME_BP};
use commit_verify::mpc::{self, Message, ProtocolId};
use commit_verify::{strategies, CommitStrategy, CommitmentId, ConvolveCommitProof};
use strict_encoding::{StrictDumb, StrictEncode};

use crate::tapret::{TapretError, TapretProof};

/// Default depth of LNPBP-4 commitment tree
pub const ANCHOR_MIN_LNPBP4_DEPTH: u8 = 3;

/// Anchor identifier - a commitment to the anchor data.
#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From, Default)]
#[wrapper(Deref, BorrowSlice, Display, FromStr, Hex, Index, RangeOps)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BP)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct AnchorId(
    #[from]
    #[from([u8; 32])]
    Bytes32,
);

impl CommitStrategy for AnchorId {
    type Strategy = strategies::Strict;
}

/// Errors verifying anchors.
#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(inner)]
pub enum VerifyError {
    /// Tapret commitment verification failure.
    #[from]
    Tapret(TapretError),

    /// LNPBP-4 invalid proof.
    #[from(mpc::UnrelatedProof)]
    Lnpbp4UnrelatedProtocol,
}

/// Anchor is a data structure used in deterministic bitcoin commitments for
/// keeping information about the proof of the commitment in connection to the
/// transaction which contains the commitment, and multi-protocol merkle tree as
/// defined by LNPBP-4.
#[derive(Clone, PartialEq, Eq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BP)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct Anchor<L: mpc::Proof + StrictDumb> {
    /// Transaction containing deterministic bitcoin commitment.
    pub txid: Txid,

    /// Structured multi-protocol LNPBP-4 data the transaction commits to.
    pub mpc_proof: L,

    /// Proof of the DBC commitment.
    pub dbc_proof: Proof,
}

impl CommitStrategy for Anchor<mpc::MerkleBlock> {
    type Strategy = strategies::Strict;
}

impl CommitmentId for Anchor<mpc::MerkleBlock> {
    const TAG: [u8; 32] = *b"urn:lnpbp:lnpbp0011:anchor:v01#A";
    type Id = AnchorId;
}

impl Ord for Anchor<mpc::MerkleBlock> {
    fn cmp(&self, other: &Self) -> Ordering { self.anchor_id().cmp(&other.anchor_id()) }
}

impl PartialOrd for Anchor<mpc::MerkleBlock> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}

/// Error merging two [`Anchor`]s.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum MergeError {
    /// Error merging two LNPBP-4 proofs, which are unrelated.
    #[display(inner)]
    #[from(mpc::UnrelatedProof)]
    Lnpbp4Mismatch,

    /// anchors can't be merged since they have different witness transactions
    TxidMismatch,

    /// anchors can't be merged since they have different proofs
    ProofMismatch,
}

impl Anchor<mpc::MerkleBlock> {
    /// Returns id of the anchor (commitment hash).
    #[inline]
    pub fn anchor_id(&self) -> AnchorId { self.commitment_id() }
}

impl Anchor<mpc::MerkleProof> {
    /// Returns id of the anchor (commitment hash).
    #[inline]
    pub fn anchor_id(
        &self,
        protocol_id: impl Into<ProtocolId>,
        message: Message,
    ) -> Result<AnchorId, mpc::UnrelatedProof> {
        Ok(self.to_merkle_block(protocol_id, message)?.anchor_id())
    }

    /// Reconstructs anchor containing merkle block
    pub fn into_merkle_block(
        self,
        protocol_id: impl Into<ProtocolId>,
        message: Message,
    ) -> Result<Anchor<mpc::MerkleBlock>, mpc::UnrelatedProof> {
        let lnpbp4_proof = mpc::MerkleBlock::with(&self.mpc_proof, protocol_id.into(), message)?;
        Ok(Anchor {
            txid: self.txid,
            mpc_proof: lnpbp4_proof,
            dbc_proof: self.dbc_proof,
        })
    }

    /// Reconstructs anchor containing merkle block
    pub fn to_merkle_block(
        &self,
        protocol_id: impl Into<ProtocolId>,
        message: Message,
    ) -> Result<Anchor<mpc::MerkleBlock>, mpc::UnrelatedProof> {
        self.clone().into_merkle_block(protocol_id, message)
    }

    /// Verifies that the transaction commits to the anchor and the anchor
    /// commits to the given message under the given protocol.
    pub fn verify(
        &self,
        protocol_id: impl Into<ProtocolId>,
        message: Message,
        tx: Tx,
    ) -> Result<bool, VerifyError> {
        self.dbc_proof
            .verify(&self.mpc_proof.convolve(protocol_id.into(), message)?, tx)
            .map_err(VerifyError::from)
    }

    /// Verifies that the anchor commits to the given message under the given
    /// protocol.
    pub fn convolve(
        &self,
        protocol_id: impl Into<ProtocolId>,
        message: Message,
    ) -> Result<mpc::Commitment, mpc::UnrelatedProof> {
        self.mpc_proof.convolve(protocol_id.into(), message)
    }
}

impl Anchor<mpc::MerkleBlock> {
    /// Conceals all LNPBP-4 data except specific protocol and produces merkle
    /// proof anchor.
    pub fn to_merkle_proof(
        &self,
        protocol: impl Into<ProtocolId>,
    ) -> Result<Anchor<mpc::MerkleProof>, mpc::LeafNotKnown> {
        self.clone().into_merkle_proof(protocol)
    }

    /// Conceals all LNPBP-4 data except specific protocol and converts anchor
    /// into merkle proof anchor.
    pub fn into_merkle_proof(
        self,
        protocol: impl Into<ProtocolId>,
    ) -> Result<Anchor<mpc::MerkleProof>, mpc::LeafNotKnown> {
        let lnpbp4_proof = self.mpc_proof.to_merkle_proof(protocol.into())?;
        Ok(Anchor {
            txid: self.txid,
            mpc_proof: lnpbp4_proof,
            dbc_proof: self.dbc_proof,
        })
    }

    /// Conceals all LNPBP-4 data except specific protocol.
    pub fn conceal_except(
        &mut self,
        protocols: impl AsRef<[ProtocolId]>,
    ) -> Result<usize, mpc::LeafNotKnown> {
        self.mpc_proof.conceal_except(protocols)
    }

    /// Merges two anchors keeping revealed data.
    pub fn merge_reveal(mut self, other: Self) -> Result<Self, MergeError> {
        if self.txid != other.txid {
            return Err(MergeError::TxidMismatch);
        }
        if self.dbc_proof != other.dbc_proof {
            return Err(MergeError::ProofMismatch);
        }
        self.mpc_proof.merge_reveal(other.mpc_proof)?;
        Ok(self)
    }
}

/// Type and type-specific proof information of a deterministic bitcoin
/// commitment.
#[derive(Clone, PartialEq, Eq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BP, tags = order)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
#[non_exhaustive]
pub enum Proof {
    /// Opret commitment (no extra-transaction proof is required).
    #[strict_type(dumb)]
    OpretFirst,

    /// Tapret commitment and a proof of it.
    TapretFirst(TapretProof),
}

impl Proof {
    /// Verifies validity of the proof.
    pub fn verify(&self, msg: &mpc::Commitment, tx: Tx) -> Result<bool, TapretError> {
        match self {
            Proof::OpretFirst => {
                for txout in &tx.outputs {
                    if txout.script_pubkey.is_op_return() {
                        return Ok(txout.script_pubkey == ScriptPubkey::op_return(msg.as_slice()));
                    }
                }
                Ok(false)
            }
            Proof::TapretFirst(proof) => ConvolveCommitProof::<_, Tx, _>::verify(proof, msg, tx),
        }
    }
}
