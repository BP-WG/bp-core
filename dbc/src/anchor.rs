// Deterministic bitcoin commitments library.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2023 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
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

use std::error::Error;

use bc::{Tx, Txid};
use commit_verify::mpc::{self, Message, ProtocolId};
use strict_encoding::{StrictDumb, StrictEncode};

use crate::LIB_NAME_BPCORE;

mod dbc {
    pub use crate::Proof;
}

/// Errors verifying anchors.
#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(inner)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub enum VerifyError<E: Error> {
    /// Deterministic commitment error.
    #[display(inner)]
    Dbc(E),

    /// invalid MPC proof. Details: {0}
    #[from]
    Mpc(mpc::InvalidProof),
}

/// Anchor is a data structure used in deterministic bitcoin commitments for
/// keeping information about the proof of the commitment in connection to the
/// transaction which contains the commitment, and multi-protocol merkle tree as
/// defined by LNPBP-4.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BPCORE)]
#[derive(CommitEncode)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct Anchor<L: mpc::Proof + StrictDumb, D: dbc::Proof> {
    /// Transaction containing deterministic bitcoin commitment.
    pub txid: Txid,

    /// Structured multi-protocol LNPBP-4 data the transaction commits to.
    pub mpc_proof: L,

    /// Proof of the DBC commitment.
    pub dbc_proof: D,
}

/// Error merging two [`Anchor`]s.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum MergeError {
    /// Error merging two MPC proofs, which are unrelated.
    #[display(inner)]
    #[from]
    MpcMismatch(mpc::MergeError),

    /// anchors can't be merged since they have different witness transactions
    TxidMismatch,

    /// anchors can't be merged since they have different DBC proofs
    DbcMismatch,
}

impl<D: dbc::Proof> Anchor<mpc::MerkleProof, D> {
    /// Reconstructs anchor containing merkle block
    pub fn into_merkle_block(
        self,
        protocol_id: impl Into<ProtocolId>,
        message: impl Into<Message>,
    ) -> Result<Anchor<mpc::MerkleBlock, D>, mpc::InvalidProof> {
        let lnpbp4_proof =
            mpc::MerkleBlock::with(&self.mpc_proof, protocol_id.into(), message.into())?;
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
        message: impl Into<Message>,
    ) -> Result<Anchor<mpc::MerkleBlock, D>, mpc::InvalidProof> {
        self.clone().into_merkle_block(protocol_id, message)
    }

    /// Verifies that the transaction commits to the anchor and the anchor
    /// commits to the given message under the given protocol.
    pub fn verify(
        &self,
        protocol_id: impl Into<ProtocolId>,
        message: impl Into<Message>,
        tx: &Tx,
    ) -> Result<mpc::Commitment, VerifyError<D::Error>> {
        let mpc_commitment = self.convolve(protocol_id, message)?;
        self.dbc_proof
            .verify(&mpc_commitment, tx)
            .map_err(VerifyError::Dbc)?;
        Ok(mpc_commitment)
    }

    /// Verifies that the anchor commits to the given message under the given
    /// protocol.
    pub fn convolve(
        &self,
        protocol_id: impl Into<ProtocolId>,
        message: impl Into<Message>,
    ) -> Result<mpc::Commitment, mpc::InvalidProof> {
        self.mpc_proof.convolve(protocol_id.into(), message.into())
    }
}

impl<D: dbc::Proof> Anchor<mpc::MerkleBlock, D> {
    /// Conceals all LNPBP-4 data except specific protocol and produces merkle
    /// proof anchor.
    pub fn to_merkle_proof(
        &self,
        protocol: impl Into<ProtocolId>,
    ) -> Result<Anchor<mpc::MerkleProof, D>, mpc::LeafNotKnown> {
        self.clone().into_merkle_proof(protocol)
    }

    /// Conceals all LNPBP-4 data except specific protocol and converts anchor
    /// into merkle proof anchor.
    pub fn into_merkle_proof(
        self,
        protocol: impl Into<ProtocolId>,
    ) -> Result<Anchor<mpc::MerkleProof, D>, mpc::LeafNotKnown> {
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
            return Err(MergeError::DbcMismatch);
        }
        self.mpc_proof.merge_reveal(other.mpc_proof)?;
        Ok(self)
    }
}
