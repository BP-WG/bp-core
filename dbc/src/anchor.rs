// Deterministic bitcoin commitments library.
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

#![allow(missing_docs)]

//! Anchors are data structures used in deterministic bitcoin commitments for
//! keeping information about the proof of the commitment in connection to the
//! transaction which contains the commitment, and multi-protocol merkle tree as
//! defined by LNPBP-4.

use std::error::Error;
use std::marker::PhantomData;

use bc::{Tx, Txid};
use commit_verify::mpc::{self, Message, ProtocolId};
use strict_encoding::{StrictDumb, StrictEncode};

use crate::opret::OpretProof;
use crate::tapret::TapretProof;
use crate::{DbcMethod, Method, LIB_NAME_BPCORE};

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
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct Anchor<L: mpc::Proof + StrictDumb, D: dbc::Proof<M>, M: DbcMethod = Method> {
    /// Transaction containing deterministic bitcoin commitment.
    pub txid: Txid,

    /// Structured multi-protocol LNPBP-4 data the transaction commits to.
    pub mpc_proof: L,

    /// Proof of the DBC commitment.
    pub dbc_proof: D,

    #[doc(hidden)]
    #[strict_type(skip)]
    pub _method: PhantomData<M>,
}

impl<L: mpc::Proof + StrictDumb, D: dbc::Proof<M>, M: DbcMethod> Anchor<L, D, M> {
    /// Constructs anchor for a given witness transaction id, MPC and DBC
    /// proofs.
    pub fn new(witness_txid: Txid, mpc_proof: L, dbc_proof: D) -> Self {
        Self {
            txid: witness_txid,
            mpc_proof,
            dbc_proof,
            _method: PhantomData,
        }
    }
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

impl<D: dbc::Proof<M>, M: DbcMethod> Anchor<mpc::MerkleProof, D, M> {
    /// Reconstructs anchor containing merkle block
    pub fn into_merkle_block(
        self,
        protocol_id: impl Into<ProtocolId>,
        message: impl Into<Message>,
    ) -> Result<Anchor<mpc::MerkleBlock, D, M>, mpc::InvalidProof> {
        let lnpbp4_proof =
            mpc::MerkleBlock::with(&self.mpc_proof, protocol_id.into(), message.into())?;
        Ok(Anchor {
            txid: self.txid,
            mpc_proof: lnpbp4_proof,
            dbc_proof: self.dbc_proof,
            _method: default!(),
        })
    }

    /// Reconstructs anchor containing merkle block
    pub fn to_merkle_block(
        &self,
        protocol_id: impl Into<ProtocolId>,
        message: impl Into<Message>,
    ) -> Result<Anchor<mpc::MerkleBlock, D, M>, mpc::InvalidProof> {
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

impl<D: dbc::Proof<M>, M: DbcMethod> Anchor<mpc::MerkleBlock, D, M> {
    /// Conceals all LNPBP-4 data except specific protocol and produces merkle
    /// proof anchor.
    pub fn to_merkle_proof(
        &self,
        protocol: impl Into<ProtocolId>,
    ) -> Result<Anchor<mpc::MerkleProof, D, M>, mpc::LeafNotKnown> {
        self.clone().into_merkle_proof(protocol)
    }

    /// Conceals all LNPBP-4 data except specific protocol and converts anchor
    /// into merkle proof anchor.
    pub fn into_merkle_proof(
        self,
        protocol: impl Into<ProtocolId>,
    ) -> Result<Anchor<mpc::MerkleProof, D, M>, mpc::LeafNotKnown> {
        let lnpbp4_proof = self.mpc_proof.to_merkle_proof(protocol.into())?;
        Ok(Anchor {
            txid: self.txid,
            mpc_proof: lnpbp4_proof,
            dbc_proof: self.dbc_proof,
            _method: default!(),
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

#[derive(Clone, Eq, PartialEq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BPCORE, tags = custom, dumb = Self::Tapret(strict_dumb!()))]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase", untagged)
)]
pub enum AnchorSet<P: mpc::Proof + StrictDumb = mpc::MerkleProof> {
    #[strict_type(tag = 0x01)]
    Tapret(Anchor<P, TapretProof>),
    #[strict_type(tag = 0x02)]
    Opret(Anchor<P, OpretProof>),
    #[strict_type(tag = 0x03)]
    Dual {
        tapret: Anchor<P, TapretProof>,
        opret: Anchor<P, OpretProof>,
    },
}

impl<P: mpc::Proof + StrictDumb> AnchorSet<P> {
    pub fn txid(&self) -> Option<Txid> {
        match self {
            AnchorSet::Tapret(a) => Some(a.txid),
            AnchorSet::Opret(a) => Some(a.txid),
            AnchorSet::Dual { tapret, opret } if tapret.txid == opret.txid => Some(tapret.txid),
            _ => None,
        }
    }

    pub fn txid_unchecked(&self) -> Txid {
        match self {
            AnchorSet::Tapret(a) => a.txid,
            AnchorSet::Opret(a) => a.txid,
            AnchorSet::Dual { tapret, opret: _ } => tapret.txid,
        }
    }

    pub fn from_split(
        tapret: Option<Anchor<P, TapretProof>>,
        opret: Option<Anchor<P, OpretProof>>,
    ) -> Option<Self> {
        Some(match (tapret, opret) {
            (Some(tapret), Some(opret)) => Self::Dual { tapret, opret },
            (Some(tapret), None) => Self::Tapret(tapret),
            (None, Some(opret)) => Self::Opret(opret),
            (None, None) => return None,
        })
    }

    #[allow(clippy::type_complexity)]
    pub fn as_split(&self) -> (Option<&Anchor<P, TapretProof>>, Option<&Anchor<P, OpretProof>>) {
        match self {
            AnchorSet::Tapret(tapret) => (Some(tapret), None),
            AnchorSet::Opret(opret) => (None, Some(opret)),
            AnchorSet::Dual { tapret, opret } => (Some(tapret), Some(opret)),
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn into_split(self) -> (Option<Anchor<P, TapretProof>>, Option<Anchor<P, OpretProof>>) {
        match self {
            AnchorSet::Tapret(tapret) => (Some(tapret), None),
            AnchorSet::Opret(opret) => (None, Some(opret)),
            AnchorSet::Dual { tapret, opret } => (Some(tapret), Some(opret)),
        }
    }

    pub fn mpc_proofs(&self) -> impl Iterator<Item = &P> {
        let (t, o) = self.as_split();
        t.map(|a| &a.mpc_proof)
            .into_iter()
            .chain(o.map(|a| &a.mpc_proof))
    }
}
