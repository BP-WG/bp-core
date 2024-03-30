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
//! transaction which contains the commitment, and multiprotocol merkle tree as
//! defined by LNPBP-4.

use std::error::Error;
use std::marker::PhantomData;

use amplify::confinement::TinyVec;
use bc::{Tx, TxMerkleNode, Txid};
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

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BPCORE, tags = custom, dumb = Self::Txid(strict_dumb!()))]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub enum TxWitness {
    #[strict_type(tag = 1)]
    Txid(Txid),
    #[strict_type(tag = 2)]
    Spv(Tx, TinyVec<TxMerkleNode>), // TODO: Introduce merkle path type
}

impl TxWitness {
    pub fn txid(&self) -> Txid {
        match self {
            TxWitness::Txid(txid) => *txid,
            TxWitness::Spv(tx, _) => tx.txid(),
        }
    }

    pub fn merge_reveal(self, other: Self) -> Result<Self, MergeError> {
        let txid = self.txid();
        if txid != other.txid() {
            return Err(MergeError::TxidMismatch);
        }
        Ok(match (self, other) {
            (Self::Txid(txid), Self::Txid(_)) => Self::Txid(txid),
            (Self::Spv(tx, spv), Self::Txid(_)) | (Self::Txid(_), Self::Spv(tx, spv)) => {
                Self::Spv(tx, spv)
            }
            (Self::Spv(tx, spv1), Self::Spv(_, spv2)) if spv1 == spv2 => Self::Spv(tx, spv1),
            // We do not error here since if the merkle path is invalid we will error in validation.
            // Here we just take the longest one and try to recover from the corrupted data.
            (Self::Spv(tx, spv1), Self::Spv(_, spv2)) if spv1.len() > spv2.len() => {
                Self::Spv(tx, spv1)
            }
            (Self::Spv(tx, _), Self::Spv(_, spv2)) => Self::Spv(tx, spv2),
        })
    }
}

/// Anchor is a data structure used in deterministic bitcoin commitments for
/// keeping information about the proof of the commitment in a transactions,
/// and multiprotocol merkle tree as defined by LNPBP-4.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BPCORE)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct EtxWitness<L: mpc::Proof + StrictDumb, D: dbc::Proof<M>, M: DbcMethod = Method> {
    /// Structured multi-protocol LNPBP-4 data the transaction commits to.
    pub mpc_proof: L,

    /// Proof of the DBC commitment.
    pub dbc_proof: D,

    #[doc(hidden)]
    #[strict_type(skip)]
    pub _method: PhantomData<M>,
}

impl<L: mpc::Proof + StrictDumb, D: dbc::Proof<M>, M: DbcMethod> EtxWitness<L, D, M> {
    /// Constructs extra-transaction witness for a given MPC and DBC
    /// proofs.
    pub fn new(mpc_proof: L, dbc_proof: D) -> Self {
        Self {
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

impl<D: dbc::Proof<M>, M: DbcMethod> EtxWitness<mpc::MerkleProof, D, M> {
    /// Reconstructs anchor containing merkle block
    pub fn into_merkle_block(
        self,
        protocol_id: impl Into<ProtocolId>,
        message: impl Into<Message>,
    ) -> Result<EtxWitness<mpc::MerkleBlock, D, M>, mpc::InvalidProof> {
        let lnpbp4_proof =
            mpc::MerkleBlock::with(&self.mpc_proof, protocol_id.into(), message.into())?;
        Ok(EtxWitness {
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
    ) -> Result<EtxWitness<mpc::MerkleBlock, D, M>, mpc::InvalidProof> {
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

impl<D: dbc::Proof<M>, M: DbcMethod> EtxWitness<mpc::MerkleBlock, D, M> {
    /// Conceals all LNPBP-4 data except specific protocol and produces merkle
    /// proof anchor.
    pub fn to_merkle_proof(
        &self,
        protocol: impl Into<ProtocolId>,
    ) -> Result<EtxWitness<mpc::MerkleProof, D, M>, mpc::LeafNotKnown> {
        self.clone().into_merkle_proof(protocol)
    }

    /// Conceals all LNPBP-4 data except specific protocol and converts anchor
    /// into merkle proof anchor.
    pub fn into_merkle_proof(
        self,
        protocol: impl Into<ProtocolId>,
    ) -> Result<EtxWitness<mpc::MerkleProof, D, M>, mpc::LeafNotKnown> {
        let lnpbp4_proof = self.mpc_proof.to_merkle_proof(protocol.into())?;
        Ok(EtxWitness {
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

    /// Merges two extra-transaction witnesses keeping revealed data.
    pub fn merge_reveal(mut self, other: Self) -> Result<Self, MergeError> {
        if self.dbc_proof != other.dbc_proof {
            return Err(MergeError::DbcMismatch);
        }
        self.mpc_proof.merge_reveal(other.mpc_proof)?;
        Ok(self)
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BPCORE, tags = custom)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase", untagged)
)]
pub enum Anchor<P: mpc::Proof + StrictDumb = mpc::MerkleProof> {
    #[strict_type(tag = 0x01)]
    Tapret {
        tapret: EtxWitness<P, TapretProof>,
        txw: TxWitness,
    },
    #[strict_type(tag = 0x02)]
    Opret {
        opret: EtxWitness<P, OpretProof>,
        txw: TxWitness,
    },
    #[strict_type(tag = 0x03)]
    Dual {
        tapret: EtxWitness<P, TapretProof>,
        opret: EtxWitness<P, OpretProof>,
        txw: TxWitness,
    },
}

impl<P: mpc::Proof + StrictDumb> StrictDumb for Anchor<P> {
    fn strict_dumb() -> Self {
        Self::Tapret {
            tapret: strict_dumb!(),
            txw: strict_dumb!(),
        }
    }
}

impl<P: mpc::Proof + StrictDumb> Anchor<P> {
    pub fn txid(&self) -> Txid {
        match self {
            Anchor::Tapret { txw, .. } | Anchor::Opret { txw, .. } | Anchor::Dual { txw, .. } => {
                txw.txid()
            }
        }
    }

    pub fn tx_witness(&self) -> &TxWitness {
        match self {
            Anchor::Tapret { txw, .. } | Anchor::Opret { txw, .. } | Anchor::Dual { txw, .. } => {
                txw
            }
        }
    }

    pub fn mpc_proofs(&self) -> impl Iterator<Item = &P> {
        let (t, o) = match self {
            Anchor::Tapret { tapret, txw: _ } => (Some(tapret), None),
            Anchor::Opret { opret, txw: _ } => (None, Some(opret)),
            Anchor::Dual {
                tapret,
                opret,
                txw: _,
            } => (Some(tapret), Some(opret)),
        };
        t.map(|a| &a.mpc_proof)
            .into_iter()
            .chain(o.map(|a| &a.mpc_proof))
    }

    fn split(
        self,
    ) -> (TxWitness, Option<EtxWitness<P, TapretProof>>, Option<EtxWitness<P, OpretProof>>) {
        match self {
            Anchor::Tapret { tapret, txw } => (txw, Some(tapret), None),
            Anchor::Opret { opret, txw } => (txw, None, Some(opret)),
            Anchor::Dual { tapret, opret, txw } => (txw, Some(tapret), Some(opret)),
        }
    }
}

impl Anchor<mpc::MerkleBlock> {
    /// Merges two anchors keeping revealed data.
    pub fn merge_reveal(self, other: Self) -> Result<Self, MergeError> {
        if self == other {
            return Ok(self);
        }
        let (txw1, tapret1, opret1) = self.split();
        let (txw2, tapret2, opret2) = other.split();
        let txw = txw1.merge_reveal(txw2)?;
        let tapret = match (tapret1, tapret2) {
            (None, None) => None,
            (Some(tapret), None) | (None, Some(tapret)) => Some(tapret),
            (Some(tapret1), Some(tapret2)) => Some(tapret1.merge_reveal(tapret2)?),
        };
        let opret = match (opret1, opret2) {
            (None, None) => None,
            (Some(opret), None) | (None, Some(opret)) => Some(opret),
            (Some(opret1), Some(opret2)) => Some(opret1.merge_reveal(opret2)?),
        };
        Ok(match (tapret, opret) {
            (None, None) => unreachable!(),
            (Some(tapret), None) => Self::Tapret { tapret, txw },
            (None, Some(opret)) => Self::Opret { opret, txw },
            (Some(tapret), Some(opret)) => Self::Dual { tapret, opret, txw },
        })
    }
}
