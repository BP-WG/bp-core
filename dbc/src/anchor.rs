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

//! Anchors are data structures used in deterministic bitcoin commitments for
//! keeping information about the proof of the commitment in connection to the
//! transaction which contains the commitment, and multi-protocol merkle tree as
//! defined by LNPBP-4.

use std::cmp::Ordering;
use std::collections::BTreeMap;

use amplify::Wrapper;
use bitcoin::hashes::{sha256, sha256t};
use bitcoin::{Transaction, Txid};
use commit_verify::convolve_commit::ConvolveCommitProof;
use commit_verify::multi_commit::{MultiCommitment, MultiSource, ProtocolId};
use commit_verify::{
    commit_encode, multi_commit, CommitVerify, ConsensusCommit,
    EmbedCommitProof, EmbedCommitVerify, Message, MultiCommitBlock, TaggedHash,
    TryCommitVerify, UntaggedProtocol,
};
use psbt::Psbt;

use crate::tapret::{
    Lnpbp6, PsbtCommitError, PsbtVerifyError, TapretError, TapretProof,
};

/// Default number of LNPBP slots
pub const ANCHOR_MIN_COMMITMENTS: u16 = 16;

static MIDSTATE_ANCHOR_ID: [u8; 32] = [
    148, 72, 59, 59, 150, 173, 163, 140, 159, 237, 69, 118, 104, 132, 194, 110,
    250, 108, 1, 140, 74, 248, 152, 205, 70, 32, 184, 87, 20, 102, 127, 20,
];

/// Tag used for [`AnchorId`] hash type
pub struct AnchorIdTag;

impl sha256t::Tag for AnchorIdTag {
    #[inline]
    fn engine() -> sha256::HashEngine {
        let midstate = sha256::Midstate::from_inner(MIDSTATE_ANCHOR_ID);
        sha256::HashEngine::from_midstate(midstate, 64)
    }
}

/// Unique anchor identifier equivalent to the anchor commitment hash
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
#[derive(
    Wrapper, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default, From
)]
#[wrapper(
    Debug, Display, LowerHex, Index, IndexRange, IndexFrom, IndexTo, IndexFull
)]
pub struct AnchorId(sha256t::Hash<AnchorIdTag>);

impl<Msg> CommitVerify<Msg, UntaggedProtocol> for AnchorId
where
    Msg: AsRef<[u8]>,
{
    #[inline]
    fn commit(msg: &Msg) -> AnchorId { AnchorId::hash(msg) }
}

impl strict_encoding::Strategy for AnchorId {
    type Strategy = strict_encoding::strategies::Wrapped;
}

/// Errors working with anchors.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Display, Error, From)]
#[display(inner)]
pub enum Error {
    /// Errors embedding LNPBP-4 commitment into PSBT
    #[from]
    EmbedCommit(PsbtCommitError),

    /// Errors constructing LNPBP-4 commitment
    #[from]
    Lnpbp4(multi_commit::Error),
}

/// Anchor is a data structure used in deterministic bitcoin commitments for
/// keeping information about the proof of the commitment in connection to the
/// transaction which contains the commitment, and multi-protocol merkle tree as
/// defined by LNPBP-4.
#[derive(Clone, PartialEq, Eq, Debug, StrictEncode, StrictDecode)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
pub struct Anchor {
    /// Transaction containing deterministic bitcoin commitment.
    pub txid: Txid,

    /// Structured multi-protocol LNPBP-4 data the transaction commits to.
    pub lnpbp4_block: MultiCommitBlock,

    /// Proof of the commitment.
    pub proof: Proof,
}

impl commit_encode::Strategy for Anchor {
    type Strategy = commit_encode::strategies::UsingStrict;
}

impl ConsensusCommit for Anchor {
    type Commitment = AnchorId;
}

impl Ord for Anchor {
    fn cmp(&self, other: &Self) -> Ordering {
        self.anchor_id().cmp(&other.anchor_id())
    }
}

impl PartialOrd for Anchor {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Anchor {
    /// Returns id of the anchor (commitment hash).
    #[inline]
    pub fn anchor_id(&self) -> AnchorId { self.consensus_commit() }

    /// Constructs anchor and embeds LNPBP4 commitment into PSBT.
    pub fn commit(
        psbt: &mut Psbt,
        messages: BTreeMap<ProtocolId, Message>,
    ) -> Result<Anchor, Error> {
        let multi_source = MultiSource {
            min_length: ANCHOR_MIN_COMMITMENTS,
            messages,
        };
        let lnpbp4_block = MultiCommitBlock::try_commit(&multi_source)?;
        psbt.embed_commit(&lnpbp4_block).map_err(Error::from)
    }

    /// Verifies that the transaction commits to the anchor and the anchor
    /// commits to the given message under the given protocol.
    pub fn verify(
        &self,
        protocol_id: ProtocolId,
        message: Message,
        tx: Transaction,
    ) -> Result<bool, TapretError> {
        self.proof
            .verify(&self.lnpbp4_block.consensus_commit(), tx)
            .map(|res| res && self.lnpbp4_block.verify(protocol_id, message))
    }

    /// Conceals all LNPBP-4 data except specific protocol.
    pub fn conceal_except(&mut self, protocol_id: ProtocolId) -> usize {
        self.lnpbp4_block.conceal_except(protocol_id)
    }
}

impl EmbedCommitProof<MultiCommitBlock, Psbt, Lnpbp6> for Anchor {
    fn restore_original_container(
        &self,
        psbt: &Psbt,
    ) -> Result<Psbt, PsbtVerifyError> {
        match self.proof {
            Proof::Opret1st => todo!("Implement OpRet"),
            Proof::Tapret1st(ref proof) => {
                proof.restore_original_container(psbt)
            }
        }
    }
}

impl EmbedCommitVerify<MultiCommitBlock, Lnpbp6> for Psbt {
    type Proof = Anchor;
    type CommitError = PsbtCommitError;
    type VerifyError = PsbtVerifyError;

    fn embed_commit(
        &mut self,
        msg: &MultiCommitBlock,
    ) -> Result<Self::Proof, Self::CommitError> {
        let lnpbp4_block = msg.clone();

        // TODO: Implement OpRet
        let proof = self.embed_commit(&lnpbp4_block.consensus_commit())?;

        let anchor = Anchor {
            txid: self.to_txid(),
            lnpbp4_block,
            proof: Proof::Tapret1st(proof),
        };

        // TODO: Update PSBT

        Ok(anchor)
    }
}

/// Type and type-specific proof information of a deterministic bitcoin
/// commitment.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[derive(StrictEncode, StrictDecode)]
#[strict_encoding(by_order)]
#[non_exhaustive]
pub enum Proof {
    /// Opret commitment (no extra-transaction proof is required).
    Opret1st,

    /// Tapret commitment and a proof of it.
    Tapret1st(TapretProof),
}

impl Proof {
    /// Verifies validity of the proof.
    pub fn verify(
        &self,
        msg: &MultiCommitment,
        tx: Transaction,
    ) -> Result<bool, TapretError> {
        match self {
            Proof::Opret1st => todo!("Implement opret commitment verification"),
            Proof::Tapret1st(proof) => {
                ConvolveCommitProof::<_, Transaction, _>::verify(proof, msg, tx)
            }
        }
    }
}

#[cfg(test)]
mod test {
    use commit_verify::tagged_hash;

    use super::*;

    #[test]
    fn test_anchor_id_midstate() {
        let midstate = tagged_hash::Midstate::with(b"bp:dbc:anchor");
        assert_eq!(midstate.into_inner().into_inner(), MIDSTATE_ANCHOR_ID);
    }
}
