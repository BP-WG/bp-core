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

//! Implementation of tapret commitments for PSBT-related data structures.

use amplify::Wrapper;
use bitcoin::hashes::{sha256t, Hash};
use bitcoin::psbt::TapTree;
use bitcoin::util::taproot::TaprootMerkleBranch;
use bitcoin::{Script, TxOut};
use commit_verify::multi_commit::{Lnpbp4Tag, MultiCommitment};
use commit_verify::EmbedCommitVerify;
use psbt::commit::tapret::ProprietaryKeyTapret;
use psbt::{ProprietaryKey, TapretOutput};
use secp256k1::Secp256k1;
use strict_encoding::StrictEncode;

use crate::tapret::{TapTreeContainer, TapTreeError};

/// Error finalizing deterministic bitcoin commitments in the PSBT
#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum CommitmentError {
    /// tapret commitment is already created for this output; it could be that
    /// the PSBT was commitment-finalized under some other protocol.
    CommitmentAlreadyFinalized,

    /// an attempt to add tapret commitment to a non-taproot output or output
    /// which does not contain all required information about script tree and
    /// internal key.
    NonTaprootOutput,

    /// output is not marked to host the commitments; please set
    /// [`PSBT_OUT_TAPRET_HOST`] flag on it first.
    OutputCantHostCommitment,

    /// Errors during commitment embedding into [`TapTreeContainer`]
    #[from]
    #[display(inner)]
    TapTree(TapTreeError),
}

/// PSBT commitment finalizer does output-type specific modifications – and
/// saves information for the wallet in form of tweak data such that the wallet
/// will be able to store the information for future address retrievals and
/// spending.
pub trait CommitFinalizer {
    /// - Taproot: take the value of `TAPRET_COMMITMENT` and add two equal
    ///   `OP_RETURN` branches at the `depth = max(depth) + 1`; save merkle path to
    ///   this branch as `TAPRET_PROOF`; update value of transaction `scriptPubkey`.
    fn finalize_tapret(
        &mut self,
        secp: &Secp256k1<secp256k1::VerifyOnly>,
    ) -> Result<Option<TaprootMerkleBranch>, CommitmentError>;
}

impl CommitFinalizer for (TxOut, psbt::Output) {
    fn finalize_tapret(
        &mut self,
        secp: &Secp256k1<secp256k1::VerifyOnly>,
    ) -> Result<Option<TaprootMerkleBranch>, CommitmentError> {
        let (txout, output) = self;

        if output.has_tapret_proof() {
            return Err(CommitmentError::CommitmentAlreadyFinalized);
        }

        // TODO: Use multimessage commitment data type
        let commitment = match output.tapret_commitment() {
            None => return Ok(None),
            Some(commitment) => commitment,
        }
        .into_inner();
        let commitment = sha256t::Hash::<Lnpbp4Tag>::from_inner(commitment);
        let commitment = MultiCommitment::from_inner(commitment);

        let internal_key = output
            .tap_internal_key
            .ok_or(CommitmentError::NonTaprootOutput)?;

        let taptree = output
            .tap_tree
            .as_ref()
            .ok_or(CommitmentError::NonTaprootOutput)?;

        let mut container = TapTreeContainer::from_inner(taptree.clone());
        let proof = container.embed_commit(&commitment)?;
        let taptree: TapTree = container.into_inner();
        output.tap_tree = Some(taptree.clone());

        let builder = taptree.into_inner();
        let spend_info = builder
            .finalize(secp, internal_key)
            .expect("tapret TapTree commitment algorithm failure");
        txout.script_pubkey =
            Script::new_v1_p2tr_tweaked(spend_info.output_key());

        output
            .proprietary
            .insert(ProprietaryKey::tapret_proof(), proof.strict_serialize().expect("proof size limited by 127 hashes can't exceed strict encoding limitations"));

        Ok(Some(proof))
    }
}

#[cfg(test)]
mod test {
    //use super::*;

    #[test]
    fn noscript() {}
}
