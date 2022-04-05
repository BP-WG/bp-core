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

#![cfg(feature = "wallet")]

use bitcoin::hashes::Hash;
use bitcoin::psbt::{Output, TapTree};
use bitcoin::util::taproot::TapBranchHash;
use bitcoin::{Script, TxOut};
use bitcoin_scripts::taproot::{Node, TaprootScriptTree, TreeNode};
use bitcoin_scripts::TapNodeHash;
use commit_verify::embed_commit::ConvolveCommitVerify;
use commit_verify::multi_commit::MultiCommitment;
use commit_verify::{EmbedCommitProof, EmbedCommitVerify};
use psbt::commit::tapret::DfsPathEncodeError;
use psbt::TapretOutput;
use secp256k1::SECP256K1;

use super::{Lnpbp6, TapretProof};
use crate::tapret::taptree::{
    TapretProofError, TapretSourceError, TapretSourceInfo,
};

/// Errors during tapret PSBT commitment process.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Display, Error, From)]
pub enum PsbtCommitError {
    /// Invalid taproot script tree source information.
    #[from]
    #[display(inner)]
    SourceError(TapretSourceError),

    /// tapret commitment can't be made in a transaction lacking any taproot
    /// outputs.
    #[display(doc_comments)]
    NoTaprootOutput,

    /// tapret commitment can't be made due to an absent taproot internal key
    /// in PSBT data.
    InternalKeyMissed,

    /// tapret commitment does not change internal key, but the key in PSBT
    /// data and key from the tapret proof differ.
    InternalKeyMismatch,

    /// invalid tapret commitment path in PSBT data.
    #[from(DfsPathEncodeError)]
    TapretPathInvalid,

    /// PSBT output misses tapret path information.
    TapretPathMissed,
}

/// Errors during tapret PSBT commitment process.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum PsbtVerifyError {
    #[from]
    #[from(DfsPathEncodeError)]
    #[from(TapretSourceError)]
    Commit(PsbtCommitError),

    #[from]
    Proof(TapretProofError),
}

impl EmbedCommitProof<MultiCommitment, (psbt::Output, TxOut), Lnpbp6>
    for TapretProof
{
    fn restore_original_container(
        &self,
        commit_container: &(Output, TxOut),
    ) -> Result<(Output, TxOut), PsbtVerifyError> {
        let mut original_container = commit_container.clone();
        let (output, txout) = &mut original_container;

        let internal_key = output
            .tap_internal_key
            .ok_or(PsbtCommitError::InternalKeyMissed)?;
        if internal_key != self.internal_key {
            return Err(PsbtCommitError::InternalKeyMismatch)
                .map_err(PsbtVerifyError::from);
        }

        let dfs_path = output
            .tapret_dfs_path()
            .ok_or(PsbtCommitError::TapretPathMissed)??;

        let tap_tree = output.tap_tree.map(TaprootScriptTree::from);
        let source =
            TapretSourceInfo::<TaprootScriptTree>::with(tap_tree, dfs_path)?;
        let source = self.path_proof.restore_original_container(&source)?;

        let merkle_root = source
            .as_root_node()
            .map(TreeNode::node_hash)
            .map(TapNodeHash::into_inner)
            .map(TapBranchHash::from_inner);
        txout.script_pubkey =
            Script::new_v1_p2tr(SECP256K1, self.internal_key, merkle_root);

        output.tap_tree = source.into_tap_tree();

        Ok(original_container)
    }
}

impl EmbedCommitVerify<MultiCommitment, Lnpbp6> for (psbt::Output, TxOut) {
    type Proof = TapretProof;
    type CommitError = PsbtCommitError;
    type VerifyError = PsbtVerifyError;

    fn embed_commit(
        &mut self,
        msg: &MultiCommitment,
    ) -> Result<Self::Proof, Self::CommitError> {
        let (output, txout) = self;

        let internal_key = if let Some(internal_key) = output.tap_internal_key {
            internal_key
        } else {
            return Err(PsbtCommitError::InternalKeyMissed);
        };

        let dfs_path = output
            .tapret_dfs_path()
            .ok_or(PsbtCommitError::TapretPathMissed)??;

        let mut source = TapretSourceInfo::<TapTree>::with(
            output.tap_tree.clone(),
            dfs_path,
        )?;

        let path_proof = source.embed_commit(msg)?;

        let proof = TapretProof {
            path_proof,
            internal_key,
        };

        txout.convolve_commit(&proof, msg);

        Ok(proof)
    }
}
