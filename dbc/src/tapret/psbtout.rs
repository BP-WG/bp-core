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

use bitcoin::hashes::Hash;
use bitcoin::psbt::Output;
use bitcoin::util::taproot::TapBranchHash;
use bitcoin::{Script, TxOut};
use bitcoin_scripts::taproot::{Node, TaprootScriptTree};
use commit_verify::embed_commit::ConvolveCommitVerify;
use commit_verify::multi_commit::MultiCommitment;
use commit_verify::{EmbedCommitProof, EmbedCommitVerify};
use secp256k1::SECP256K1;

use super::{Lnpbp6, TapretProof, TapretTreeError};

/// Errors during tapret PSBT commitment process.
#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
pub enum TapretPsbtError {
    /// Error embedding tapret commitment into taproot script tree.
    #[from]
    #[display(inner)]
    TreeEmbedding(TapretTreeError),

    /// tapret commitment can't be made in a transaction lacking any taproot
    /// outputs.
    #[display(doc_comments)]
    NoTaprootOutput,

    /// tapret commitment can't be made due to an absent taproot internal key
    /// in PSBT data
    InternalKeyMissed,

    /// tapret commitment can't be made due to an absent taproot script tree in
    /// PSBT data
    TapTreeMissed,
}

impl EmbedCommitProof<MultiCommitment, (psbt::Output, TxOut), Lnpbp6>
    for TapretProof
{
    fn restore_original_container(
        &self,
        commit_container: &(Output, TxOut),
    ) -> Result<(Output, TxOut), TapretPsbtError> {
        let mut original_container = commit_container.clone();
        let (output, txout) = &mut original_container;

        let internal_key =
            if let Some(internal_key) = &mut output.tap_internal_key {
                internal_key
            } else {
                return Err(TapretPsbtError::InternalKeyMissed);
            };

        let tap_tree = if let Some(tap_tree) = &mut output.tap_tree {
            tap_tree
        } else {
            return Err(TapretPsbtError::TapTreeMissed);
        };

        *internal_key = self.internal_key;
        *tap_tree = self.other_node.restore_original_container(tap_tree)?;

        let original_root =
            TaprootScriptTree::from(tap_tree.clone()).into_root_node();
        let merkle_root =
            TapBranchHash::from_inner(original_root.node_hash().into_inner());

        txout.script_pubkey = Script::new_v1_p2tr(
            SECP256K1,
            self.internal_key,
            Some(merkle_root),
        );

        Ok(original_container)
    }
}

impl EmbedCommitVerify<MultiCommitment, Lnpbp6> for (psbt::Output, TxOut) {
    type Proof = TapretProof;
    type CommitError = TapretPsbtError;

    fn embed_commit(
        &mut self,
        msg: &MultiCommitment,
    ) -> Result<Self::Proof, Self::CommitError> {
        let (output, txout) = self;

        let internal_key = if let Some(internal_key) = output.tap_internal_key {
            internal_key
        } else {
            return Err(TapretPsbtError::InternalKeyMissed);
        };

        let tap_tree = if let Some(tap_tree) = &mut output.tap_tree {
            tap_tree
        } else {
            return Err(TapretPsbtError::TapTreeMissed);
        };

        let node_proof = tap_tree.embed_commit(msg)?;

        let proof = TapretProof {
            other_node: node_proof,
            internal_key,
        };

        txout.convolve_commit(proof.clone(), msg);

        Ok(proof)
    }
}
