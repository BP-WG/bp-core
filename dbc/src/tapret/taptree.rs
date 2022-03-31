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

//! `EmbedCommit: TapTree, Msg -> TapTree', TapNode`

/*
use bitcoin::blockdata::opcodes::all;
use bitcoin::blockdata::script;
use bitcoin::hashes::Hash;
use bitcoin::psbt::TapTree;
use bitcoin::util::taproot::{
    LeafVersion, TapLeafHash, TaprootBuilder, TaprootBuilderError,
};
use bitcoin_scripts::TapScript;
use commit_verify::multi_commit::MultiCommitment;
use commit_verify::{
    CommitEncode, CommitVerify, EmbedCommitProof, EmbedCommitVerify,
};
use secp256k1::{KeyPair, SECP256K1};

use crate::tapret::{Lnpbp6, TapNode};
*/

use bitcoin::util::taproot::TaprootBuilderError;

/// Errors during tapret commitment embedding into [`TapTree`] container.
#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum TapTreeError {
    /// the provided commitment data can't be strict encoded. Details: {0}
    #[from]
    StrictEncoding(strict_encoding::Error),

    /// unable to update tap tree with the commitment. Details: {0}
    #[from]
    TapTree(TaprootBuilderError),
}

/*
impl EmbedCommitProof<MultiCommitment, TapTree, Lnpbp6> for TapNode {
    fn restore_original_container(
        &self,
        commit_container: &TapTree,
    ) -> TapTree {
        todo!()
    }
}

impl EmbedCommitVerify<MultiCommitment, Lnpbp6> for TapTree {
    type Proof = TapNode;
    type CommitError = TapTreeError;

    fn embed_commit(
        &mut self,
        msg: &MultiCommitment,
    ) -> Result<Self::Proof, Self::CommitError> {
        let script_commitment = TapScript::commit(msg).into_inner();

        // TODO: Replace with `self.script_count()` upon rust-bitcoin #922 merge

        let mut tap_node = TapNode::None;
        let mut builder = TaprootBuilder::new();
        let mut first_branch = None;
        builder.add_leaf(0, script_commitment);
        for (depth, script) in self.iter() {
            match (tap_node, depth) {
                (TapNode::None, 0) => {
                    tap_node = TapNode::Leaf(script.clone().into())
                }
                (TapNode::None, 1) => {
                    let hash2 = TapLeafHash::from_script(script, ver)
                        .into_hidden_hash();
                    match first_branch {
                        None => {
                            first_branch = Some(
                                TapLeafHash::from_script(script, ver)
                                    .into_hidden_hash(),
                            )
                        }
                        Some(hash1) if hash1 < hash2 => {
                            tap_node = TapNode::Branch(hash1, hash2)
                        }
                        Some(hash1) => tap_node = TapNode::Branch(hash2, hash1),
                    }
                }
                (TapNode::None, _) => {
                    let hash2 = TapLeafHash::from_script(script, ver)
                        .into_hidden_hash();
                }
                (TapNode::Leaf(ref left_script), 1)
                    if left_script.tap_leaf_hash() < script.tap_leaf_hash() =>
                {
                    TapNode::Branch(
                        left_script.tap_leaf_hash().into_hidden_hash(),
                        script.tap_leaf_hash().into_hidden_hash(),
                    )
                }
            }
            builder = builder.add_leaf(depth as usize + 1, script.clone())?;
        }

        // We use a dumb internal key since its data are not used anywhere
        // TODO: Allow extraction of script merkle branches in rust-bitcoin from
        //       TaprootTreeBuilder without using internal key
        let internal_key =
            KeyPair::from_secret_key(SECP256K1, secp256k1::ONE_KEY)
                .public_key();
        let spend_info = builder
            .finalize(SECP256K1, internal_key)
            .expect("tapret TapTree commitment algorithm failure");

        // Both of the DFS-last two leafs has the same merkle path, so we can
        // use any of them.
        let control_block = spend_info
            .control_block(&(script_commitment, LeafVersion::TapScript))
            .expect("tapret TapTree commitment algorithm failure");
        debug_assert_eq!(
            control_block.merkle_branch.as_inner().len(),
            commit_depth
        );

        Ok(control_block.merkle_branch)
    }
}
*/
