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

#![cfg(any(feature = "consensus", feature = "wallet"))]

//! `EmbedCommit: TapTree, Msg -> TapTree', TapNode`

use amplify::Wrapper;
use bitcoin::psbt::TapTree;
use bitcoin::util::taproot::{TaprootBuilder, TaprootBuilderError};
use bitcoin_scripts::taproot::{
    DfsOrdering, MaxDepthExceeded, Node, TaprootScriptTree, TreeNode,
};
use bitcoin_scripts::TapScript;
use commit_verify::multi_commit::MultiCommitment;
use commit_verify::{CommitVerify, EmbedCommitProof, EmbedCommitVerify};

use super::{Lnpbp6, TapRightPartner};

/// Errors during tapret commitment embedding into tapscript tree.
#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum TapretTreeError {
    /// the provided commitment data can't be strict encoded. Details: {0}
    #[from]
    StrictEncoding(strict_encoding::Error),

    /// unable to update tap tree with the commitment. Details: {0}
    #[from]
    TapTree(TaprootBuilderError),

    /// the tree
    #[from]
    TreeBuilder(TaprootBuilder),

    /// the tapret commitment can't be performet since the taproot script
    /// tree already has maximal depth.
    #[from(MaxDepthExceeded)]
    MaxDepthExceeded,

    /// the provided taproot script tree has no revealed nodes to prove the
    /// commitment.
    IncompleteTree(TaprootScriptTree),
}

impl EmbedCommitProof<MultiCommitment, TaprootScriptTree, Lnpbp6>
    for TapRightPartner
{
    fn restore_original_container(
        &self,
        modified_tree: &TaprootScriptTree,
    ) -> Result<TaprootScriptTree, TapretTreeError> {
        let (_, original_tree) =
            modified_tree.clone().split().map_err(|_| {
                TapretTreeError::IncompleteTree(modified_tree.clone())
            })?;
        Ok(original_tree)
    }
}

impl EmbedCommitVerify<MultiCommitment, Lnpbp6> for TaprootScriptTree {
    type Proof = TapRightPartner;
    type CommitError = TapretTreeError;

    fn embed_commit(
        &mut self,
        msg: &MultiCommitment,
    ) -> Result<Self::Proof, Self::CommitError> {
        let script_commitment = TapScript::commit(msg);

        let root_node = self.to_root_node();
        let tap_node = match root_node {
            TreeNode::Leaf(leaf_script, _) => {
                TapRightPartner::Leaf(leaf_script.clone())
            }
            TreeNode::Hidden(..) => {
                return Err(TapretTreeError::IncompleteTree(self.clone()))
            }
            TreeNode::Branch(branch, _) => TapRightPartner::Branch(
                branch.as_left_node().node_hash(),
                branch.as_right_node().node_hash(),
            ),
        };

        let mut builder = TaprootBuilder::new();
        builder = builder.add_leaf(0, script_commitment.into_inner())?;
        let commit_tree =
            TaprootScriptTree::from(TapTree::from_inner(builder)?);

        *self = self.clone().join(commit_tree, DfsOrdering::LeftRight)?;

        Ok(tap_node)
    }
}

impl EmbedCommitProof<MultiCommitment, TapTree, Lnpbp6> for TapRightPartner {
    fn restore_original_container(
        &self,
        commit_container: &TapTree,
    ) -> Result<TapTree, TapretTreeError> {
        let tree = TaprootScriptTree::from(commit_container.clone());
        EmbedCommitProof::<_, TaprootScriptTree, _>::restore_original_container(
            self, &tree,
        )
        .map(TapTree::from)
    }
}

impl EmbedCommitVerify<MultiCommitment, Lnpbp6> for TapTree {
    type Proof = TapRightPartner;
    type CommitError = TapretTreeError;

    fn embed_commit(
        &mut self,
        msg: &MultiCommitment,
    ) -> Result<Self::Proof, Self::CommitError> {
        TaprootScriptTree::from(self.clone()).embed_commit(msg)
    }
}
