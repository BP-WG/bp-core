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

use core::fmt::Debug;
use core::hash::Hash;

use bitcoin::psbt::{IncompleteTapTree, TapTree};
use bitcoin::util::taproot::TaprootBuilderError;
use bitcoin_scripts::taproot::{
    self, Branch, CutError, DfsOrder, DfsOrdering, DfsPath, DfsTraversalError,
    InstillError, MaxDepthExceeded, Node, TaprootScriptTree, TreeNode,
    UnsplittableTree,
};
use bitcoin_scripts::{LeafScript, TapNodeHash, TapScript};
use commit_verify::{
    lnpbp4, CommitVerify, EmbedCommitProof, EmbedCommitVerify,
};

use super::{Lnpbp6, TapretNodePartner, TapretPathProof};
use crate::tapret::TapretPathError;

// TODO: Re-check the use of all error variants
/// Errors during tapret commitment embedding into tapscript tree.
#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum TapretTreeError {
    /// the provided commitment data can't be strict encoded. Details: {0}
    #[from]
    Encoding(confined_encoding::Error),

    /// unable to update tap tree with the commitment. Details: {0}
    #[from]
    TapTree(TaprootBuilderError),

    /// the taproot script tree is invalid. Details: {0}
    #[from]
    TreeBuilder(IncompleteTapTree),

    /// the tapret commitment is impossible since the taproot script tree
    /// already has the maximal depth.
    #[from(MaxDepthExceeded)]
    MaxDepthExceeded,

    /// the provided taproot script tree has no revealed nodes to prove the
    /// commitment.
    IncompleteTree(TaprootScriptTree),

    /// tapret node partner {0} contains alternative commitment
    AlternativeCommitment(TapretNodePartner),

    /// tapret node partner {0} has an invalid order with the commitment node
    /// {1}
    IncorrectOrdering(TapretNodePartner, TreeNode),
}

/// Errors during taproot script tree tapret commitment verification and
/// restoration of the original container structure.
#[derive(
    Clone, PartialOrd, Ord, PartialEq, Eq, Hash, Debug, Display, Error, From
)]
#[display(doc_comments)]
pub enum TapretProofError {
    /// the provided tapret proof does not contain a taproot script tree, i.e.
    /// can't contain a commitment
    EmptyTree,

    /// the provided tapret proof consists of a single node
    #[from(UnsplittableTree)]
    UnsplittableTree,

    /// Errors in the taproot script tree and tapret path proof
    /// correspondences. See [`TapretSourceError`] for details.
    #[from]
    #[display(inner)]
    SourceError(TapretSourceError),
}

impl From<taproot::CutError> for TapretProofError {
    fn from(err: CutError) -> Self {
        match err {
            CutError::UnsplittableTree => Self::UnsplittableTree,
            CutError::DfsTraversal(e) => Self::SourceError(e.into()),
        }
    }
}

/// Errors during taproot script tree tapret commitment ebmedding.
#[derive(
    Clone, PartialOrd, Ord, PartialEq, Eq, Hash, Debug, Display, Error, From
)]
#[display(doc_comments)]
pub enum TapretSourceError {
    /// the length of the constructed tapret path proof exceeds taproot path
    /// length limit.
    #[from(MaxDepthExceeded)]
    MaxDepthExceeded,

    /// the node partner {0} at the level 1 can't be proven not to contain an
    /// alternative tapret commitment.
    InvalidNodePartner(TapretNodePartner),

    /// unable to produce tapret commitment since the commitment path {0} does
    /// not exist within the tree.
    PathNotExists(DfsPath),

    /// the provided taproot script tree contains hidden node {0} at path {1}
    /// and can't be used for tapret commit instillation.
    HiddenNode(TapNodeHash, DfsPath),

    /// the provided tapret commitment path {1} points at the leaf node {0}
    /// and can't be used for tapret commit instillation.
    LeafNode(LeafScript, DfsPath),
}

impl From<InstillError> for TapretSourceError {
    fn from(err: InstillError) -> Self {
        match err {
            InstillError::MaxDepthExceeded => Self::MaxDepthExceeded,
            InstillError::DfsTraversal(e) => e.into(),
        }
    }
}

impl From<DfsTraversalError> for TapretSourceError {
    fn from(err: DfsTraversalError) -> Self {
        match err {
            DfsTraversalError::PathNotExists(path) => Self::PathNotExists(path),
            DfsTraversalError::HiddenNode {
                node_hash,
                failed_path,
                path_leftover: _,
            } => Self::HiddenNode(node_hash, failed_path),
            DfsTraversalError::LeafNode {
                leaf_script,
                failed_path,
                path_leftover: _,
            } => Self::LeafNode(leaf_script, failed_path),
        }
    }
}

impl From<TapretPathError> for TapretSourceError {
    fn from(err: TapretPathError) -> Self {
        match err {
            TapretPathError::MaxDepthExceeded => Self::MaxDepthExceeded,
            TapretPathError::InvalidNodePartner(partner) => {
                Self::InvalidNodePartner(partner)
            }
        }
    }
}

/// Structure wrapping concrete taproot script tree, acting as a source of the
/// tapret commitment, keeping information about DFS path which should be used
/// for embedding tapret commit.
///
/// The structure can be used with [`TapTree`] and [`TaprootScriptTree`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TapretSourceInfo<Tree>(Option<Tree>)
where
    Tree: Clone + Eq + Debug;

impl TapretSourceInfo<TaprootScriptTree> {
    /// Validates that the provided path can be used for a tapret commitment
    /// embedding and constructs [`SourceTree`] from the provided
    /// [`TaprootScriptTree`] and a valid path. The path must point to a branch
    /// node in the tree.
    ///
    /// # Errors
    ///
    /// The following errors may happen:
    /// - [`DfsPathError::PathNotExists`], if the path does not exists within
    ///   the tree;
    /// - [`DfsPathError::HiddenNode`], if the path passes through a hidden node
    ///   of the tree;
    /// - [`DfsPathError::LeafNode`], if the path points at a leaf node.
    pub fn with(
        tap_tree: Option<TaprootScriptTree>,
    ) -> Result<Self, TapretSourceError> {
        Ok(TapretSourceInfo(tap_tree))
    }

    /// Returns reference to the script tree root node, if taproot script tree
    /// is present in the source data.
    pub fn as_root_node(&self) -> Option<&TreeNode> {
        self.0.as_ref().map(TaprootScriptTree::as_root_node)
    }

    /// Releases internal [`TapTree`] data, if present.
    #[inline]
    pub fn into_tap_tree(self) -> Option<TapTree> { self.0.map(TapTree::from) }
}

impl TapretSourceInfo<TapTree> {
    /// Validates that the provided path can be used for a tapret commitment
    /// embedding and constructs [`SourceTree`] from the provided [`TapTree`]
    /// and a valid path. The path must point to a branch node in the tree.
    ///
    /// # Errors
    ///
    /// The following errors may happen:
    /// - [`DfsPathError::PathNotExists`], if the path does not exists within
    ///   the tree;
    /// - [`DfsPathError::HiddenNode`], if the path passes through a hidden node
    ///   of the tree;
    /// - [`DfsPathError::LeafNode`], if the path points at a leaf node.
    #[inline]
    pub fn with(tap_tree: Option<TapTree>) -> Result<Self, TapretSourceError> {
        TapretSourceInfo::<TaprootScriptTree>::with(
            tap_tree.map(TaprootScriptTree::from),
        )
        .map(TapretSourceInfo::from)
    }

    /// Releases internal [`TapTree`] data, if present.
    #[inline]
    pub fn into_tap_tree(self) -> Option<TapTree> { self.0 }
}

impl From<&TapretSourceInfo<TapTree>> for TapretSourceInfo<TaprootScriptTree> {
    fn from(source: &TapretSourceInfo<TapTree>) -> Self {
        let tap_tree = source.0.as_ref().cloned().map(TaprootScriptTree::from);
        TapretSourceInfo(tap_tree)
    }
}

impl From<TapretSourceInfo<TaprootScriptTree>> for TapretSourceInfo<TapTree> {
    fn from(source: TapretSourceInfo<TaprootScriptTree>) -> Self {
        let tap_tree = source.0.map(TapTree::from);
        TapretSourceInfo(tap_tree)
    }
}

impl
    EmbedCommitProof<
        lnpbp4::CommitmentHash,
        TapretSourceInfo<TaprootScriptTree>,
        Lnpbp6,
    > for TapretPathProof
{
    fn restore_original_container(
        &self,
        modified_tree: &TapretSourceInfo<TaprootScriptTree>,
    ) -> Result<TapretSourceInfo<TaprootScriptTree>, TapretProofError> {
        let tap_tree = modified_tree
            .0
            .as_ref()
            .cloned()
            .ok_or(TapretProofError::EmptyTree)?;

        match self.partner_node {
            // Taproot has key-only spending
            None => Ok(TapretSourceInfo(None)),
            // Taproot has script spendings
            Some(_) => {
                let (original_tree, _) = tap_tree.split()?;
                Ok(TapretSourceInfo(Some(original_tree)))
            }
        }
    }
}

impl EmbedCommitVerify<lnpbp4::CommitmentHash, Lnpbp6>
    for TapretSourceInfo<TaprootScriptTree>
{
    type Proof = TapretPathProof;
    type CommitError = TapretSourceError;
    type VerifyError = TapretProofError;

    fn embed_commit(
        &mut self,
        msg: &lnpbp4::CommitmentHash,
    ) -> Result<Self::Proof, Self::CommitError> {
        for nonce in 0..=u8::MAX {
            let commitment_script = TapScript::commit(&(*msg, nonce));

            let commitment_node =
                TreeNode::with_tap_script(commitment_script, 0);
            let commitment_subtree = TaprootScriptTree::with(commitment_node)
                .expect("invalid commitment node construction");

            let tap_tree = if let Some(ref mut tap_tree) = self.0 {
                tap_tree
            } else {
                self.0 = Some(commitment_subtree);
                return Ok(TapretPathProof::new());
            };

            let original_tree = tap_tree.clone();
            *tap_tree =
                original_tree.join(commitment_subtree, DfsOrder::Last)?;

            let branch = tap_tree
                .as_root_node()
                .as_branch()
                .expect("instill algorithm is broken");
            let partner = branch.as_dfs_child_node(DfsOrder::First);

            let partner_is_left_node =
                branch.dfs_ordering() == DfsOrdering::LeftRight;

            let partner_proof = match (partner_is_left_node, partner) {
                (true, node) => TapretNodePartner::LeftNode(node.node_hash()),
                (false, TreeNode::Leaf(script, _)) => {
                    TapretNodePartner::RightLeaf(script.clone())
                }
                (false, TreeNode::Hidden(partner_hash, _)) => {
                    return Err(TapretSourceError::HiddenNode(
                        *partner_hash,
                        vec![DfsOrder::First].into(),
                    ))
                }
                (false, TreeNode::Branch(partner_branch, _)) => {
                    TapretNodePartner::right_branch(
                        partner_branch.as_left_node().node_hash(),
                        partner_branch.as_right_node().node_hash(),
                    )
                }
            };

            if partner_is_left_node || nonce == u8::MAX {
                return TapretPathProof::with(partner_proof, nonce)
                    .map_err(TapretSourceError::from);
            }
        }
        unreachable!("for cycle always returns before exiting")
    }
}

impl EmbedCommitProof<lnpbp4::CommitmentHash, TapretSourceInfo<TapTree>, Lnpbp6>
    for TapretPathProof
{
    fn restore_original_container(
        &self,
        modified_container: &TapretSourceInfo<TapTree>,
    ) -> Result<TapretSourceInfo<TapTree>, TapretProofError> {
        EmbedCommitProof::<
            _,
            TapretSourceInfo<TaprootScriptTree>,
            _,
        >::restore_original_container(
            self, &modified_container.into()
        ).map(TapretSourceInfo::into)
    }
}

impl EmbedCommitVerify<lnpbp4::CommitmentHash, Lnpbp6>
    for TapretSourceInfo<TapTree>
{
    type Proof = TapretPathProof;
    type CommitError = TapretSourceError;
    type VerifyError = TapretProofError;

    fn embed_commit(
        &mut self,
        msg: &lnpbp4::CommitmentHash,
    ) -> Result<Self::Proof, Self::CommitError> {
        let mut source = TapretSourceInfo::<TaprootScriptTree>::from(
            self as &TapretSourceInfo<_>,
        );
        let proof = source.embed_commit(msg)?;
        *self = source.into();
        Ok(proof)
    }
}
