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

use core::fmt::Debug;
use core::hash::Hash;

use bitcoin::psbt::{IncompleteTapTree, TapTree};
use bitcoin::util::taproot::TaprootBuilderError;
use bitcoin_scripts::taproot::{
    Branch, CutError, DfsOrder, DfsOrdering, DfsPath, DfsTraversalError,
    InstillError, MaxDepthExceeded, Node, TaprootScriptTree, TreeNode,
};
use bitcoin_scripts::{taproot, LeafScript, TapNodeHash, TapScript};
use commit_verify::multi_commit::MultiCommitment;
use commit_verify::{CommitVerify, EmbedCommitProof, EmbedCommitVerify};

use super::{Lnpbp6, TapretNodePartner, TapretPathProof};
use crate::tapret::TapretPathError;

// TODO: Re-check the use of all error variants
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
    TreeBuilder(IncompleteTapTree),

    /// the tapret commitment can't be performet since the taproot script
    /// tree already has maximal depth.
    #[from(MaxDepthExceeded)]
    MaxDepthExceeded,

    /// the provided taproot script tree has no revealed nodes to prove the
    /// commitment.
    IncompleteTree(TaprootScriptTree),

    /// unable to add an invalid tapret node partner information {1} to the
    /// merkle path proof at the level {0}.
    InvalidPartnerProof(u8, TapretNodePartner),
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
#[derive(Clone, PartialOrd, Ord, PartialEq, Eq, Hash, Debug, Display, Error)]
#[display(doc_comments)]
pub enum TapretSourceError {
    /// the length of the constructed tapret path proof exceeds taproot path
    /// length limit.
    MaxDepthExceeded,

    /// the node partner {1} at the level {0} can't be proven not to contain an
    /// alternative tapret commitment.
    InvalidNodePartner(u8, TapretNodePartner),

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
            TapretPathError::InvalidNodePartner(depth, partner) => {
                Self::InvalidNodePartner(depth, partner)
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
pub struct TapretSourceInfo<Tree>
where
    Tree: Clone + Eq + Debug,
{
    /// The concrete tree implementation.
    tap_tree: Option<Tree>,

    /// DFS path which should be used fot instilling tapret commitment.
    dfs_path: DfsPath,
}

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
        dfs_path: DfsPath,
    ) -> Result<Self, TapretSourceError> {
        if let Some(ref tap_tree) = tap_tree {
            match tap_tree.node_at(&dfs_path)? {
                TreeNode::Hidden(hash, _) => {
                    return Err(TapretSourceError::HiddenNode(*hash, dfs_path))
                }
                TreeNode::Leaf(leaf_script, _) => {
                    return Err(TapretSourceError::LeafNode(
                        leaf_script.clone(),
                        dfs_path,
                    ))
                }
                TreeNode::Branch(_, _) => {}
            }
        } else if !dfs_path.is_empty() {
            return Err(TapretSourceError::PathNotExists(dfs_path));
        }
        Ok(TapretSourceInfo { tap_tree, dfs_path })
    }

    /// Returns reference to the script tree root node, if taproot script tree
    /// is present in the source data.
    pub fn as_root_node(&self) -> Option<&TreeNode> {
        self.tap_tree.as_ref().map(TaprootScriptTree::as_root_node)
    }

    /// Releases internal [`TapTree`] data, if present.
    #[inline]
    pub fn into_tap_tree(self) -> Option<TapTree> {
        self.tap_tree.map(TapTree::from)
    }
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
    pub fn with(
        tap_tree: Option<TapTree>,
        dfs_path: DfsPath,
    ) -> Result<Self, TapretSourceError> {
        TapretSourceInfo::<TaprootScriptTree>::with(
            tap_tree.map(TaprootScriptTree::from),
            dfs_path,
        )
        .map(TapretSourceInfo::from)
    }

    /// Releases internal [`TapTree`] data, if present.
    #[inline]
    pub fn into_tap_tree(self) -> Option<TapTree> { self.tap_tree }
}

impl From<&TapretSourceInfo<TapTree>> for TapretSourceInfo<TaprootScriptTree> {
    fn from(source: &TapretSourceInfo<TapTree>) -> Self {
        let tap_tree = source
            .tap_tree
            .as_ref()
            .cloned()
            .map(TaprootScriptTree::from);
        TapretSourceInfo {
            tap_tree,
            dfs_path: source.dfs_path.clone(),
        }
    }
}

impl From<TapretSourceInfo<TaprootScriptTree>> for TapretSourceInfo<TapTree> {
    fn from(source: TapretSourceInfo<TaprootScriptTree>) -> Self {
        let tap_tree = source.tap_tree.map(TapTree::from);
        TapretSourceInfo {
            tap_tree,
            dfs_path: source.dfs_path,
        }
    }
}

impl
    EmbedCommitProof<
        MultiCommitment,
        TapretSourceInfo<TaprootScriptTree>,
        Lnpbp6,
    > for TapretPathProof
{
    fn restore_original_container(
        &self,
        modified_tree: &TapretSourceInfo<TaprootScriptTree>,
    ) -> Result<TapretSourceInfo<TaprootScriptTree>, TapretProofError> {
        let tap_tree = modified_tree
            .tap_tree
            .as_ref()
            .cloned()
            .ok_or(TapretProofError::EmptyTree)?;
        let mut dfs_path = modified_tree.dfs_path.clone();
        // Taproot has key-only spending
        if dfs_path.pop().is_none() {
            return Ok(TapretSourceInfo {
                tap_tree: None,
                dfs_path,
            });
        }
        // Taproot has script spendings
        let (_, original_tree) = tap_tree.cut(&dfs_path, DfsOrder::Last)?;
        Ok(TapretSourceInfo {
            tap_tree: Some(original_tree),
            dfs_path,
        })
    }
}

impl EmbedCommitVerify<MultiCommitment, Lnpbp6>
    for TapretSourceInfo<TaprootScriptTree>
{
    type Proof = TapretPathProof;
    type CommitError = TapretSourceError;
    type VerifyError = TapretProofError;

    fn embed_commit(
        &mut self,
        msg: &MultiCommitment,
    ) -> Result<Self::Proof, Self::CommitError> {
        let commitment_script = TapScript::commit(msg);
        let commitment_node =
            taproot::TreeNode::with_tap_script(commitment_script, 0);
        let commitment_subtree = TaprootScriptTree::with(commitment_node)
            .expect("invalid commitment node construction");

        let tap_tree = if let Some(ref mut tap_tree) = self.tap_tree {
            tap_tree
        } else {
            self.tap_tree = Some(commitment_subtree);
            return Ok(TapretPathProof::new());
        };

        let commitment_path = tap_tree.instill(
            commitment_subtree,
            &self.dfs_path,
            DfsOrder::Last,
        )?;
        tap_tree
            .nodes_on_path(&commitment_path)
            .enumerate()
            .try_fold(
                TapretPathProof::new(),
                |mut path_proof, (index, node)| {
                    let step = commitment_path[index];
                    let branch = node
                        .ok()
                        .and_then(TreeNode::as_branch)
                        .expect("instill algorithm is broken");
                    let partner = branch.as_dfs_child_node(!step);

                    let partner_is_left_node = {
                        (branch.dfs_ordering() == DfsOrdering::LeftRight
                            && step == DfsOrder::Last)
                            || (branch.dfs_ordering() == DfsOrdering::RightLeft
                                && step == DfsOrder::First)
                    };

                    let partner_proof = match (partner_is_left_node, partner) {
                        (true, node) => {
                            TapretNodePartner::LeftNode(node.node_hash())
                        }
                        (false, TreeNode::Leaf(script, _)) => {
                            TapretNodePartner::RightLeaf(script.clone())
                        }
                        (false, TreeNode::Hidden(partner_hash, _)) => {
                            return Err(TapretSourceError::HiddenNode(
                                *partner_hash,
                                DfsPath::with(&commitment_path[..index]),
                            ))
                        }
                        (false, TreeNode::Branch(partner_branch, _)) => {
                            TapretNodePartner::right_branch(
                                partner_branch.as_left_node().node_hash(),
                                partner_branch.as_right_node().node_hash(),
                            )
                        }
                    };
                    path_proof.push(partner_proof)?;
                    Ok(path_proof)
                },
            )
    }
}

impl EmbedCommitProof<MultiCommitment, TapretSourceInfo<TapTree>, Lnpbp6>
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

impl EmbedCommitVerify<MultiCommitment, Lnpbp6> for TapretSourceInfo<TapTree> {
    type Proof = TapretPathProof;
    type CommitError = TapretSourceError;
    type VerifyError = TapretProofError;

    fn embed_commit(
        &mut self,
        msg: &MultiCommitment,
    ) -> Result<Self::Proof, Self::CommitError> {
        let mut source = TapretSourceInfo::<TaprootScriptTree>::from(
            self as &TapretSourceInfo<_>,
        );
        let proof = source.embed_commit(msg)?;
        *self = source.into();
        Ok(proof)
    }
}
