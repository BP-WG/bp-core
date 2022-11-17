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

//! Taproot OP_RETURN-based deterministic bitcoin commitment scheme ("tapret").
//!
//! **Embed-commit by constructor:**
//! a) `TapTree, Msg -> TapTree', TapRightPartner`, defined in `taptree` mod;
//! b) `(psbt::Output, TxOut), Msg -> (psbt::Output, TxOut)', TapretProof`,
//!    defined in `output` mod;
//! c) `PSBT, Msg -> PSBT', TapretProof`, defined in `psbt` mod;
//! **Convolve-commit by receiver:**
//! d) `UntweakedPublicKey, TapRightPartner, Msg -> TweakedPublicKey'` in
//!    `xonlypk`;
//! e) `PubkeyScript, TapretProof, Msg -> PubkeyScript'` in `scriptpk`;
//! f) `TxOut, TapretProof, Msg -> TxOut'` in `txout`;
//! g) `Tx, TapretProof, Msg -> Tx'` in `tx`.
//!
//! **Verify by constructor:**
//! a) `TapRightPartner, Msg, TapTree' -> bool`;
//! b) `TapretProof, Msg, (psbt::Output, TxOut)' -> bool`;
//! c) `TapretProof, Msg, PSBT' -> bool`.
//! **Verify by receiver:**
//! d) `TweakedPublicKey, TapretProof, Msg -> bool`;
//! e) `PubkeyScript', TapretProof, Msg -> bool`;
//! f) `TxOut', TapretProof, Msg -> bool`;
//! g) `Tx', TapretProof, Msg -> bool`.
//!
//! **Find:** `descriptor::Tr<PublicKey> + TapretTweak -> descriptor::Tapret`
//!
//! **Spend:** `TapretTweak + ControlBlock -> ControlBlock'`
//!
//! Find & spend procedures are wallet-specific, embed-commit and verify -
//! are not.
//!
//! **Possible data type conversions:**
//! - `TapTree', UntweakedPublicKey -> TweakedPublicKey'`
//! - `TapRightPartner, UntweakedPublicKey -> TweakedPublicKey`
//! - `TapRightPartner, Msg -> TapretTweak`
//! - `TapretProof, Msg -> TweakedPublicKey'`
//!
//! **Embed-commitment containers and proofs (container/proof):**
//! a) `TapTree` / `TapRightPartner`
//! b) `TapretProof` / `TweakedPublicKey'`
//! b) `XOnlyPublicKey` / `TapretProof`

#[cfg(feature = "wallet")]
mod psbtout;
mod tapscript;
mod taptree;
mod tx;
mod txout;
mod xonlypk;

#[cfg(feature = "wallet")]
pub use psbtout::{PsbtCommitError, PsbtVerifyError};
pub use tapscript::TAPRET_SCRIPT_COMMITMENT_PREFIX;
pub use taptree::TapretTreeError;
pub use tx::TapretError;

/// Marker non-instantiable enum defining LNPBP-6 taproot OP_RETURN (`tapret`)
/// protocol.
pub enum Lnpbp6 {}

use std::io::Read;

use bitcoin::hashes::sha256::Midstate;
use bitcoin::hashes::Hash;
use bitcoin::schnorr::UntweakedPublicKey;
use bitcoin::util::taproot::{TapBranchHash, TaprootMerkleBranch};
use bitcoin::Script;
use bitcoin_scripts::taproot::TreeNode;
use bitcoin_scripts::{IntoNodeHash, LeafScript, PubkeyScript, TapNodeHash};
use commit_verify::CommitmentProtocol;
use confined_encoding::{self, ConfinedDecode};
use secp256k1::SECP256K1;

impl CommitmentProtocol for Lnpbp6 {
    // TaggedHash("LNPBP6")
    const HASH_TAG_MIDSTATE: Option<Midstate> = Some(Midstate([
        38, 117, 83, 113, 201, 197, 124, 94, 152, 111, 62, 165, 154, 239, 157,
        166, 10, 195, 217, 29, 15, 182, 55, 211, 190, 230, 184, 41, 241, 198,
        65, 54,
    ]));
}

/// Errors in constructing tapret path proof [`TapretPathProof`].
#[derive(Clone, Eq, PartialEq, Hash, Debug, Display, Error)]
#[display(doc_comments)]
pub enum TapretPathError {
    /// the length of the constructed tapret path proof exceeds taproot path
    /// length limit.
    MaxDepthExceeded,

    /// the node partner {0} at the level 1 can't be proven not to contain an
    /// alternative tapret commitment.
    InvalidNodePartner(TapretNodePartner),
}

/// Rigt-side hashing partner in the taproot script tree, used by
/// [`TapretNodePartner::RightBranch`] to ensure correct consensus ordering of
/// the child elements.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[derive(ConfinedEncode)]
#[display("{left_node_hash}:{right_node_hash}")]
pub struct TapretRightBranch {
    left_node_hash: TapNodeHash,
    right_node_hash: TapNodeHash,
}

impl TapretRightBranch {
    /// Constructs [`TapretRightBranch`] by putting `a` and `b` branches hashes
    /// into the correct consensus order (i.e. lexicographically).
    pub fn with(a: TapNodeHash, b: TapNodeHash) -> TapretRightBranch {
        let (left, right) = if a < b { (a, b) } else { (b, a) };
        TapretRightBranch {
            left_node_hash: left,
            right_node_hash: right,
        }
    }

    /// Returns hash of the left-side child node of the branch (having smaller
    /// hash value).
    #[inline]
    pub fn left_node_hash(self) -> TapNodeHash { self.left_node_hash }

    /// Returns hash of the right-side child node of the branch (having smaller
    /// hash value).
    #[inline]
    pub fn right_node_hash(self) -> TapNodeHash { self.right_node_hash }

    /// Computes node hash of the partner node defined by this proof.
    pub fn node_hash(&self) -> TapNodeHash {
        TapBranchHash::from_node_hashes(
            self.left_node_hash,
            self.right_node_hash,
        )
        .into_node_hash()
    }
}

impl ConfinedDecode for TapretRightBranch {
    fn confined_decode<D: Read>(
        mut d: D,
    ) -> Result<Self, confined_encoding::Error> {
        let left_node_hash = ConfinedDecode::confined_decode(&mut d)?;
        let right_node_hash = ConfinedDecode::confined_decode(d)?;
        if left_node_hash > right_node_hash {
            Err(confined_encoding::Error::DataIntegrityError(s!(
                "non-cosensus ordering of hashes in TapretRightBranch"
            )))
        } else {
            Ok(TapretRightBranch {
                left_node_hash,
                right_node_hash,
            })
        }
    }
}

/// Information proving step of a tapret path in determined way within a given
/// original [`bitcoin::psbt::TapTree`].
///
/// The structure hosts proofs that the right-side partner at the taproot script
/// tree node does not contain an alternative OP-RETURN commitment script.
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, From)]
#[derive(ConfinedEncode, ConfinedDecode)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[display(inner)]
pub enum TapretNodePartner {
    /// Tapret commitment is on the right side of the tree; i.e the node
    /// hashing partner can't contain an alternative commitment.
    LeftNode(TapNodeHash),

    /// Single script spending path was present before tapret commitment, which
    /// becomes a second leaf at level 1.
    #[from]
    RightLeaf(LeafScript),

    /// Multiple script spending paths were present; or a single script
    /// spending path should be hidden from revealing the script in the proof.
    ///
    /// To prove that the 1-nd level branch is not a script leafs containing
    /// an alternative OP_RETURN commitment we have to reveal the presence of
    /// two level 2 structures underneath.
    RightBranch(TapretRightBranch),
}

impl TapretNodePartner {
    /// Constructs right-side tapret branch proof structuring `a` and `b`
    /// children node hashes in the correct consensus order (i.e.
    /// lexicographically).
    pub fn right_branch(a: TapNodeHash, b: TapNodeHash) -> TapretNodePartner {
        TapretNodePartner::RightBranch(TapretRightBranch::with(a, b))
    }

    /// Checks that the sibling data does not contain another tapret commitment.
    ///
    /// The check ensures that if the sibling data are present, their first 32
    /// bytes are not equal to [`TAPRET_SCRIPT_COMMITMENT_PREFIX`], and if
    /// the sibling is another node, the hash of its first child in the proof
    /// is smaller than the hash of the other.
    pub fn check_no_commitment(&self) -> bool {
        match self {
            TapretNodePartner::LeftNode(_) => true,
            TapretNodePartner::RightLeaf(LeafScript { script, .. })
                if script.len() < 32 =>
            {
                true
            }
            TapretNodePartner::RightLeaf(LeafScript { script, .. }) => {
                script[0..32] != TAPRET_SCRIPT_COMMITMENT_PREFIX[..]
            }
            TapretNodePartner::RightBranch(right_branch) => {
                right_branch.left_node_hash()[..]
                    != TAPRET_SCRIPT_COMMITMENT_PREFIX[..]
            }
        }
    }

    /// Checks that the sibling has a correct ordering regarding some other
    /// node.
    pub fn check_ordering(&self, other_node: TapNodeHash) -> bool {
        match self {
            TapretNodePartner::LeftNode(left_node) => *left_node <= other_node,
            TapretNodePartner::RightLeaf(leaf_script) => {
                let right_node = leaf_script.tap_leaf_hash().into_node_hash();
                other_node <= right_node
            }
            TapretNodePartner::RightBranch(right_branch) => {
                let right_node = right_branch.node_hash();
                other_node <= right_node
            }
        }
    }

    /// Computes node hash of the partner node defined by this proof.
    pub fn node_hash(&self) -> TapNodeHash {
        match self {
            TapretNodePartner::LeftNode(hash) => *hash,
            TapretNodePartner::RightLeaf(leaf_script) => {
                leaf_script.tap_leaf_hash().into_node_hash()
            }
            TapretNodePartner::RightBranch(right_branch) => {
                right_branch.node_hash()
            }
        }
    }

    /// Constructs [`TreeNode`] for the node partner.
    pub fn to_tree_node(&self) -> TreeNode {
        match self {
            TapretNodePartner::LeftNode(left_node) => {
                TreeNode::Hidden(*left_node, 1)
            }
            TapretNodePartner::RightLeaf(leaf_script) => {
                TreeNode::Leaf(leaf_script.clone(), 0)
            }
            TapretNodePartner::RightBranch(partner_branch) => {
                TreeNode::Hidden(partner_branch.node_hash(), 1)
            }
        }
    }
}

/// Structure proving that a merkle path to the tapret commitment inside the
/// taproot script tree does not have an alternative commitment.
///
/// Holds information about the sibling at level 1 of the tree in form of
/// [`TapretNodePartner`].
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Default)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[derive(ConfinedEncode, ConfinedDecode)]
pub struct TapretPathProof {
    /// Information about the sibling at level 1 of the tree
    partner_node: Option<TapretNodePartner>,

    /// A nonce value used to put the tapret commitment into the right side of
    /// the tree.
    nonce: u8,
}

impl TapretPathProof {
    /// Construct new empty path proof.
    #[inline]
    pub fn new() -> TapretPathProof { TapretPathProof::default() }

    /// Adds element to the path proof.
    pub fn with(
        elem: TapretNodePartner,
        nonce: u8,
    ) -> Result<TapretPathProof, TapretPathError> {
        if !elem.check_no_commitment() {
            return Err(TapretPathError::InvalidNodePartner(elem));
        }
        Ok(TapretPathProof {
            partner_node: Some(elem),
            nonce,
        })
    }

    /// Checks that the sibling data does not contain another tapret commitment
    /// for any step of the mekrle path.
    #[inline]
    pub fn check_no_commitment(&self) -> bool {
        self.partner_node
            .as_ref()
            .map(TapretNodePartner::check_no_commitment)
            .unwrap_or(true)
    }

    /// Returns original merkle root of the tree before deterministic bitcoin
    /// commitment. If originally there was no script path spendings, returns
    /// `None`.
    #[inline]
    pub fn original_merkle_root(&self) -> Option<TapNodeHash> {
        self.partner_node
            .as_ref()
            .map(|partner| partner.node_hash())
    }
}

/*

impl IntoIterator for TapretPathProof {
    type Item = TapretNodePartner;
    type IntoIter = std::vec::IntoIter<TapretNodePartner>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'data> IntoIterator for &'data TapretPathProof {
    type Item = TapretNodePartner;
    type IntoIter = core::slice::Iter<'data, TapretNodePartner>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

 */

/// Information proving tapret determinism for a given tapret commitment.
/// Used both in the commitment procedure for PSBTs and in
/// client-side-validation of the commitment.
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[derive(ConfinedEncode, ConfinedDecode)]
pub struct TapretProof {
    /// A merkle path to the commitment inside the taproot script tree. For
    /// each node it also must hold information about the sibling in form of
    /// [`TapretNodePartner`].
    pub path_proof: TapretPathProof,

    /// The internal key used by the taproot output.
    ///
    /// We need to keep this information client-side since it can't be
    /// retrieved from the mined transaction.
    pub internal_key: UntweakedPublicKey,
}

impl TapretProof {
    /// Restores original scripPubkey before deterministic bitcoin commitment
    /// applied.
    #[inline]
    pub fn original_pubkey_script(&self) -> PubkeyScript {
        let merkle_root = self
            .path_proof
            .original_merkle_root()
            .map(TapNodeHash::into_inner)
            .map(TapBranchHash::from_inner);
        Script::new_v1_p2tr(SECP256K1, self.internal_key, merkle_root).into()
    }
}

/// Tapret value: a final tweak applied to the internal taproot key which
/// includes commitment to both initial taptree merkle root and the OP_RETURN
/// commitment branch. Represents the taptree merkle root of the modified
/// taptree.
#[derive(Wrapper, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[derive(ConfinedEncode, ConfinedDecode)]
pub struct TapretTweak(TaprootMerkleBranch);

#[cfg(test)]
mod test {
    use amplify::Wrapper;
    use commit_verify::tagged_hash;

    use super::*;

    #[test]
    fn test_lnpbp6_midstate() {
        let midstate = tagged_hash::Midstate::with(b"LNPBP6");
        assert_eq!(
            midstate.into_inner().into_inner(),
            Lnpbp6::HASH_TAG_MIDSTATE.unwrap().into_inner()
        );
    }
}
