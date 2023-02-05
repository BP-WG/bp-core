// Deterministic bitcoin commitments library.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2023 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2023 LNP/BP Standards Association. All rights reserved.
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

mod tapscript;
mod tx;
mod txout;
mod xonlypk;

pub use bc::LIB_NAME_BP;
pub use tx::TapretError;
pub use xonlypk::TapretKeyError;

/// Marker non-instantiable enum defining LNPBP-12 taproot OP_RETURN (`tapret`)
/// protocol.
pub enum Lnpbp12 {}

use bc::{InternalPk, IntoTapHash, LeafScript, ScriptPubkey, TapBranchHash, TapNodeHash};
use commit_verify::CommitmentProtocol;

pub use self::tapscript::TAPRET_SCRIPT_COMMITMENT_PREFIX;

impl CommitmentProtocol for Lnpbp12 {}

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
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BP)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
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
        TapBranchHash::with_nodes(self.left_node_hash, self.right_node_hash).into_tap_hash()
    }
}

/*
impl StrictDecode for TapretRightBranch {
    fn strict_decode<D: Read>(
        mut d: D,
    ) -> Result<Self, strict_encoding::Error> {
        let left_node_hash = StrictDecode::strict_decode(&mut d)?;
        let right_node_hash = StrictDecode::strict_decode(d)?;
        if left_node_hash > right_node_hash {
            Err(strict_encoding::Error::DataIntegrityError(s!(
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
 */

/// Information proving step of a tapret path in determined way within a given
/// tap tree.
///
/// The structure hosts proofs that the right-side partner at the taproot script
/// tree node does not contain an alternative OP-RETURN commitment script.
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, From)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BP, tags = order, dumb = Self::RightLeaf(default!()))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
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
    /// The check ensures that if the sibling data are present, their first 31
    /// bytes are not equal to [`TAPRET_SCRIPT_COMMITMENT_PREFIX`], and if
    /// the sibling is another node, the hash of its first child in the proof
    /// is smaller than the hash of the other.
    pub fn check_no_commitment(&self) -> bool {
        match self {
            TapretNodePartner::LeftNode(_) => true,
            TapretNodePartner::RightLeaf(LeafScript { script, .. }) if script.len() < 64 => true,
            TapretNodePartner::RightLeaf(LeafScript { script, .. }) => {
                script[..31] != TAPRET_SCRIPT_COMMITMENT_PREFIX[..]
            }
            TapretNodePartner::RightBranch(right_branch) => {
                right_branch.left_node_hash()[..31] != TAPRET_SCRIPT_COMMITMENT_PREFIX[..]
            }
        }
    }

    /// Checks that the sibling has a correct ordering regarding some other
    /// node.
    pub fn check_ordering(&self, other_node: TapNodeHash) -> bool {
        match self {
            TapretNodePartner::LeftNode(left_node) => *left_node <= other_node,
            TapretNodePartner::RightLeaf(leaf_script) => {
                let right_node = leaf_script.tap_leaf_hash().into_tap_hash();
                other_node <= right_node
            }
            TapretNodePartner::RightBranch(right_branch) => {
                let right_node = right_branch.node_hash();
                other_node <= right_node
            }
        }
    }

    /// Computes node hash of the partner node defined by this proof.
    pub fn tap_node_hash(&self) -> TapNodeHash {
        match self {
            TapretNodePartner::LeftNode(hash) => *hash,
            TapretNodePartner::RightLeaf(leaf_script) => {
                leaf_script.tap_leaf_hash().into_tap_hash()
            }
            TapretNodePartner::RightBranch(right_branch) => right_branch.node_hash(),
        }
    }
}

/// Structure proving that a merkle path to the tapret commitment inside the
/// taproot script tree does not have an alternative commitment.
///
/// Holds information about the sibling at level 1 of the tree in form of
/// [`TapretNodePartner`].
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BP)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
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
    pub fn root() -> TapretPathProof {
        TapretPathProof {
            partner_node: None,
            nonce: 0,
        }
    }

    /// Adds element to the path proof.
    pub fn with(elem: TapretNodePartner, nonce: u8) -> Result<TapretPathProof, TapretPathError> {
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
            .map(|partner| partner.tap_node_hash())
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
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BP)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct TapretProof {
    /// A merkle path to the commitment inside the taproot script tree. For
    /// each node it also must hold information about the sibling in form of
    /// [`TapretNodePartner`].
    pub path_proof: TapretPathProof,

    /// The internal key used by the taproot output.
    ///
    /// We need to keep this information client-side since it can't be
    /// retrieved from the mined transaction.
    pub internal_pk: InternalPk,
}

impl TapretProof {
    /// Restores original scripPubkey before deterministic bitcoin commitment
    /// applied.
    #[inline]
    pub fn original_pubkey_script(&self) -> ScriptPubkey {
        let merkle_root = self.path_proof.original_merkle_root();
        ScriptPubkey::p2tr(self.internal_pk, merkle_root)
    }
}
