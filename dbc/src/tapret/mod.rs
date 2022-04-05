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
//! a) `TapTree, Msg -> TapTree', TapRightPartner`, defined in [`taptree`] mod;
//! b) `(psbt::Output, TxOut), Msg -> (psbt::Output, TxOut)', TapretProof`,
//!    defined in [`output`] mod;
//! c) `PSBT, Msg -> PSBT', TapretProof`, defined in [`psbt`] mod;
//! **Convolve-commit by receiver:**
//! d) `UntweakedPublicKey, TapRightPartner, Msg -> TweakedPublicKey'` in
//!    [`xonlypk`];
//! e) `PubkeyScript, TapretProof, Msg -> PubkeyScript'` in [`scriptpk`];
//! f) `TxOut, TapretProof, Msg -> TxOut'` in [`txout`];
//! g) `Tx, TapretProof, Msg -> Tx'` in [`tx`].
//!
//! **Verify by constructor:**
//! a) `TapRightPartner, Msg, TapTree' -> bool`;
//! b) `TapretProof, Msg, (psbt::Output, TxOut)' -> bool`;
//! c) `TapretProof, Msg, PSBT' -> bool`.
//! **Verify by receiver:**
//! d) `UntweakedPublicKey, TapRightPartner, Msg, TweakedPublicKey -> bool`;
//! e) `PubkeyScript, TapretProof, Msg, PubkeyScript' -> bool`;
//! f) `TxOut, TapretProof, Msg, TxOut' -> bool`;
//! g) `Tx, TapretProof, Msg -> Tx'`.
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

mod psbt;
mod psbtout;
mod scriptpk;
mod tapscript;
mod taptree;
mod tx;
mod txout;
mod xonlypk;

pub use psbtout::{PsbtCommitError, PsbtVerifyError};
pub use tapscript::TAPRET_SCRIPT_COMMITMENT_PREFIX;
pub use taptree::TapretTreeError;
pub use tx::TapretError;

/// Marker non-instantiable enum defining LNPBP-6 taproot OP_RETURN (`tapret`)
/// protocol.
pub enum Lnpbp6 {}

use core::ops::Deref;
use std::io::Read;

use bitcoin::hashes::sha256::Midstate;
use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::schnorr::UntweakedPublicKey;
use bitcoin::util::taproot::{
    TapBranchHash, TaprootMerkleBranch, TAPROOT_CONTROL_MAX_NODE_COUNT,
};
use bitcoin_scripts::{IntoNodeHash, LeafScript, TapNodeHash};
use commit_verify::CommitmentProtocol;
use strict_encoding::{self, StrictDecode};

impl CommitmentProtocol for Lnpbp6 {
    // TODO: Set up proper midstate value for LNPBP6
    const HASH_TAG_MIDSTATE: Option<Midstate> = None;
}

/// Errors in constructing tapret path proof [`TapretPathProof`].
#[derive(Clone, Eq, PartialEq, Hash, Debug, Display, Error)]
#[display(doc_comments)]
pub enum TapretPathError {
    /// the length of the constructed tapret path proof exceeds taproot path
    /// length limit.
    MaxDepthExceeded,

    /// the node partner {1} at the level {0} can't be proven not to contain an
    /// alternative tapret commitment.
    InvalidNodePartner(u8, TapretNodePartner),
}

/// Rigt-side hashing partner in the taproot script tree, used by
/// [`TapretNodePartner::RightBranch`] to ensure correct consensus ordering of
/// the child elements.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[derive(StrictEncode)]
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
        let mut engine = TapBranchHash::engine();
        engine.input(&self.left_node_hash.min(self.right_node_hash));
        engine.input(&self.left_node_hash.max(self.right_node_hash));
        TapNodeHash::from_engine(engine)
        /* TODO: Replace with:
        TapBranchHash::from_node_hashes(
            self.left_node_hash,
            self.right_node_hash,
        )
         */
    }
}

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

/// Information proving step of a tapret path in determined way within a given
/// original [`TapTree`].
///
/// The structure hosts proofs that the right-side partner at the taproot script
/// tree node does not contain an alternative OP-RETURN commitment script.
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, From)]
#[derive(StrictEncode, StrictDecode)]
#[display(inner)]
pub enum TapretNodePartner {
    /// Script spending path on the right side of the parent node is absent;
    /// tapret commitment represented by a single leaf or is sitra ahra: it
    /// exists on the left side of the tree.
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
    pub fn check(&self) -> bool {
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
}

/// Structure proving that a merkle path to the tapret commitment inside the
/// taproot script tree does not have an alternative commitment.
///
/// For each node holds information about the sibling in form of
/// [`TapRightPartner`].
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Default)]
pub struct TapretPathProof(Vec<TapretNodePartner>);

impl Deref for TapretPathProof {
    type Target = Vec<TapretNodePartner>;

    #[inline]
    fn deref(&self) -> &Self::Target { &self.0 }
}

impl TapretPathProof {
    /// Construct new empty path proof.
    #[inline]
    pub fn new() -> TapretPathProof { TapretPathProof::default() }

    /// Adds element to the path proof.
    pub fn push(
        &mut self,
        elem: TapretNodePartner,
    ) -> Result<u8, TapretPathError> {
        if self.len() > TAPROOT_CONTROL_MAX_NODE_COUNT {
            return Err(TapretPathError::MaxDepthExceeded);
        }
        if !elem.check() {
            return Err(TapretPathError::InvalidNodePartner(
                self.len() as u8,
                elem,
            ));
        }
        self.0.push(elem);
        return Ok(self.0.len() as u8);
    }

    /// Checks that the sibling data does not contain another tapret commitment
    /// for any step of the mekrle path.
    #[inline]
    pub fn check(&self) -> bool { self.0.iter().all(TapretNodePartner::check) }
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
pub struct TapretProof {
    /// A merkle path to the commitment inside the taproot script tree. For
    /// each node it also must hold information about the sibling in form of
    /// [`TapRightPartner`].
    pub path_proof: TapretPathProof,

    /// The internal key used by the taproot output.
    ///
    /// We need to keep this information client-side since it can't be
    /// retrieved from the mined transaction.
    pub internal_key: UntweakedPublicKey,
}

/// Tapret value: a final tweak applied to the internal taproot key which
/// includes commitment to both initial taptree merkle root and the OP_RETURN
/// commitment branch. Represents the taptree merkle root of the modified
/// taptree.
#[derive(Wrapper, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[derive(StrictEncode, StrictDecode)]
pub struct TapretTweak(TaprootMerkleBranch);
