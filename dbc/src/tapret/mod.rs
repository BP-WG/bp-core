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

pub use psbtout::TapretPsbtError;
pub use tapscript::TAPRET_SCRIPT_COMMITMENT_PREFIX;
pub use taptree::TapretTreeError;
pub use tx::TapretError;

/// Marker non-instantiable enum defining LNPBP-6 taproot OP_RETURN (`tapret`)
/// protocol.
pub enum Lnpbp6 {}

use bitcoin::hashes::sha256::{self, Midstate};
use bitcoin::schnorr::UntweakedPublicKey;
use bitcoin::util::taproot::{TapBranchHash, TaprootMerkleBranch};
use bitcoin_scripts::LeafScript;
use commit_verify::CommitmentProtocol;

impl CommitmentProtocol for Lnpbp6 {
    // TODO: Set up proper midstate value for LNPBP6
    const HASH_TAG_MIDSTATE: Option<Midstate> = None;
}

/// Information proving stap of a tapret path in determined way within a given
/// original [`TapTree`].
///
/// The structure hosts proofs that the right-side partner at the taproot script
/// tree node does not contain an alternative OP-RETURN commitment script.
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, From)]
#[derive(StrictEncode, StrictDecode)]
pub enum TapRightPartner {
    /// Script spending path on the right side of the parent node is absent;
    /// tapret commitment represented by a single leaf or is sitra ahra: it
    /// exists on the left side of the tree.
    #[display("~")]
    None,

    /// Single script spending path was present before tapret commitment, which
    /// becomes a second leaf at level 1.
    #[from]
    #[display(inner)]
    Leaf(LeafScript),

    /// Multiple script spending paths were present; or a single script
    /// spending path should be hidden from revelaing the script in the
    /// proof.
    ///
    /// To prove that the 1-nd level branch is not a script leafs containing
    /// an alternative OP_RETURN commitment we have to reveal the presence of
    /// two level 2 structures underneath.
    #[display(inner)]
    Branch(sha256::Hash, sha256::Hash),
}

impl TapRightPartner {
    /// Checks that the sibling data does not contain another tapret commitment.
    ///
    /// The check ensures that if the sibling data are present, their first 32
    /// bytes are not equal to [`TAPRET_SCRIPT_COMMITMENT_PREFIX`], and if
    /// the sibling is another node, the hash of its first child in the proof
    /// is smaller than the hash of the other.
    pub fn check(&self) -> bool {
        match self {
            TapRightPartner::None => true,
            TapRightPartner::Leaf(LeafScript { script, .. })
                if script.len() < 32 =>
            {
                true
            }
            TapRightPartner::Leaf(LeafScript { script, .. }) => {
                script[0..32] != TAPRET_SCRIPT_COMMITMENT_PREFIX[..]
            }
            TapRightPartner::Branch(left_hash, right_hash)
                if right_hash < left_hash =>
            {
                false
            }
            TapRightPartner::Branch(left_hash, _) => {
                left_hash[..] != TAPRET_SCRIPT_COMMITMENT_PREFIX[..]
            }
        }
    }
}

/// Information proving tapret determinism for a given tapret commitment.
/// Used both in the commitment procedure for PSBTs and in
/// client-side-validation of the commitment.
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct TapretProof {
    /// A merkle path to the commitment inside the taproot script tree. For
    /// each node it also must hold information about the sibling in form of
    /// [`TapRightPartner`].
    pub merkle_path: Vec<(TapBranchHash, TapRightPartner)>,

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
