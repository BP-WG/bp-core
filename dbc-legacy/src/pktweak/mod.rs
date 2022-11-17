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

#[cfg(feature = "miniscript")]
pub mod keyset;
pub mod lnpbp1;
#[cfg(feature = "miniscript")]
pub mod lockscript;
pub mod pubkey;
#[cfg(feature = "miniscript")]
pub mod scriptpubkey;
pub mod taproot;
#[cfg(feature = "miniscript")]
pub mod txout;

use bitcoin::hashes::sha256;
use bitcoin_scripts::LockScript;
#[cfg(feature = "miniscript")]
pub use keyset::{KeysetCommitment, KeysetContainer};
#[cfg(feature = "miniscript")]
pub use lockscript::{LockscriptCommitment, LockscriptContainer};
pub use pubkey::{PubkeyCommitment, PubkeyContainer};
#[cfg(feature = "miniscript")]
pub use scriptpubkey::{
    ScriptEncodeData, ScriptEncodeMethod, SpkCommitment, SpkContainer,
};
pub use taproot::{TaprootCommitment, TaprootContainer};
#[cfg(feature = "miniscript")]
pub use txout::{TxoutCommitment, TxoutContainer};

/// Structure keeping the minimum of information (bytewise) required to verify
/// deterministic bitcoin commitment given only the transaction source, its
/// fee and protocol-specific constants. It is a part of the [`Proof`] data.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Display)]
#[derive(ConfinedEncode, ConfinedDecode)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[display(doc_comments)]
pub enum ScriptEncodeData {
    /// Public key. Since we keep the original public key as a part of a proof,
    /// and value of the tweaked key can be reconstructed with DBC source data
    /// and the original pubkey, so we do not need to keep any additional data
    /// here).
    SinglePubkey,

    /// Any output containing script information, aside from OP_RETURN outputs
    /// (using [`ScriptEncodeData::SinglePubkey`]) and tapscript.
    /// We have to store full original script in it's byte form since when
    /// the deteministic bitcoin commitment is verified, the output may be
    /// still unspent and we will not be able to reconstruct the script without
    /// this data kept in the client-validated part.
    LockScript(LockScript),

    // TODO: Add `WrappedWitnessScript(WitnessScript) variant
    /// Taproot-based outputs. We need to keep only the hash of the taprscript
    /// merkle tree root.
    Taproot(sha256::Hash),
}
