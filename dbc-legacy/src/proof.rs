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

use amplify::{Slice32, Wrapper};
use bitcoin::hashes::sha256;

use crate::Error;

/// Extra-transaction proof of a deterministic bitcoin commitment.
///
/// Encodes only extra-transaction data in the most compact form; without
/// information on which specific commitment type is used. The commitment type
/// must be determined by the protocol data and transaction structure.
///
/// Proof does not stores the actual key data internally not to consume
/// resources on validating elliptic key points each time the proof is
/// deserialized (client-side-validated data may contain many thousands of
/// proofs and such validation may significantly reduce performance).
#[derive(Clone, PartialEq, Eq, Hash, Debug, Display)]
#[derive(ConfinedEncode, ConfinedDecode)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[display("proof({pubkey}, {source}")]
pub enum Proof {
    /// No extra-transaction data are required
    #[strict_encoding(value = 0x01)]
    Embedded,

    /// Extra-transaction proof consists of a single public key.
    ///
    /// This variant covers even public keys, prefixed with `0x02` as a part of
    /// the proof type data.
    #[strict_encoding(value = 0x02)]
    EvenKey(Slice32),

    /// Extra-transaction proof consists of a single public key.
    ///
    /// This variant covers odd public keys, prefixed with `0x03` as a part of
    /// the proof type data.
    #[strict_encoding(value = 0x03)]
    OddKey(Slice32),

    // 0x04 encoding is skipped to distinguish with a stored uncompressed keys
    /// Extra-transaction proof consists of a single public key as a part of
    /// P2WPKH-in-P2SH nested legacy structure.
    ///
    /// This variant covers even public keys.
    #[strict_encoding(value = 0x05)]
    NestedEvenKey(Slice32),

    /// Extra-transaction proof consists of a single public key as a part of
    /// P2WPKH-in-P2SH nested legacy structure.
    ///
    /// This variant covers odd public keys.
    #[strict_encoding(value = 0x06)]
    NestedOddKey(Slice32),

    /// Extra-transaction proof consists of a single public key and script.
    ///
    /// This variant covers even public keys.
    #[strict_encoding(value = 0x07)]
    ScriptEvenKey {
        target_key: Slice32,
        script: Box<[u8]>,
    },

    /// Extra-transaction proof consists of a single public key and script.
    ///
    /// This variant covers odd public keys.
    #[strict_encoding(value = 0x08)]
    ScriptOddKey {
        target_key: Slice32,
        script: Box<[u8]>,
    },

    /// Extra-transaction proof consists of a single public key and witness
    /// script structured as P2WSH-in-P2SH nested legacy structure.
    ///
    /// This variant covers even public keys.
    #[strict_encoding(value = 0x09)]
    NestedScriptEvenKey {
        target_key: Slice32,
        script: Box<[u8]>,
    },

    /// Extra-transaction proof consists of a single public key and witness
    /// script structured as P2WSH-in-P2SH nested legacy structure.
    ///
    /// This variant covers odd public keys.
    #[strict_encoding(value = 0x10)]
    NestedScriptOddKey {
        target_key: Slice32,
        script: Box<[u8]>,
    },

    /// Extra-transaction proof consists of a taproot internal public key and
    /// a merkle proof for a second branch of the merkle tree in the taproot
    /// script tree.
    #[strict_encoding(value = 0x11)]
    XOnlyKeyTaproot {
        internal_key: Slice32,
        merkle_subroot: sha256::Hash,
    },
}

impl From<secp256k1::PublicKey> for Proof {
    fn from(pubkey: secp256k1::PublicKey) -> Self {
        let data = pubkey.serialize();
        let inner =
            Slice32::from_slice(&data[1..]).expect("fixed-length slice");
        match data[0] {
            0x02 => Proof::EvenKey(inner),
            0x03 => Proof::OddKey(inner),
            _ => unreachable!(
                "Secp256k1 public key with non-0x02 and non-0x03 prefix"
            ),
        }
    }
}

impl Proof {
    pub fn public_key(&self) -> Result<secp256k1::PublicKey, Error> {
        let mut data: Vec<u8> = Vec::with_capacity(32);

        match self {
            Proof::Embedded => return Err(Error::InvalidProofStructure),
            Proof::EvenKey(pk)
            | Proof::NestedEvenKey(pk)
            | Proof::ScriptEvenKey { target_key: pk, .. }
            | Proof::NestedScriptEvenKey { target_key: pk, .. }
            | Proof::XOnlyKeyTaproot {
                internal_key: pk, ..
            } => {
                data.extend([0x02]);
                data.extend(pk.as_inner());
            }
            Proof::OddKey(pk)
            | Proof::NestedOddKey(pk)
            | Proof::ScriptOddKey { target_key: pk, .. }
            | Proof::NestedScriptOddKey { target_key: pk, .. } => {
                data.extend([0x03]);
                data.extend(pk.as_inner());
            }
        }

        Ok(secp256k1::PublicKey::from_slice(&data)
            .expect("fixed-size public key"))
    }
}
