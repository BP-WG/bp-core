// BP Core Library implementing LNP/BP specifications & standards related to
// bitcoin protocol
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

use amplify::DumbDefault;
use bitcoin::secp256k1;

use super::{Error, ScriptEncodeData};

pub trait Container: Sized {
    type Supplement;
    type Host;

    fn reconstruct(
        proof: &Proof,
        supplement: &Self::Supplement,
        host: &Self::Host,
    ) -> Result<Self, Error>;

    fn deconstruct(self) -> (Proof, Self::Supplement);

    fn to_proof(&self) -> Proof;
    fn into_proof(self) -> Proof;
}

#[derive(Clone, PartialEq, Eq, Hash, Debug, Display)]
#[derive(StrictEncode, StrictDecode)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[display("proof({pubkey}, {source}")]
pub struct Proof {
    pub pubkey: secp256k1::PublicKey,
    pub source: ScriptEncodeData,
}

impl DumbDefault for Proof {
    fn dumb_default() -> Self {
        Proof {
            pubkey: secp256k1::PublicKey::from_secret_key(
                secp256k1::SECP256K1,
                &secp256k1::key::ONE_KEY,
            ),
            source: Default::default(),
        }
    }
}

impl From<secp256k1::PublicKey> for Proof {
    fn from(pubkey: secp256k1::PublicKey) -> Self {
        Self {
            pubkey,
            source: ScriptEncodeData::SinglePubkey,
        }
    }
}
