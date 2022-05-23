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

use amplify::Wrapper;
use bitcoin::hashes::{sha256, Hmac};
use bitcoin::{secp256k1, XOnlyPublicKey};
use commit_verify::EmbedCommitVerify;

use super::{PubkeyCommitment, PubkeyContainer};
use crate::{Container, Error, Proof};

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct TaprootContainer {
    pub script_root: sha256::Hash,
    pub intermediate_key: XOnlyPublicKey,
    /// Single SHA256 hash of the protocol-specific tag
    pub tag: sha256::Hash,
    /// Tweaking factor stored after [`TaprootCommitment::embed_commit`]
    /// procedure
    pub tweaking_factor: Option<Hmac<sha256::Hash>>,
}

impl Container for TaprootContainer {
    /// Out supplement is a protocol-specific tag in its hashed form
    type Supplement = sha256::Hash;
    /// Our proof contains the host, so we don't need host here
    type Host = Option<()>;

    fn reconstruct(
        proof: &Proof,
        supplement: &Self::Supplement,
        _: &Self::Host,
    ) -> Result<Self, Error> {
        match proof {
            Proof::XOnlyKeyTaproot {
                internal_key,
                merkle_subroot,
            } => Ok(Self {
                script_root: *merkle_subroot,
                intermediate_key: XOnlyPublicKey::from_slice(
                    internal_key.as_inner(),
                )
                .map_err(|_| Error::InvalidProofStructure)?,
                tag: *supplement,
                tweaking_factor: None,
            }),
            _ => Err(Error::InvalidProofStructure),
        }
    }

    fn deconstruct(self) -> (Proof, Self::Supplement) {
        (self.to_proof(), self.tag)
    }

    #[inline]
    fn to_proof(&self) -> Proof {
        Proof::XOnlyKeyTaproot {
            internal_key: self.intermediate_key.serialize().into(),
            merkle_subroot: self.script_root,
        }
    }

    #[inline]
    fn into_proof(self) -> Proof {
        self.to_proof()
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct TaprootCommitment {
    pub script_root: sha256::Hash,
    pub intermediate_key_commitment: PubkeyCommitment,
}

impl<MSG> EmbedCommitVerify<MSG> for TaprootCommitment
where
    MSG: AsRef<[u8]>,
{
    type Container = TaprootContainer;
    type Error = Error;

    fn embed_commit(
        container: &mut Self::Container,
        msg: &MSG,
    ) -> Result<Self, Self::Error> {
        let mut data: Vec<u8> = vec![0x02];
        data.extend(container.intermediate_key.serialize().iter());
        let pubkey = secp256k1::PublicKey::from_slice(&data).expect(
            "Failed to construct 33 Publickey from 0x02 appended x-only key",
        );

        let mut pubkey_container = PubkeyContainer {
            pubkey,
            tag: container.tag,
            tweaking_factor: None,
        };

        let cmt = PubkeyCommitment::embed_commit(&mut pubkey_container, msg)?;

        container.tweaking_factor = pubkey_container.tweaking_factor;

        Ok(Self {
            script_root: container.script_root,
            intermediate_key_commitment: cmt,
        })
    }
}
