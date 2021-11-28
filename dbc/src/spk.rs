// BP Core Library implementing LNP/BP specifications & standards related to
// bitcoin protocol
//
// Written in 2020-2021 by
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

use core::convert::TryFrom;

use amplify::Wrapper;
use bitcoin::blockdata::script::Script;
use bitcoin::hashes::{sha256, Hmac};
use bitcoin::secp256k1;
use bitcoin_scripts::convert::ToPubkeyScript;
use bitcoin_scripts::{ConvertInfo, LockScript, PubkeyScript};
use commit_verify::EmbedCommitVerify;
use descriptors::ScriptPubkeyDescr;

use super::{
    Container, Error, LockscriptCommitment, LockscriptContainer, Proof,
    PubkeyCommitment, PubkeyContainer, TaprootCommitment, TaprootContainer,
};

/// Enum defining how given `scriptPubkey` is constructed from the script data
/// or a public key. It is similar to Bitcoin Core descriptors, however it does
/// provide additional variants required for RGB, in particular -
/// [`ScriptEncodeMethod::OpReturn`] variant with a requirement of public key
/// presence (this key will contain commitment). Because of this we can't use
/// miniscript descriptors as well; also in miniscript, descriptor contains a
/// script source, while here the script source is kept separately and is a part
/// of the [`Proof`], while [`ScriptEncodeMethod`] is not included into the
/// proof (it can be guessed from a given proof and `scriptPubkey` and we'd like
/// to preserve space with client-validated data).
#[derive(Clone, PartialEq, Eq, Hash, Debug, Display)]
#[non_exhaustive]
pub enum ScriptEncodeMethod {
    #[display("PublicKey")]
    PublicKey,
    #[display("PubkeyHash")]
    PubkeyHash,
    #[display("ScriptHash")]
    ScriptHash,
    #[display("WPubkeyHash")]
    WPubkeyHash,
    #[display("WScriptHash")]
    WScriptHash,
    #[display("ShWPubkeyHash")]
    ShWPubkeyHash,
    #[display("ShWScriptHash")]
    ShWScriptHash,
    #[display("Taproot")]
    Taproot,
    #[display("OpReturn")]
    OpReturn,
    #[display("Bare")]
    Bare,
}

/// Structure keeping the minimum of information (bytewise) required to verify
/// deterministic bitcoin commitment given only the transaction source, its
/// fee and protocol-specific constants. It is a part of the [`Proof`] data.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Display)]
#[derive(StrictEncode, StrictDecode)]
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

impl Default for ScriptEncodeData {
    fn default() -> Self { Self::SinglePubkey }
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct SpkContainer {
    pub pubkey: secp256k1::PublicKey,
    pub method: ScriptEncodeMethod,
    pub source: ScriptEncodeData,
    /// Single SHA256 hash of the protocol-specific tag
    pub tag: sha256::Hash,
    /// Tweaking factor stored after [`SpkCommitment::embed_commit`]
    /// procedure
    pub tweaking_factor: Option<Hmac<sha256::Hash>>,
}

impl SpkContainer {
    pub fn construct(
        protocol_tag: &sha256::Hash,
        pubkey: secp256k1::PublicKey,
        source: ScriptEncodeData,
        method: ScriptEncodeMethod,
    ) -> Self {
        Self {
            pubkey,
            source,
            method,
            tag: *protocol_tag,
            tweaking_factor: None,
        }
    }
}

impl Container for SpkContainer {
    /// Out supplement is a protocol-specific tag in its hashed form
    type Supplement = sha256::Hash;
    type Host = PubkeyScript;

    fn reconstruct(
        proof: &Proof,
        supplement: &Self::Supplement,
        host: &Self::Host,
    ) -> Result<Self, Error> {
        let (lockscript, _) = match &proof.source {
            ScriptEncodeData::SinglePubkey => (None, None),
            ScriptEncodeData::LockScript(script) => (Some(script), None),
            ScriptEncodeData::Taproot(hash) => (None, Some(hash)),
        };

        let mut proof = proof.clone();
        let method = match ScriptPubkeyDescr::try_from(host.clone())? {
            ScriptPubkeyDescr::Sh(script_hash) => {
                let script =
                    PubkeyScript::from_inner(Script::new_p2sh(&script_hash));
                let some_script = Some(script);
                if let Some(lockscript) = lockscript {
                    if lockscript.to_pubkey_script(ConvertInfo::Hashed)
                        == some_script
                    {
                        ScriptEncodeMethod::ScriptHash
                    } else if lockscript.to_pubkey_script(ConvertInfo::NestedV0)
                        == some_script
                    {
                        // TODO: Fail here, use WrappedWitnessScript variant
                        ScriptEncodeMethod::ShWScriptHash
                    } else {
                        return Err(Error::InvalidProofStructure);
                    }
                } else if proof.pubkey.to_pubkey_script(ConvertInfo::NestedV0)
                    == some_script
                {
                    ScriptEncodeMethod::ShWPubkeyHash
                } else {
                    return Err(Error::InvalidProofStructure);
                }
            }
            ScriptPubkeyDescr::Bare(script)
                if script.as_inner().is_op_return() =>
            {
                ScriptEncodeMethod::OpReturn
            }
            ScriptPubkeyDescr::Bare(script) => {
                proof.source = ScriptEncodeData::LockScript(LockScript::from(
                    script.to_inner(),
                ));
                ScriptEncodeMethod::Bare
            }
            ScriptPubkeyDescr::Pk(_) => ScriptEncodeMethod::PublicKey,
            ScriptPubkeyDescr::Pkh(_) => ScriptEncodeMethod::PubkeyHash,
            ScriptPubkeyDescr::Wpkh(_) => ScriptEncodeMethod::WPubkeyHash,
            ScriptPubkeyDescr::Wsh(_) => ScriptEncodeMethod::WScriptHash,
            ScriptPubkeyDescr::Tr(_) => ScriptEncodeMethod::Taproot,
            _ => unimplemented!(), // TODO: Fail with error here
        };
        let proof = proof;

        match method {
            ScriptEncodeMethod::PublicKey
            | ScriptEncodeMethod::PubkeyHash
            | ScriptEncodeMethod::WPubkeyHash
            | ScriptEncodeMethod::ShWPubkeyHash
            | ScriptEncodeMethod::OpReturn => {
                if ScriptEncodeData::SinglePubkey != proof.source {
                    return Err(Error::InvalidProofStructure);
                }
            }
            ScriptEncodeMethod::Bare // TODO: Move bare to pubkey only encoding
            | ScriptEncodeMethod::ScriptHash
            | ScriptEncodeMethod::WScriptHash
            | ScriptEncodeMethod::ShWScriptHash => {
                if ! matches!(proof.source, ScriptEncodeData::LockScript(_)) {
                    return Err(Error::InvalidProofStructure);
                }
            }
            // TODO: Use WrappedWitnessScript variant
            ScriptEncodeMethod::Taproot => {
                if ! matches!(proof.source, ScriptEncodeData::Taproot(_) | ScriptEncodeData::SinglePubkey) {
                    return Err(Error::InvalidProofStructure);
                }
            }
        }

        Ok(Self {
            pubkey: proof.pubkey,
            source: proof.source,
            method,
            tag: *supplement,
            tweaking_factor: None,
        })
    }

    fn deconstruct(self) -> (Proof, Self::Supplement) {
        (
            Proof {
                pubkey: self.pubkey,
                source: self.source,
            },
            self.tag,
        )
    }

    fn to_proof(&self) -> Proof {
        Proof {
            pubkey: self.pubkey,
            source: self.source.clone(),
        }
    }

    fn into_proof(self) -> Proof {
        Proof {
            pubkey: self.pubkey,
            source: self.source,
        }
    }
}

/// [`PubkeyScript`] containing LNPBP-2 commitment
#[derive(
    Wrapper, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Debug,
    Display, From
)]
#[display(inner)]
#[wrapper(LowerHex, UpperHex)]
pub struct SpkCommitment(PubkeyScript);

impl<MSG> EmbedCommitVerify<MSG> for SpkCommitment
where
    MSG: AsRef<[u8]>,
{
    type Container = SpkContainer;
    type Error = super::Error;

    fn embed_commit(
        container: &mut Self::Container,
        msg: &MSG,
    ) -> Result<Self, Self::Error> {
        use ScriptEncodeMethod::*;
        let script_pubkey = match container.source {
            ScriptEncodeData::LockScript(ref lockscript) => {
                let mut lockscript_container = LockscriptContainer {
                    script: lockscript.clone(),
                    pubkey: container.pubkey,
                    tag: container.tag,
                    tweaking_factor: None,
                };
                let lockscript = LockscriptCommitment::embed_commit(
                    &mut lockscript_container,
                    msg,
                )?
                .into_inner();
                container.tweaking_factor =
                    lockscript_container.tweaking_factor;
                match container.method {
                    Bare => lockscript.to_pubkey_script(ConvertInfo::Bare),
                    ScriptHash => {
                        lockscript.to_pubkey_script(ConvertInfo::Hashed)
                    }
                    WScriptHash => {
                        lockscript.to_pubkey_script(ConvertInfo::SegWitV0)
                    }
                    ShWScriptHash => {
                        lockscript.to_pubkey_script(ConvertInfo::NestedV0)
                    }
                    _ => return Err(Error::InvalidProofStructure),
                }
            }
            ScriptEncodeData::Taproot(taproot_hash) => {
                if container.method != Taproot {
                    return Err(Error::InvalidProofStructure);
                }
                let mut taproot_container = TaprootContainer {
                    script_root: taproot_hash,
                    intermediate_key: container.pubkey,
                    tag: container.tag,
                    tweaking_factor: None,
                };
                let _taproot = TaprootCommitment::embed_commit(
                    &mut taproot_container,
                    msg,
                )?;
                container.tweaking_factor = taproot_container.tweaking_factor;
                // TODO #2: Finalize taproot commitments once taproot will be
                //          finalized. We don't know yet how to form scripPubkey
                //          from Taproot data
                unimplemented!()
            }
            ScriptEncodeData::SinglePubkey => {
                let mut pubkey_container = PubkeyContainer {
                    pubkey: container.pubkey,
                    tag: container.tag,
                    tweaking_factor: None,
                };
                let pubkey = *PubkeyCommitment::embed_commit(
                    &mut pubkey_container,
                    msg,
                )?;
                container.tweaking_factor = pubkey_container.tweaking_factor;
                match container.method {
                    PublicKey => pubkey.to_pubkey_script(ConvertInfo::Bare),
                    PubkeyHash => pubkey.to_pubkey_script(ConvertInfo::Hashed),
                    WPubkeyHash => {
                        pubkey.to_pubkey_script(ConvertInfo::SegWitV0)
                    }
                    ShWScriptHash => {
                        pubkey.to_pubkey_script(ConvertInfo::NestedV0)
                    }
                    OpReturn => {
                        let ser = pubkey.serialize();
                        if ser[0] != 0x02 {
                            return Err(Error::InvalidOpReturnKey);
                        }
                        Some(Script::new_op_return(&ser).into())
                    }
                    _ => return Err(Error::InvalidProofStructure),
                }
            }
        }
        .ok_or(Error::UncompressedKey)?;
        Ok(SpkCommitment::from_inner(script_pubkey))
    }
}
