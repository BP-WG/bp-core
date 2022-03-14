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

use core::convert::TryFrom;

use amplify::Wrapper;
use bitcoin::blockdata::script::Script;
use bitcoin::hashes::{sha256, Hmac};
use bitcoin::secp256k1;
use bitcoin_scripts::convert::ToPubkeyScript;
use bitcoin_scripts::{Category, LockScript, PubkeyScript};
use commit_verify::EmbedCommitVerify;

use super::{
    LockscriptCommitment, LockscriptContainer, PubkeyCommitment,
    PubkeyContainer, ScriptEncodeData, TaprootCommitment, TaprootContainer,
};
use crate::{Container, Error, Proof};

/// Structure with a set of allowed transaction output-based commitment schema.
///
/// Transaction output-based commitments can be created with a different
/// schemata, specific to a specific structure of `scriptPubkey`. Different
/// client-side-validation protocols, working with output-based commitments may
/// allow different forms of commitments; for instance RGBv1 requires that
/// only tapscript-based op_return commitments must be supported inside P2TR
/// outputs. This structure allows to specify the list of supported commitment
/// schemata as a set of flags.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Default)]
pub struct CommitmentSchema {
    /// Tweaks of a single pubkey using LNPBP-1 schema inside P2PK output.
    pub p2pk_tweak: bool,

    /// Tweaks of a single pubkey using LNPBP-1 schema inside P2PKH output.
    pub p2pkh_tweak: bool,

    /// Tweaks of a single pubkey using LNPBP-1 schema inside P2WPKH output.
    pub p2wpkh_tweak: bool,

    /// Tweaks of a single pubkey using LNPBP-1 schema inside a legacy
    /// P2WPKH-in-P2SH output.
    pub p2wpkh_sh_tweak: bool,

    /// Tweaks of a keyset according to LNPBP-1 schema inside a bare scripts
    /// contained within `pubkeyScript`. The set of keys is extracted from the
    /// script using LNPBP-2 schema.
    pub bare_tweak: bool,

    /// Tweaks of a keyset according to LNPBP-1 schema inside a plain
    /// (non-witness-nested) P2SH outputs. The set of keys is extracted from the
    /// script using LNPBP-2 schema.
    pub p2sh_tweak: bool,

    /// Tweaks of a keyset according to LNPBP-1 schema inside a non-nested/
    /// non-legacy P2WSH outputs. The set of keys is extracted from the
    /// script using LNPBP-2 schema.
    pub p2wsh_tweak: bool,

    /// Tweaks of a keyset according to LNPBP-1 schema inside the nested/
    /// legacy P2WSH-in-P2SH outputs. The set of keys is extracted from the
    /// script using LNPBP-2 schema.
    pub p2wsh_sh_tweak: bool,

    /// Commitment directly added to a single and alone `OP_RETURN` operation
    /// contained in a bare `scriptPubkey` in transaction output.
    pub p2pk_return: bool,

    /// Commitment put inside a single `OP_RETURN` tapscript code in the first
    /// leaf of taproot script path spending according to LNPBP-6 schema.
    pub p2tr_return: bool,
}

impl CommitmentSchema {
    /// Sets/clears flags for all commitment schemata based on tweaking of a
    /// single public key (P2PK, P2PKH, P2WPKH, P2WPKH-in-P2SH).
    pub fn update_pubkey_tweaks(&mut self, allow: bool) {
        self.p2pk_tweak = allow;
        self.p2pkh_tweak = allow;
        self.p2wpkh_tweak = allow;
        self.p2wpkh_sh_tweak = allow;
    }

    /// Sets/clears flags for all commitment schemata based on tweaking of a
    /// public key set extracted from a script (Bare, P2PSH, P2WSH,
    /// P2WSH-in-P2SH).
    pub fn update_script_tweaks(&mut self, allow: bool) {
        self.bare_tweak = allow;
        self.p2sh_tweak = allow;
        self.p2wsh_tweak = allow;
        self.p2wsh_sh_tweak = allow;
    }
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
        let method = match descriptors::Compact::try_from(host.clone())? {
            descriptors::Compact::Sh(script_hash) => {
                let script = Script::new_p2sh(&script_hash);
                if let Some(lockscript) = lockscript {
                    if *lockscript.to_pubkey_script(Category::Hashed) == script
                    {
                        ScriptEncodeMethod::ScriptHash
                    } else if *lockscript.to_pubkey_script(Category::Nested)
                        == script
                    {
                        // TODO: Fail here, use WrappedWitnessScript variant
                        ScriptEncodeMethod::ShWScriptHash
                    } else {
                        return Err(Error::InvalidProofStructure);
                    }
                } else if *proof.pubkey.to_pubkey_script(Category::Nested)
                    == script
                {
                    ScriptEncodeMethod::ShWPubkeyHash
                } else {
                    return Err(Error::InvalidProofStructure);
                }
            }
            descriptors::Compact::Bare(script)
                if script.as_inner().is_op_return() =>
            {
                ScriptEncodeMethod::OpReturn
            }
            descriptors::Compact::Bare(script) => {
                proof.source = ScriptEncodeData::LockScript(LockScript::from(
                    script.to_inner(),
                ));
                ScriptEncodeMethod::Bare
            }
            descriptors::Compact::Pk(_) => ScriptEncodeMethod::PublicKey,
            descriptors::Compact::Pkh(_) => ScriptEncodeMethod::PubkeyHash,
            descriptors::Compact::Wpkh(_) => ScriptEncodeMethod::WPubkeyHash,
            descriptors::Compact::Wsh(_) => ScriptEncodeMethod::WScriptHash,
            descriptors::Compact::Taproot(_) => ScriptEncodeMethod::Taproot,
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
                    Bare => lockscript.to_pubkey_script(Category::Bare),
                    ScriptHash => lockscript.to_pubkey_script(Category::Hashed),
                    WScriptHash => {
                        lockscript.to_pubkey_script(Category::SegWit)
                    }
                    ShWScriptHash => {
                        lockscript.to_pubkey_script(Category::Nested)
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
                    PublicKey => pubkey.to_pubkey_script(Category::Bare),
                    PubkeyHash => pubkey.to_pubkey_script(Category::Hashed),
                    WPubkeyHash => pubkey.to_pubkey_script(Category::SegWit),
                    ShWScriptHash => pubkey.to_pubkey_script(Category::Nested),
                    OpReturn => {
                        let ser = pubkey.serialize();
                        if ser[0] != 0x02 {
                            return Err(Error::InvalidOpReturnKey);
                        }
                        Script::new_op_return(&ser).into()
                    }
                    _ => return Err(Error::InvalidProofStructure),
                }
            }
        };
        Ok(SpkCommitment::from_inner(script_pubkey))
    }
}
