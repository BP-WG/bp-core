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

/// Ephemeral/intermediary structure used as a container storing all data
/// participating in the creation or verification of a specific commitment.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct SpkContainer {
    /// Extra-transaction proof of the commitment
    pub proof: Proof,

    /// Set of allowed commitment schemata.
    ///
    /// The set is defined by the specific client-side-validation protocol.
    pub allowed: CommitmentSchema,

    /// Single SHA256 hash of the protocol-specific tag
    pub tag: sha256::Hash,

    /// Tweaking factor stored after [`SpkCommitment::embed_commit`]
    /// procedure
    pub tweaking_factor: Option<Hmac<sha256::Hash>>,
}

impl Container for SpkContainer {
    /// Supplement is a protocol-specific tag in its hashed form and protocol-
    /// defined set of allowed commitment schemata.
    type Supplement = (sha256::Hash, CommitmentSchema);

    /// The host for the commitment is a `scriptPubkey` of a transaction output
    /// which is a part of the [`Proof`], so we do not use it here.
    type Host = ();

    fn reconstruct(
        proof: &Proof,
        supplement: &Self::Supplement,
        _host: &Self::Host,
    ) -> Result<Self, Error> {
        Ok(SpkContainer {
            proof: proof.clone(),
            allowed: supplement.1,
            tag: supplement.0,
            tweaking_factor: None,
        })
    }

    #[inline]
    fn deconstruct(self) -> (Proof, Self::Supplement) {
        (self.proof, (self.tag, self.allowed))
    }

    #[inline]
    fn to_proof(&self) -> Proof {
        self.proof.clone()
    }

    #[inline]
    fn into_proof(self) -> Proof {
        self.proof
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
    }
}
