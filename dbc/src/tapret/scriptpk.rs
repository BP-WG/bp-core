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

use bitcoin::Script;
use bitcoin_scripts::PubkeyScript;
use commit_verify::convolve_commit::{
    ConvolveCommitProof, ConvolveCommitVerify,
};
use commit_verify::lnpbp4;

use super::{Lnpbp6, TapretProof, TapretTreeError};

impl ConvolveCommitProof<lnpbp4::CommitmentHash, PubkeyScript, Lnpbp6>
    for TapretProof
{
    type Suppl = Self;

    fn restore_original(&self, _: &PubkeyScript) -> PubkeyScript {
        self.original_pubkey_script()
    }

    fn extract_supplement(&self) -> &Self::Suppl { self }
}

impl ConvolveCommitVerify<lnpbp4::CommitmentHash, TapretProof, Lnpbp6>
    for PubkeyScript
{
    type Commitment = PubkeyScript;
    type CommitError = TapretTreeError;

    fn convolve_commit(
        &self,
        supplement: &TapretProof,
        msg: &lnpbp4::CommitmentHash,
    ) -> Result<(PubkeyScript, TapretProof), Self::CommitError> {
        let (output_key, proof) = supplement
            .internal_key
            .convolve_commit(&supplement.path_proof, msg)?;

        let commitment = Script::new_v1_p2tr_tweaked(output_key).into();

        Ok((commitment, proof))
    }
}
