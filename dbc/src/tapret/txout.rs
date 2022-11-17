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

use bitcoin::{Script, TxOut};
use commit_verify::convolve_commit::{ConvolveCommit, ConvolveCommitProof};
use commit_verify::lnpbp4;

use super::{Lnpbp6, TapretProof, TapretTreeError};

impl ConvolveCommitProof<lnpbp4::CommitmentHash, TxOut, Lnpbp6>
    for TapretProof
{
    type Suppl = Self;

    fn restore_original(&self, commitment: &TxOut) -> TxOut {
        TxOut {
            value: commitment.value,
            script_pubkey: self.original_pubkey_script().into(),
        }
    }

    fn extract_supplement(&self) -> &Self::Suppl { self }
}

impl ConvolveCommit<lnpbp4::CommitmentHash, TapretProof, Lnpbp6> for TxOut {
    type Commitment = TxOut;
    type CommitError = TapretTreeError;

    fn convolve_commit(
        &self,
        supplement: &TapretProof,
        msg: &lnpbp4::CommitmentHash,
    ) -> Result<(TxOut, TapretProof), Self::CommitError> {
        let (output_key, _) = supplement
            .internal_key
            .convolve_commit(&supplement.path_proof, msg)?;

        let script_pubkey = Script::new_v1_p2tr_tweaked(output_key);

        let commitment = TxOut {
            value: self.value,
            script_pubkey,
        };

        Ok((commitment, supplement.clone()))
    }
}
