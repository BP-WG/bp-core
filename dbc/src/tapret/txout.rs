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

use bp::{ScriptPubkey, TxOut};
use commit_verify::{mpc, ConvolveCommit, ConvolveCommitProof};

use super::{Lnpbp12, TapretKeyError, TapretProof};

impl ConvolveCommitProof<mpc::Commitment, TxOut, Lnpbp12> for TapretProof {
    type Suppl = Self;

    fn restore_original(&self, commitment: &TxOut) -> TxOut {
        TxOut {
            value: commitment.value,
            script_pubkey: self.original_pubkey_script().into(),
        }
    }

    fn extract_supplement(&self) -> &Self::Suppl { self }
}

impl ConvolveCommit<mpc::Commitment, TapretProof, Lnpbp12> for TxOut {
    type Commitment = TxOut;
    type CommitError = TapretKeyError;

    fn convolve_commit(
        &self,
        supplement: &TapretProof,
        msg: &mpc::Commitment,
    ) -> Result<(TxOut, TapretProof), Self::CommitError> {
        let (output_key, _) = supplement
            .internal_pk
            .convolve_commit(&supplement.path_proof, msg)?;

        let script_pubkey = ScriptPubkey::p2tr_tweaked(output_key);

        let commitment = TxOut {
            value: self.value,
            script_pubkey,
        };

        Ok((commitment, supplement.clone()))
    }
}
