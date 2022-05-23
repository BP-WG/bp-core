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

use commit_verify::multi_commit::MultiCommitment;
use commit_verify::{EmbedCommitProof, EmbedCommitVerify};
use psbt::Psbt;

use super::{Lnpbp6, PsbtCommitError, PsbtVerifyError, TapretProof};

impl EmbedCommitProof<MultiCommitment, Psbt, Lnpbp6> for TapretProof {
    fn restore_original_container(
        &self,
        commit_container: &Psbt,
    ) -> Result<Psbt, PsbtVerifyError> {
        let psbt = commit_container.clone();

        for output in &psbt.outputs {
            if output.script.is_v1_p2tr() {
                EmbedCommitProof::<_, psbt::Output, Lnpbp6>::restore_original_container(self, output)?;
                break;
            }
        }

        Err(PsbtCommitError::NoTaprootOutput).map_err(PsbtVerifyError::from)
    }
}

impl EmbedCommitVerify<MultiCommitment, Lnpbp6> for Psbt {
    type Proof = TapretProof;
    type CommitError = PsbtCommitError;
    type VerifyError = PsbtVerifyError;

    fn embed_commit(
        &mut self,
        msg: &MultiCommitment,
    ) -> Result<Self::Proof, Self::CommitError> {
        for output in &mut self.outputs {
            if output.script.is_v1_p2tr() {
                return output.embed_commit(msg);
            }
        }

        Err(PsbtCommitError::NoTaprootOutput)
    }
}
