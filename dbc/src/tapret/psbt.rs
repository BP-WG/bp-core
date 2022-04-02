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

#![cfg(feature = "wallet")]

use bitcoin::Transaction;
use commit_verify::multi_commit::MultiCommitment;
use commit_verify::{EmbedCommitProof, EmbedCommitVerify};
use psbt::Psbt;

use super::{Lnpbp6, TapretProof, TapretPsbtError};

impl EmbedCommitProof<MultiCommitment, (Psbt, Transaction), Lnpbp6>
    for TapretProof
{
    fn restore_original_container(
        &self,
        commit_container: &(Psbt, Transaction),
    ) -> Result<(Psbt, Transaction), TapretPsbtError> {
        let (psbt, tx) = commit_container.clone();

        for (output, txout) in (psbt.outputs, tx.output) {
            if txout.script_pubkey.is_v1_p2tr() {
                return self.restore_original_container(&(output, txout));
            }
        }

        return Err(TapretPsbtError::NoTaprootOutput);
    }
}

impl EmbedCommitVerify<MultiCommitment, Lnpbp6> for (Psbt, Transaction) {
    type Proof = TapretProof;
    type CommitError = TapretPsbtError;

    fn embed_commit(
        &mut self,
        msg: &MultiCommitment,
    ) -> Result<Self::Proof, Self::CommitError> {
        let (psbt, tx) = self;

        for (output, txout) in (&mut psbt.outputs, &mut tx.output) {
            if txout.script_pubkey.is_v1_p2tr() {
                return (output, txout).embed_commit(msg);
            }
        }

        return Err(TapretPsbtError::NoTaprootOutput);
    }
}
