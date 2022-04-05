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

#![cfg(any(feature = "consensus", feature = "wallet"))]

use bitcoin::Script;
use bitcoin_scripts::PubkeyScript;
use commit_verify::embed_commit::ConvolveCommitVerify;
use commit_verify::multi_commit::MultiCommitment;

use super::{Lnpbp6, TapretProof, TapretTreeError};

impl ConvolveCommitVerify<MultiCommitment, TapretProof, Lnpbp6>
    for PubkeyScript
{
    type Commitment = PubkeyScript;
    type CommitError = TapretTreeError;

    fn convolve_commit(
        &self,
        supplement: &TapretProof,
        msg: &MultiCommitment,
    ) -> Result<Self::Commitment, Self::CommitError> {
        let output_key = supplement
            .internal_key
            .convolve_commit(&supplement.path_proof, msg)?;

        Ok(Script::new_v1_p2tr_tweaked(output_key).into())
    }
}
