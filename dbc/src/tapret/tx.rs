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

use bitcoin::Transaction;
use commit_verify::embed_commit::ConvolveCommitVerify;
use commit_verify::multi_commit::MultiCommitment;

use super::{Lnpbp6, TapretProof, TapretTreeError};

/// Errors during tapret commitment.
#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
pub enum TapretError {
    /// Error embedding tapret commitment into taproot script tree.
    #[from]
    #[display(inner)]
    TreeEmbedding(TapretTreeError),

    /// tapret commitment can't be made in a transaction lacking any taproot
    /// outputs.
    #[display(doc_comments)]
    NoTaprootOutput,
}

impl ConvolveCommitVerify<MultiCommitment, TapretProof, Lnpbp6>
    for Transaction
{
    type Commitment = Transaction;
    type CommitError = TapretError;

    fn convolve_commit(
        &self,
        supplement: &TapretProof,
        msg: &MultiCommitment,
    ) -> Result<Self::Commitment, Self::CommitError> {
        let mut tx = self.clone();

        for txout in &mut tx.output {
            if txout.script_pubkey.is_v1_p2tr() {
                *txout = txout
                    .convolve_commit(supplement, msg)
                    .map_err(TapretError::from)?;
                return Ok(tx);
            }
        }

        return Err(TapretError::NoTaprootOutput);
    }
}
