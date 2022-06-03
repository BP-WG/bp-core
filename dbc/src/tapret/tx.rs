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
use commit_verify::convolve_commit::{
    ConvolveCommitProof, ConvolveCommitVerify,
};
use commit_verify::lnpbp4;

use super::{Lnpbp6, TapretProof, TapretTreeError};

/// Errors during tapret commitment.
#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
pub enum TapretError {
    /// Error embedding tapret commitment into taproot script tree.
    #[from]
    #[display(inner)]
    TreeEmbedding(TapretTreeError),

    /// tapret commitment in a transaction lacking any taproot outputs.
    #[display(doc_comments)]
    NoTaprootOutput,
}

impl ConvolveCommitProof<lnpbp4::CommitmentHash, Transaction, Lnpbp6>
    for TapretProof
{
    type Suppl = Self;

    fn restore_original(&self, commitment: &Transaction) -> Transaction {
        let mut tx = commitment.clone();

        for txout in &mut tx.output {
            if txout.script_pubkey.is_v1_p2tr() {
                txout.script_pubkey = self.original_pubkey_script().into();
            }
        }
        tx
    }

    fn extract_supplement(&self) -> &Self::Suppl { self }
}

impl ConvolveCommitVerify<lnpbp4::CommitmentHash, TapretProof, Lnpbp6>
    for Transaction
{
    type Commitment = Transaction;
    type CommitError = TapretError;

    fn convolve_commit(
        &self,
        supplement: &TapretProof,
        msg: &lnpbp4::CommitmentHash,
    ) -> Result<(Transaction, TapretProof), Self::CommitError> {
        let mut tx = self.clone();

        for txout in &mut tx.output {
            if txout.script_pubkey.is_v1_p2tr() {
                let (commitment, proof) = txout
                    .convolve_commit(supplement, msg)
                    .map_err(TapretError::from)?;
                *txout = commitment;
                return Ok((tx, proof));
            }
        }

        Err(TapretError::NoTaprootOutput)
    }
}
