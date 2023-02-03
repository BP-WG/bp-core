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

use bp::Tx;
use commit_verify::{mpc, ConvolveCommit, ConvolveCommitProof};

use super::{Lnpbp12, TapretKeyError, TapretProof};

/// Errors during tapret commitment.
#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
pub enum TapretError {
    /// Error embedding tapret commitment into x-only key.
    #[from]
    #[display(inner)]
    KeyEmbedding(TapretKeyError),

    /// tapret commitment in a transaction lacking any taproot outputs.
    #[display(doc_comments)]
    NoTaprootOutput,
}

impl ConvolveCommitProof<mpc::Commitment, Tx, Lnpbp12> for TapretProof {
    type Suppl = Self;

    fn restore_original(&self, commitment: &Tx) -> Tx {
        let mut tx = commitment.clone();

        for txout in &mut tx.outputs {
            if txout.script_pubkey.is_p2tr() {
                txout.script_pubkey = self.original_pubkey_script().into();
            }
        }
        tx
    }

    fn extract_supplement(&self) -> &Self::Suppl { self }
}

impl ConvolveCommit<mpc::Commitment, TapretProof, Lnpbp12> for Tx {
    type Commitment = Tx;
    type CommitError = TapretError;

    fn convolve_commit(
        &self,
        supplement: &TapretProof,
        msg: &mpc::Commitment,
    ) -> Result<(Tx, TapretProof), Self::CommitError> {
        let mut tx = self.clone();

        for txout in &mut tx.outputs {
            if txout.script_pubkey.is_p2tr() {
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
