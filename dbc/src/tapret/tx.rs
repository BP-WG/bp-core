// Deterministic bitcoin commitments library.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2023 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2023 LNP/BP Standards Association. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use bc::Tx;
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
                txout.script_pubkey = self.original_pubkey_script();
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
