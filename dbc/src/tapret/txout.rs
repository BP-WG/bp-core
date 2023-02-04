// Deterministic bitcoin commitments library.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2023 by
//     Dr. Maxim Orlovsky <orlovsky@lnp-bp.org>
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

use bc::{ScriptPubkey, TxOut};
use commit_verify::{mpc, ConvolveCommit, ConvolveCommitProof};

use super::{Lnpbp12, TapretKeyError, TapretProof};

impl ConvolveCommitProof<mpc::Commitment, TxOut, Lnpbp12> for TapretProof {
    type Suppl = Self;

    fn restore_original(&self, commitment: &TxOut) -> TxOut {
        TxOut {
            value: commitment.value,
            script_pubkey: self.original_pubkey_script(),
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
