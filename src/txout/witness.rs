// Bitcoin protocol single-use-seals library.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2024 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association. All rights reserved.
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

use bc::{ScriptPubkey, Tx};
use commit_verify::mpc;

use crate::txout::{TxoSeal, VerifyError};

/// Witness of a bitcoin-based seal being closed.
pub trait Witness {
    /// Verify that witness indeed closes a set of seals.
    fn verify_seals<Seal: TxoSeal>(
        &self,
        seals: impl IntoIterator<Item = Seal>,
        msg: mpc::Commitment,
    ) -> Result<(), VerifyError>;
}

impl Witness for Tx {
    fn verify_seals<Seal: TxoSeal>(
        &self,
        seals: impl IntoIterator<Item = Seal>,
        msg: mpc::Commitment,
    ) -> Result<(), VerifyError> {
        for seal in seals {
            // 1. Each seal must match tx inputs
            let outpoint = seal.outpoint().ok_or(VerifyError::NoWitnessTxid)?;
            if !self.inputs.iter().any(|txin| txin.prev_output == outpoint) {
                return Err(VerifyError::WitnessNotClosingSeal(self.txid(), outpoint));
            }
        }

        // 2. Verify DBC with the giving closing method
        let Some(output) = self.outputs().find(|out| out.script_pubkey.is_op_return()) else {
            return Err(VerifyError::NoOpReturn(self.txid()));
        };

        let expected_script = ScriptPubkey::op_return(msg.as_slice());
        if output.script_pubkey != expected_script {
            return Err(VerifyError::Dbc(self.txid()));
        }

        Ok(())
    }
}
