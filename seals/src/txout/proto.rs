// Bitcoin protocol single-use-seals library.
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

use bc::Txid;
use commit_verify::mpc;
use dbc::{Anchor, Proof};
use single_use_seals::{SealProtocol, SealStatus, VerifySeal};
use strict_encoding::StrictDumb;

use crate::resolver::Resolver;
use crate::txout::{TxoSeal, VerifyError};

pub struct Witness {
    pub txid: Txid,
    pub proof: Proof,
}

impl<L> From<Anchor<L>> for Witness
where L: mpc::Proof + StrictDumb
{
    fn from(anchor: Anchor<L>) -> Self {
        Witness {
            txid: anchor.txid,
            proof: anchor.dbc_proof,
        }
    }
}

/// Txo single-use-seal engine.
pub struct TxoProtocol<R: Resolver> {
    resolver: R,
}

impl<Seal, R> SealProtocol<Seal> for TxoProtocol<R>
where
    Seal: TxoSeal,
    R: Resolver,
{
    type Witness = Witness;
    type Message = mpc::Commitment;
    type PublicationId = Txid;
    type Error = VerifyError;

    fn get_seal_status(&self, _seal: &Seal) -> Result<SealStatus, Self::Error> { todo!() }
}

impl<'seal, Seal, R> VerifySeal<'seal, Seal> for TxoProtocol<R>
where
    Seal: TxoSeal + 'seal,
    R: Resolver,
{
    fn verify_seal(
        &self,
        seal: &'seal Seal,
        msg: &Self::Message,
        witness: &Self::Witness,
    ) -> Result<bool, Self::Error> {
        // 1. Get tx
        let tx = self.resolver.tx_by_id(witness.txid)?;

        // 2. The seal must match tx inputs
        let outpoint = seal.outpoint_or(witness.txid);
        if !tx.inputs.iter().any(|txin| txin.prev_output == outpoint) {
            return Err(VerifyError::WitnessNotClosingSeal(witness.txid, outpoint));
        }

        // 3. Verify DBC with the giving closing method
        witness.proof.verify(msg, tx).map_err(VerifyError::from)
    }

    fn verify_seal_all(
        &self,
        seals: impl IntoIterator<Item = &'seal Seal>,
        msg: &Self::Message,
        witness: &Self::Witness,
    ) -> Result<bool, Self::Error> {
        // 1. Get tx
        let tx = self.resolver.tx_by_id(witness.txid)?;

        let mut method = None;
        for seal in seals {
            // 2. All seals must have the same closing method
            if let Some(method) = method {
                if method != seal.method() {
                    return Err(VerifyError::InconsistentCloseMethod);
                }
            } else {
                method = Some(seal.method());
            }

            // 3. Each seal must match tx inputs
            let outpoint = seal.outpoint_or(witness.txid);
            if !tx.inputs.iter().any(|txin| txin.prev_output == outpoint) {
                return Err(VerifyError::WitnessNotClosingSeal(witness.txid, outpoint));
            }
        }

        // 4. Verify DBC with the giving closing method
        witness.proof.verify(msg, tx).map_err(VerifyError::from)
    }
}
