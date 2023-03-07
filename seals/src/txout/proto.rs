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

use std::convert::Infallible;

use bc::{Tx, Txid};
use commit_verify::mpc;
use dbc::Proof;
use single_use_seals::{SealProtocol, SealStatus};

use crate::resolver::Resolver;
use crate::txout::TxoSeal;

pub struct Witness {
    pub tx: Tx,
    pub txid: Txid,
    pub proof: Proof,
}

/// Txo single-use-seal engine.
pub struct TxoProtocol<R: Resolver> {
    #[allow(dead_code)]
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
    type Error = Infallible;

    fn get_seal_status(&self, _seal: &Seal) -> Result<SealStatus, Self::Error> { todo!() }
}
