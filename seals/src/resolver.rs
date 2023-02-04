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

//! API for resolving single-use-seals.

use bc::{Tx, Txid};

/// Error resolving single-use-seal
#[derive(Debug, Display)]
#[display(doc_comments)]
pub enum Error {
    /// Resolver implementation-specific error.
    #[display(inner)]
    Connection(Box<dyn std::error::Error>),

    /// transaction with id {0} is not known to the resolver.
    UnknownTx(Txid),
}

/// API which must be provided by a resolver to operate with single-use-seal.
pub trait Resolver {
    /// Return transaction data for a given transaction id.
    fn tx_by_id(&self, txid: Txid) -> Result<Tx, Error>;
}
