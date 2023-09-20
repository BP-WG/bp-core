// Bitcoin protocol primitives library.
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

// Coding conventions
#![deny(
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case,
    unused_mut,
    unused_imports,
    dead_code,
    // TODO: Uncomment missing_docs
)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

#[macro_use]
extern crate amplify;
#[macro_use]
extern crate strict_encoding;
#[macro_use]
extern crate commit_verify;
#[cfg(feature = "serde")]
#[macro_use]
extern crate serde_crate as serde;

/// Re-export of `secp256k1` crate.
pub extern crate secp256k1;

mod block;
pub mod opcodes;
mod script;
mod segwit;
mod taproot;
mod tx;
mod util;
#[cfg(feature = "stl")]
pub mod stl;

pub use block::{BlockHash, BlockHeader};
pub use script::{OpCode, ScriptBytes, ScriptPubkey, SigScript};
pub use segwit::*;
pub use taproot::*;
pub use tx::{
    LockTime, Outpoint, OutpointParseError, Sats, SeqNo, Tx, TxIn, TxOut, TxVer, Txid, Vout,
    Witness, LOCKTIME_THRESHOLD,
};
pub use types::VarIntArray;
pub use util::{Chain, ChainParseError, NonStandardValue};

pub const LIB_NAME_BITCOIN: &str = "Bitcoin";

mod types {
    use amplify::confinement::{Confined, U32};

    pub type VarIntArray<T> = Confined<Vec<T>, 0, U32>;
}
