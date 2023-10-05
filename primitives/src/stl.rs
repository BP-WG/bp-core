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

use strict_types::{CompileError, LibBuilder, TypeLib};

use crate::{
    Bip340Sig, BlockHeader, ByteStr, Chain, ControlBlock, FutureLeafVer, LeafScript, LegacySig,
    OpCode, RedeemScript, TapCode, TapLeafHash, TapNodeHash, TapScript, Tx, VBytes, VarInt,
    WeightUnits, WitnessProgram, WitnessScript, WitnessVer, Wtxid, LIB_NAME_BITCOIN,
};

#[deprecated(since = "0.10.8", note = "use LIB_ID_BP_TX instead")]
pub const LIB_ID_BITCOIN: &str =
    "urn:ubideco:stl:6GgF7biXPVNcus2FfQj2pQuRzau11rXApMQLfCZhojgi#money-pardon-parody";
pub const LIB_ID_BP_TX: &str =
    "urn:ubideco:stl:6GgF7biXPVNcus2FfQj2pQuRzau11rXApMQLfCZhojgi#money-pardon-parody";
pub const LIB_ID_BP_CONSENSUS: &str =
    "urn:ubideco:stl:A6tfQFthqmb39wR5sWvrfgf3oiAyazm8rh7ff35ruioi#russian-emerald-extra";

#[deprecated(since = "0.10.8", note = "use _bp_tx_stl instead")]
fn _bitcoin_stl() -> Result<TypeLib, CompileError> { _bp_tx_stl() }

fn _bp_tx_stl() -> Result<TypeLib, CompileError> {
    LibBuilder::new(libname!(LIB_NAME_BITCOIN), None)
        .transpile::<Tx>()
        .compile()
}

fn _bp_consensus_stl() -> Result<TypeLib, CompileError> {
    LibBuilder::new(libname!(LIB_NAME_BITCOIN), tiny_bset! {
        strict_types::stl::std_stl().to_dependency(),
    })
    .transpile::<LegacySig>()
    .transpile::<Bip340Sig>()
    .transpile::<OpCode>()
    .transpile::<WitnessScript>()
    .transpile::<RedeemScript>()
    .transpile::<Wtxid>()
    .transpile::<WitnessProgram>()
    .transpile::<WitnessVer>()
    .transpile::<TapNodeHash>()
    .transpile::<TapLeafHash>()
    .transpile::<FutureLeafVer>()
    .transpile::<LeafScript>()
    .transpile::<TapCode>()
    .transpile::<TapScript>()
    .transpile::<ControlBlock>()
    .transpile::<BlockHeader>()
    .transpile::<Tx>()
    .transpile::<VarInt>()
    .transpile::<ByteStr>()
    .transpile::<Chain>()
    .transpile::<WeightUnits>()
    .transpile::<VBytes>()
    .compile()
}

#[deprecated(since = "0.10.8", note = "use bp_tx_stl instead")]
pub fn bitcoin_stl() -> TypeLib { bp_tx_stl() }

pub fn bp_tx_stl() -> TypeLib {
    _bp_tx_stl().expect("invalid strict type Bitcoin transaction library")
}

pub fn bp_consensus_stl() -> TypeLib {
    _bp_consensus_stl().expect("invalid strict type Bitcoin consensus library")
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn lib_id_tx() {
        let lib = bp_tx_stl();
        assert_eq!(lib.id().to_string(), LIB_ID_BP_TX);
    }

    #[test]
    fn lib_id_consensus() {
        let lib = bp_consensus_stl();
        assert_eq!(lib.id().to_string(), LIB_ID_BP_CONSENSUS);
    }
}
