// Bitcoin protocol consensus library.
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

use crate::timelocks::TimeLockInterval;
use crate::{
    Bip340Sig, BlockHeader, ByteStr, CompressedPk, ControlBlock, FutureLeafVer, InternalPk,
    LeafScript, LegacyPk, LegacySig, LockHeight, LockTimestamp, OpCode, OutputPk, PubkeyHash,
    RedeemScript, ScriptHash, TapCode, TapLeafHash, TapNodeHash, TapScript, Tx, UncompressedPk,
    VBytes, VarInt, WPubkeyHash, WScriptHash, WeightUnits, WitnessProgram, WitnessScript,
    WitnessVer, Wtxid, LIB_NAME_BITCOIN,
};

#[deprecated(since = "0.10.8", note = "use LIB_ID_BP_TX instead")]
pub const LIB_ID_BITCOIN: &str =
    "urn:ubideco:stl:HX2UBak8vPsTokug1DGMDvTpzns3xUdwZ7QJdyt4qBA9#speed-atlanta-trilogy";
pub const LIB_ID_BP_TX: &str =
    "urn:ubideco:stl:HX2UBak8vPsTokug1DGMDvTpzns3xUdwZ7QJdyt4qBA9#speed-atlanta-trilogy";
pub const LIB_ID_BP_CONSENSUS: &str =
    "urn:ubideco:stl:DQtzB8Kcfm7XeuhWf8sv3n31c5V2qK6VS1Zbye76haUQ#erosion-quiet-kinetic";

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
    .transpile::<PubkeyHash>()
    .transpile::<WPubkeyHash>()
    .transpile::<ScriptHash>()
    .transpile::<WScriptHash>()
    .transpile::<WitnessScript>()
    .transpile::<RedeemScript>()
    .transpile::<Wtxid>()
    .transpile::<WitnessProgram>()
    .transpile::<WitnessVer>()
    .transpile::<CompressedPk>()
    .transpile::<UncompressedPk>()
    .transpile::<LegacyPk>()
    .transpile::<InternalPk>()
    .transpile::<OutputPk>()
    .transpile::<TapNodeHash>()
    .transpile::<TapLeafHash>()
    .transpile::<FutureLeafVer>()
    .transpile::<LeafScript>()
    .transpile::<TapCode>()
    .transpile::<TapScript>()
    .transpile::<ControlBlock>()
    .transpile::<BlockHeader>()
    .transpile::<TimeLockInterval>()
    .transpile::<LockTimestamp>()
    .transpile::<LockHeight>()
    .transpile::<Tx>()
    .transpile::<VarInt>()
    .transpile::<ByteStr>()
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
