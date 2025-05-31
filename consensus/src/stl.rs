// Bitcoin protocol consensus library.
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
// Coding conventions

use strict_types::{CompileError, LibBuilder, TypeLib};

use crate::{
    Bip340Sig, Block, ByteStr, CompressedPk, ControlBlock, FutureLeafVer, InternalPk, LeafScript,
    LegacyPk, LegacySig, LockHeight, LockTimestamp, OpCode, OutputPk, PubkeyHash, RedeemScript,
    ScriptHash, TapCode, TapLeafHash, TapNodeHash, TapScript, TimeLockInterval, Tx, UncompressedPk,
    VBytes, VarInt, WPubkeyHash, WScriptHash, WeightUnits, WitnessProgram, WitnessScript,
    WitnessVer, Wtxid, LIB_NAME_BITCOIN,
};

pub const LIB_ID_BP_TX: &str =
    "stl:9WwTYiP2-OadKCZP-cR0bJ_Y-qruINYX-bXZFj8Y-fsQoGgo#signal-color-cipher";
pub const LIB_ID_BP_CONSENSUS: &str =
    "stl:bbBgv6xK-tksHoCQ-wI0FIdy-vBtG3iv-f9sGG_1-5KnEa5c#sport-diego-fiction";

#[allow(clippy::result_large_err)]
#[deprecated(since = "0.10.8", note = "use _bp_tx_stl instead")]
fn _bitcoin_stl() -> Result<TypeLib, CompileError> { _bp_tx_stl() }

#[allow(clippy::result_large_err)]
fn _bp_tx_stl() -> Result<TypeLib, CompileError> {
    LibBuilder::with(libname!(LIB_NAME_BITCOIN), None).transpile::<Tx>().compile()
}

#[allow(clippy::result_large_err)]
fn _bp_consensus_stl() -> Result<TypeLib, CompileError> {
    LibBuilder::with(libname!(LIB_NAME_BITCOIN), [
        strict_types::stl::std_stl().to_dependency_types()
    ])
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
    .transpile::<Block>()
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
    #![cfg_attr(coverage_nightly, coverage(off))]

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
