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

// Version 0.10.10:
// TODO: Ensure all serde uses both string and binary version
// TODO: Move consensus-level timelocks and sequence locks from other libraries
// Version 0.11.0:
// TODO: Ensure script length control doesn't panic for data structures > 4GB
// Version 1.0:
// TODO: Complete block data type implementation
// TODO: Complete OpCode enumeration
// TODO: Do a no-std feature

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
// TODO: Make strict encoding optional dependency
#[macro_use]
extern crate strict_encoding;
#[macro_use]
extern crate commit_verify;
#[cfg(feature = "serde")]
#[macro_use]
extern crate serde_crate as serde;

extern crate core;
/// Re-export of `secp256k1` crate.
pub extern crate secp256k1;

mod block;
pub mod opcodes;
mod script;
mod segwit;
mod taproot;
mod tx;
mod hashtypes;
mod sigtypes;
mod util;
mod weights;
#[cfg(feature = "stl")]
pub mod stl;
mod coding;

pub use block::{BlockHash, BlockHeader};
pub use coding::{
    ByteStr, ConsensusDataError, ConsensusDecode, ConsensusDecodeError, ConsensusEncode, LenVarInt,
    VarInt, VarIntArray,
};
pub use hashtypes::{PubkeyHash, ScriptHash, WPubkeyHash, WScriptHash};
pub use script::{OpCode, RedeemScript, ScriptBytes, ScriptPubkey, SigScript};
pub use segwit::{SegwitError, Witness, WitnessProgram, WitnessScript, WitnessVer, Wtxid};
pub use sigtypes::{Bip340Sig, LegacySig, SigError, SighashFlag, SighashType};
pub use taproot::{
    ControlBlock, FutureLeafVer, InternalPk, IntoTapHash, InvalidLeafVer, InvalidParityValue,
    InvalidPubkey, LeafScript, LeafVer, OutputPk, Parity, PubkeyParseError, TapBranchHash, TapCode,
    TapLeafHash, TapMerklePath, TapNodeHash, TapScript, TaprootPk, TAPROOT_ANNEX_PREFIX,
    TAPROOT_LEAF_MASK, TAPROOT_LEAF_TAPSCRIPT,
};
pub use tx::{
    LockTime, Outpoint, OutpointParseError, Sats, SeqNo, Tx, TxIn, TxOut, TxParseError, TxVer,
    Txid, Vout, LOCKTIME_THRESHOLD,
};
pub use util::{Chain, ChainParseError, NonStandardValue};
pub use weights::{VBytes, Weight, WeightUnits};

pub const LIB_NAME_BITCOIN: &str = "Bitcoin";
