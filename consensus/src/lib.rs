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

// Version 1.0:
// TODO: Complete block data type implementation
// TODO: Complete OpCode enumeration

// TODO: Do a no-std feature
// #![cfg_attr(not(feature = "std"), no_std)]
#![deny(
    unsafe_code,
    dead_code,
    // missing_docs,
    unused_variables,
    unused_mut,
    unused_imports,
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case
)]
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

#[macro_use]
extern crate amplify;
// TODO: Make strict encoding optional dependency
#[macro_use]
extern crate strict_encoding;
extern crate commit_verify;
#[cfg(feature = "serde")]
#[macro_use]
extern crate serde;

extern crate core;
/// Re-export of `secp256k1` crate.
pub extern crate secp256k1;

mod block;
pub mod opcodes;
mod script;
mod pubkeys;
mod segwit;
mod taproot;
mod tx;
mod hashtypes;
mod sigtypes;
mod timelocks;
mod util;
mod weights;
#[cfg(feature = "stl")]
pub mod stl;
mod coding;
mod sigcache;

pub use block::{Block, BlockHash, BlockHeader, BlockMerkleRoot};
pub use coding::{
    ByteStr, ConsensusDataError, ConsensusDecode, ConsensusDecodeError, ConsensusEncode, LenVarInt,
    VarInt, VarIntArray, VarIntBytes,
};
pub use hashtypes::{PubkeyHash, ScriptHash, WPubkeyHash, WScriptHash};
pub use opcodes::OpCode;
pub use pubkeys::{CompressedPk, InvalidPubkey, LegacyPk, PubkeyParseError, UncompressedPk};
pub use script::{RedeemScript, ScriptBytes, ScriptPubkey, SigScript};
pub use segwit::{SegwitError, Witness, WitnessProgram, WitnessScript, WitnessVer, Wtxid};
pub use sigcache::{PrevoutMismatch, SighashCache, SighashError};
pub use sigtypes::{Bip340Sig, LegacySig, ScriptCode, SigError, Sighash, SighashFlag, SighashType};
pub use taproot::{
    Annex, AnnexError, ControlBlock, FutureLeafVer, InternalKeypair, InternalPk, IntoTapHash,
    InvalidLeafVer, InvalidParityValue, LeafScript, LeafVer, OutputPk, Parity, TapBranchHash,
    TapCode, TapLeafHash, TapMerklePath, TapNodeHash, TapScript, TapSighash, XOnlyPk,
    MIDSTATE_TAPSIGHASH, TAPROOT_ANNEX_PREFIX, TAPROOT_LEAF_MASK, TAPROOT_LEAF_TAPSCRIPT,
};
pub use timelocks::{
    InvalidTimelock, LockHeight, LockTime, LockTimestamp, SeqNo, TimeLockInterval,
    TimelockParseError, LOCKTIME_THRESHOLD, SEQ_NO_CSV_DISABLE_MASK, SEQ_NO_CSV_TYPE_MASK,
};
pub use tx::{
    BlockDataParseError, Outpoint, OutpointParseError, Sats, Tx, TxIn, TxOut, TxVer, Txid, Vout,
};
pub use util::NonStandardValue;
pub use weights::{VBytes, Weight, WeightUnits};

pub const LIB_NAME_BITCOIN: &str = "Bitcoin";
