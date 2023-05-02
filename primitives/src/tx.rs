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

use std::fmt::{self, Debug, Formatter};
use std::num::ParseIntError;
use std::str::FromStr;

use amplify::hex::{self, FromHex, ToHex};
use amplify::{Bytes32, RawArray, Wrapper};

use super::{VarIntArray, LIB_NAME_BITCOIN};
use crate::{NonStandardValue, ScriptPubkey, SigScript};

#[derive(Wrapper, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Display, From)]
#[display(Self::to_hex)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BITCOIN)]
#[derive(CommitEncode)]
#[commit_encode(strategy = strict)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
#[wrapper(Index, RangeOps, BorrowSlice)]
// all-zeros used in coinbase
pub struct Txid(
    #[from]
    #[from([u8; 32])]
    Bytes32,
);

impl Debug for Txid {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Txid").field(&self.to_hex()).finish()
    }
}

impl FromStr for Txid {
    type Err = hex::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> { Self::from_hex(s) }
}

/// Satoshi made all SHA245d-based hashes to be displayed as hex strings in a
/// big endian order. Thus we need this manual implementation.
impl ToHex for Txid {
    fn to_hex(&self) -> String {
        let mut slice = self.to_raw_array();
        slice.reverse();
        slice.to_hex()
    }
}

/// Satoshi made all SHA245d-based hashes to be displayed as hex strings in a
/// big endian order. Thus we need this manual implementation.
impl FromHex for Txid {
    fn from_byte_iter<I>(iter: I) -> Result<Self, hex::Error>
    where I: Iterator<Item = Result<u8, hex::Error>> + ExactSizeIterator + DoubleEndedIterator {
        Bytes32::from_byte_iter(iter.rev()).map(Self::from)
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Display, From)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BITCOIN)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
#[display(inner)]
// 0xFFFFFFFF used in coinbase
pub struct Vout(u32);

impl Vout {
    pub fn into_u32(self) -> u32 { self.0 }
}

impl FromStr for Vout {
    type Err = ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> { s.parse().map(Self) }
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Display)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BITCOIN)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
#[display("{txid}:{vout}")]
pub struct Outpoint {
    pub txid: Txid,
    pub vout: Vout,
}

impl Outpoint {
    pub fn new(txid: Txid, vout: impl Into<Vout>) -> Self {
        Self {
            txid,
            vout: vout.into(),
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, From)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BITCOIN)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct SeqNo(u32);

#[derive(Wrapper, Clone, Eq, PartialEq, Debug, From)]
#[wrapper(Deref, Index, RangeOps)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BITCOIN)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct Witness(VarIntArray<VarIntArray<u8>>);

impl Witness {
    pub fn from_consensus_stack(witness: impl IntoIterator<Item = Vec<u8>>) -> Witness {
        let iter = witness.into_iter().map(|vec| {
            VarIntArray::try_from(vec).expect("witness stack element length exceeds 2^64 bytes")
        });
        let stack =
            VarIntArray::try_from_iter(iter).expect("witness stack size exceeds 2^64 bytes");
        Witness(stack)
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BITCOIN)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct TxIn {
    pub prev_output: Outpoint,
    pub sig_script: SigScript,
    pub sequence: SeqNo,
    pub witness: Witness,
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, From)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BITCOIN)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct Sats(u64);

#[derive(Clone, Eq, PartialEq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BITCOIN)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct TxOut {
    pub value: Sats,
    pub script_pubkey: ScriptPubkey,
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BITCOIN)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct TxVer(i32);

impl Default for TxVer {
    fn default() -> Self { TxVer(2) }
}

impl TxVer {
    /// Pre-BIP68 version.
    pub const V1: Self = TxVer(1);
    /// Current version (post-BIP68).
    pub const V2: Self = TxVer(2);

    #[inline]
    pub const fn from_consensus_i32(ver: i32) -> Self { TxVer(ver) }

    pub const fn try_from_standard(ver: i32) -> Result<Self, NonStandardValue<i32>> {
        let ver = TxVer::from_consensus_i32(ver);
        if !ver.is_standard() {
            return Err(NonStandardValue::with(ver.0, "TxVer"));
        } else {
            Ok(ver)
        }
    }

    #[inline]
    pub const fn is_standard(self) -> bool { self.0 <= TxVer::V2.0 }

    #[inline]
    pub const fn to_consensus_u32(&self) -> i32 { self.0 }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BITCOIN)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct LockTime(u32);

impl LockTime {
    #[inline]
    pub const fn from_consensus_i32(lock_time: u32) -> Self { LockTime(lock_time) }

    #[inline]
    pub const fn to_consensus_u32(&self) -> u32 { self.0 }
}

#[derive(Clone, Eq, PartialEq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BITCOIN)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct Tx {
    pub version: TxVer,
    pub inputs: VarIntArray<TxIn>,
    pub outputs: VarIntArray<TxOut>,
    pub lock_time: LockTime,
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn txid_byteorder() {
        let hex = "c9a86c99127f1b2d1ff495c238f13069ac881ec9527905016122d11d85b19b61";
        let from_str = Txid::from_str(hex).unwrap();
        let from_hex = Txid::from_hex(hex).unwrap();
        assert_eq!(from_str, from_hex);
        assert_eq!(from_str.to_string(), from_str.to_hex());
    }
}
