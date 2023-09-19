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

use std::fmt::{self, Debug, Display, Formatter};
use std::iter::Sum;
use std::num::ParseIntError;
use std::str::FromStr;

use amplify::hex::FromHex;
use amplify::{hex, Bytes32StrRev, Wrapper};

use super::{VarIntArray, LIB_NAME_BITCOIN};
use crate::{NonStandardValue, ScriptPubkey, SigScript};

#[derive(Wrapper, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, From)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BITCOIN)]
#[derive(CommitEncode)]
#[commit_encode(strategy = strict)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
#[wrapper(BorrowSlice, Index, RangeOps, Debug, LowerHex, UpperHex, Display, FromStr)]
// all-zeros used in coinbase
pub struct Txid(
    #[from]
    #[from([u8; 32])]
    Bytes32StrRev,
);

impl Txid {
    pub fn coinbase() -> Self { Self(zero!()) }
}

impl FromHex for Txid {
    fn from_byte_iter<I>(iter: I) -> Result<Self, hex::Error>
    where I: Iterator<Item = Result<u8, hex::Error>> + ExactSizeIterator + DoubleEndedIterator {
        Bytes32StrRev::from_byte_iter(iter).map(Self)
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

#[derive(Clone, Eq, PartialEq, Debug, Display, From, Error)]
#[display(doc_comments)]
pub enum OutpointParseError {
    /// malformed string representation of outoint '{0}' lacking txid and vout
    /// separator ':'
    MalformedSeparator(String),

    /// malformed outpoint output number. Details: {0}
    #[from]
    InvalidVout(ParseIntError),

    /// malformed outpoint txid value. Details: {0}
    #[from]
    InvalidTxid(hex::Error),
}

impl FromStr for Outpoint {
    type Err = OutpointParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (txid, vout) = s
            .split_once(':')
            .ok_or_else(|| OutpointParseError::MalformedSeparator(s.to_owned()))?;
        Ok(Outpoint::new(txid.parse()?, Vout::from_str(vout)?))
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BITCOIN)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct SeqNo(u32);

impl SeqNo {
    #[inline]
    pub const fn from_consensus_u32(lock_time: u32) -> Self { SeqNo(lock_time) }

    #[inline]
    pub const fn to_consensus_u32(&self) -> u32 { self.0 }
}

#[derive(Wrapper, Clone, Eq, PartialEq, Hash, Debug, From, Default)]
#[wrapper(Deref, Index, RangeOps)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BITCOIN)]
pub struct Witness(VarIntArray<VarIntArray<u8>>);

impl Witness {
    pub fn new() -> Self { default!() }

    pub fn from_consensus_stack(witness: impl IntoIterator<Item = Vec<u8>>) -> Witness {
        let iter = witness.into_iter().map(|vec| {
            VarIntArray::try_from(vec).expect("witness stack element length exceeds 2^64 bytes")
        });
        let stack =
            VarIntArray::try_from_iter(iter).expect("witness stack size exceeds 2^64 bytes");
        Witness(stack)
    }
}

#[cfg(feature = "serde")]
mod _serde {
    use serde::{Deserialize, Serialize};
    use serde_crate::ser::SerializeSeq;
    use serde_crate::{Deserializer, Serializer};

    use super::*;
    use crate::ScriptBytes;

    impl Serialize for Witness {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer {
            let mut ser = serializer.serialize_seq(Some(self.len()))?;
            for el in &self.0 {
                ser.serialize_element(&ScriptBytes::from(el.to_inner()))?;
            }
            ser.end()
        }
    }

    impl<'de> Deserialize<'de> for Witness {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: Deserializer<'de> {
            let data = Vec::<ScriptBytes>::deserialize(deserializer)?;
            Ok(Witness::from_consensus_stack(data.into_iter().map(ScriptBytes::into_vec)))
        }
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BITCOIN)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct TxIn {
    pub prev_output: Outpoint,
    pub sig_script: SigScript,
    pub sequence: SeqNo,
    pub witness: Witness,
}

#[derive(Wrapper, WrapperMut, Copy, Clone, Eq, PartialEq, Hash, Debug, From)]
#[wrapper(Add, Sub, Mul, Div, FromStr)]
#[wrapper_mut(MathAssign)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BITCOIN)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct Sats(
    #[from]
    #[from(u32)]
    #[from(u16)]
    #[from(u8)]
    pub u64,
);

impl Sats {
    pub const ZERO: Self = Sats(0);
    pub const BTC: Self = Sats(1_000_000_00);

    pub const fn from_btc(btc: u32) -> Self { Self(btc as u64 * Self::BTC.0) }

    pub const fn btc_round(&self) -> u64 {
        if self.0 == 0 {
            return 0;
        }
        let inc = 2 * self.sats_rem() / Self::BTC.0;
        self.0 / Self::BTC.0 + inc
    }

    pub const fn btc_ceil(&self) -> u64 {
        if self.0 == 0 {
            return 0;
        }
        let inc = if self.sats_rem() > 0 { 1 } else { 0 };
        self.0 / Self::BTC.0 + inc
    }

    pub const fn btc_floor(&self) -> u64 {
        if self.0 == 0 {
            return 0;
        }
        self.0 / Self::BTC.0
    }

    pub const fn sats(&self) -> u64 { self.0 }

    pub const fn sats_rem(&self) -> u64 { self.0 % Self::BTC.0 }

    pub fn checked_add(&self, other: impl Into<Self>) -> Option<Self> {
        self.0.checked_add(other.into().0).map(Self)
    }
    pub fn checked_sub(&self, other: impl Into<Self>) -> Option<Self> {
        self.0.checked_sub(other.into().0).map(Self)
    }

    pub fn checked_add_assign(&mut self, other: impl Into<Self>) -> bool {
        self.0
            .checked_add(other.into().0)
            .map(Self)
            .map(|sum| *self = sum)
            .map(|_| true)
            .unwrap_or_default()
    }
    pub fn checked_sub_assign(&mut self, other: impl Into<Self>) -> bool {
        self.0
            .checked_sub(other.into().0)
            .map(Self)
            .map(|sum| *self = sum)
            .map(|_| true)
            .unwrap_or_default()
    }

    pub fn saturating_add(&self, other: impl Into<Self>) -> Self {
        self.0.saturating_add(other.into().0).into()
    }
    pub fn saturating_sub(&self, other: impl Into<Self>) -> Self {
        self.0.saturating_sub(other.into().0).into()
    }

    pub fn saturating_add_assign(&mut self, other: impl Into<Self>) {
        *self = self.0.saturating_add(other.into().0).into();
    }
    pub fn saturating_sub_assign(&mut self, other: impl Into<Self>) {
        *self = self.0.saturating_sub(other.into().0).into();
    }
}

impl Sum for Sats {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Sats::ZERO, |sum, value| sum.saturating_add(value))
    }
}

impl Sum<u64> for Sats {
    fn sum<I: Iterator<Item = u64>>(iter: I) -> Self {
        iter.fold(Sats::ZERO, |sum, value| sum.saturating_add(value))
    }
}

impl Display for Sats {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result { Display::fmt(&self.0, f) }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BITCOIN)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct TxOut {
    pub value: Sats,
    pub script_pubkey: ScriptPubkey,
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
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
            Err(NonStandardValue::with(ver.0, "TxVer"))
        } else {
            Ok(ver)
        }
    }

    #[inline]
    pub const fn is_standard(self) -> bool { self.0 <= TxVer::V2.0 }

    #[inline]
    pub const fn to_consensus_u32(&self) -> i32 { self.0 }
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
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
    pub const fn from_consensus_u32(lock_time: u32) -> Self { LockTime(lock_time) }

    #[inline]
    pub const fn to_consensus_u32(&self) -> u32 { self.0 }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BITCOIN)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct Tx {
    pub version: TxVer,
    pub inputs: VarIntArray<TxIn>,
    pub outputs: VarIntArray<TxOut>,
    pub lock_time: LockTime,
}

#[cfg(test)]
mod test {
    use amplify::hex::{FromHex, ToHex};

    use super::*;

    #[test]
    fn txid_byteorder() {
        let hex = "ed9f6388c0360c1861d331a0388d5a54815dd720cc67fa783c348217a0e943ca";
        let from_str = Txid::from_str(hex).unwrap();
        let from_hex = Txid::from_hex(hex).unwrap();
        assert_eq!(from_str, from_hex);
        assert_eq!(from_str.to_string(), from_str.to_hex());
        assert_eq!(from_str.to_string(), hex);
        assert_eq!(format!("{from_str:x}"), hex);
        assert_eq!(from_str[0], 0xca);
    }

    #[test]
    fn sats() {
        assert_eq!(Sats(0).0, 0);
        assert_eq!(Sats(0).btc_round(), 0);
        assert_eq!(Sats(0).btc_ceil(), 0);
        assert_eq!(Sats(0).btc_floor(), 0);
        assert_eq!(Sats(0).sats(), 0);
        assert_eq!(Sats(0).sats_rem(), 0);

        assert_eq!(Sats(1000).0, 1000);
        assert_eq!(Sats(1000).btc_round(), 0);
        assert_eq!(Sats(1000).btc_ceil(), 1);
        assert_eq!(Sats(1000).btc_floor(), 0);
        assert_eq!(Sats(1000).sats(), 1000);
        assert_eq!(Sats(1000).sats_rem(), 1000);

        assert_eq!(Sats(49_999_999).btc_round(), 0);
        assert_eq!(Sats(49_999_999).btc_ceil(), 1);
        assert_eq!(Sats(49_999_999).btc_floor(), 0);
        assert_eq!(Sats(50_000_000).0, 50_000_000);
        assert_eq!(Sats(50_000_000).btc_round(), 1);
        assert_eq!(Sats(50_000_000).btc_ceil(), 1);
        assert_eq!(Sats(50_000_000).btc_floor(), 0);
        assert_eq!(Sats(50_000_000).sats(), 50_000_000);
        assert_eq!(Sats(50_000_000).sats_rem(), 50_000_000);

        assert_eq!(Sats(99_999_999).btc_round(), 1);
        assert_eq!(Sats(99_999_999).btc_ceil(), 1);
        assert_eq!(Sats(99_999_999).btc_floor(), 0);
        assert_eq!(Sats(100_000_000), Sats::from_btc(1));
        assert_eq!(Sats(100_000_000).0, 100_000_000);
        assert_eq!(Sats(100_000_000).btc_round(), 1);
        assert_eq!(Sats(100_000_000).btc_ceil(), 1);
        assert_eq!(Sats(100_000_000).btc_floor(), 1);
        assert_eq!(Sats(100_000_000).sats(), 100_000_000);
        assert_eq!(Sats(100_000_000).sats_rem(), 0);
        assert_eq!(Sats(100_000_001).sats(), 100_000_001);
        assert_eq!(Sats(100_000_001).sats_rem(), 1);
        assert_eq!(Sats(110_000_000).sats(), 110_000_000);
        assert_eq!(Sats(110_000_000).sats_rem(), 10_000_000);
    }
}
