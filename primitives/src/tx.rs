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

use core::slice;
use std::cmp::Ordering;
use std::fmt::{self, Debug, Display, Formatter};
use std::iter::Sum;
use std::num::ParseIntError;
use std::str::FromStr;
use std::vec;

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
    #[inline]
    pub fn into_u32(self) -> u32 { self.0 }
    #[inline]
    pub fn into_usize(self) -> usize { self.0 as usize }
}

impl FromStr for Vout {
    type Err = ParseIntError;

    #[inline]
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
    #[inline]
    pub fn new(txid: Txid, vout: impl Into<Vout>) -> Self {
        Self {
            txid,
            vout: vout.into(),
        }
    }

    #[inline]
    pub fn vout_u32(self) -> u32 { self.vout.into_u32() }

    #[inline]
    pub fn vout_usize(self) -> usize { self.vout.into_usize() }
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

impl IntoIterator for Witness {
    type Item = VarIntArray<u8>;
    type IntoIter = vec::IntoIter<VarIntArray<u8>>;

    fn into_iter(self) -> Self::IntoIter { self.0.into_iter() }
}

impl Witness {
    pub fn new() -> Self { default!() }

    pub fn elements(&self) -> impl Iterator<Item = &'_ [u8]> {
        self.0.iter().map(|el| el.as_slice())
    }

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

#[derive(
    Wrapper, WrapperMut, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, From, Default
)]
#[wrapper(Add, Sub, Mul, Div, FromStr)]
#[wrapper_mut(MathAssign)]
#[derive(StrictType, StrictEncode, StrictDecode)]
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
    pub fn from_sats(sats: impl Into<u64>) -> Self { Self(sats.into()) }

    pub const fn is_zero(&self) -> bool { self.0 == 0 }
    pub const fn is_non_zero(&self) -> bool { self.0 != 0 }

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

    pub fn sats_i64(&self) -> i64 {
        i64::try_from(self.0).expect("amount of sats exceeds total bitcoin supply")
    }

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

impl PartialEq<u64> for Sats {
    fn eq(&self, other: &u64) -> bool { self.0.eq(other) }
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

impl TxOut {
    pub fn new(script_pubkey: impl Into<ScriptPubkey>, value: impl Into<Sats>) -> Self {
        TxOut {
            script_pubkey: script_pubkey.into(),
            value: value.into(),
        }
    }
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
    pub const fn to_consensus_i32(&self) -> i32 { self.0 }
}

/// The Threshold for deciding whether a lock time value is a height or a time
/// (see [Bitcoin Core]).
///
/// `LockTime` values _below_ the threshold are interpreted as block heights,
/// values _above_ (or equal to) the threshold are interpreted as block times
/// (UNIX timestamp, seconds since epoch).
///
/// Bitcoin is able to safely use this value because a block height greater than
/// 500,000,000 would never occur because it would represent a height in
/// approximately 9500 years. Conversely, block times under 500,000,000 will
/// never happen because they would represent times before 1986 which
/// are, for obvious reasons, not useful within the Bitcoin network.
///
/// [Bitcoin Core]: https://github.com/bitcoin/bitcoin/blob/9ccaee1d5e2e4b79b0a7c29aadb41b97e4741332/src/script/script.h#L39
pub const LOCKTIME_THRESHOLD: u32 = 500_000_000;

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BITCOIN)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct LockTime(u32);

impl PartialOrd for LockTime {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        if self.is_height_based() != other.is_height_based() {
            None
        } else {
            Some(self.0.cmp(&other.0))
        }
    }
}

impl LockTime {
    /// Create zero time lock
    #[inline]
    pub const fn zero() -> Self { Self(0) }

    /// Creates absolute time lock with the given block height.
    ///
    /// Block height must be strictly less than `0x1DCD6500`, otherwise
    /// `None` is returned.
    #[inline]
    pub const fn from_height(height: u32) -> Option<Self> {
        if height < LOCKTIME_THRESHOLD {
            Some(Self(height))
        } else {
            None
        }
    }

    /// Creates absolute time lock with the given UNIX timestamp value.
    ///
    /// Timestamp value must be greater or equal to `0x1DCD6500`, otherwise
    /// `None` is returned.
    #[inline]
    pub const fn from_unix_timestamp(timestamp: u32) -> Option<Self> {
        if timestamp < LOCKTIME_THRESHOLD {
            None
        } else {
            Some(Self(timestamp))
        }
    }

    /// Converts into full u32 representation of `nLockTime` value as it is
    /// serialized in bitcoin transaction.
    #[inline]
    pub const fn from_consensus_u32(lock_time: u32) -> Self { LockTime(lock_time) }

    #[inline]
    pub const fn to_consensus_u32(&self) -> u32 { self.0 }

    #[inline]
    pub const fn into_consensus_u32(self) -> u32 { self.0 }

    /// Checks if the absolute timelock provided by the `nLockTime` value
    /// specifies height-based lock
    #[inline]
    pub const fn is_height_based(self) -> bool { self.0 < LOCKTIME_THRESHOLD }

    /// Checks if the absolute timelock provided by the `nLockTime` value
    /// specifies time-based lock
    #[inline]
    pub const fn is_time_based(self) -> bool { !self.is_height_based() }
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

impl Tx {
    #[inline]
    pub fn inputs(&self) -> slice::Iter<TxIn> { self.inputs.iter() }

    #[inline]
    pub fn outputs(&self) -> slice::Iter<TxOut> { self.outputs.iter() }

    #[inline]
    pub fn is_segwit(&self) -> bool { self.inputs().any(|txin| !txin.witness.is_empty()) }
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
