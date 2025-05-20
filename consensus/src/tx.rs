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

use core::slice;
use std::fmt::{self, Debug, Display, Formatter, LowerHex};
use std::iter::Sum;
use std::num::ParseIntError;
use std::ops::{Div, Rem};
use std::str::FromStr;

use amplify::hex::{self, FromHex, ToHex};
use amplify::{ByteArray, Bytes32StrRev, Wrapper};
use commit_verify::{DigestExt, Sha256};

use crate::{
    ConsensusDecode, ConsensusDecodeError, ConsensusEncode, LockTime, NonStandardValue,
    ScriptPubkey, SeqNo, SigScript, VarIntArray, Witness, Wtxid, LIB_NAME_BITCOIN,
};

#[derive(Wrapper, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, From)]
#[wrapper(AsSlice)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BITCOIN)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(transparent))]
#[wrapper(BorrowSlice, Index, RangeOps, Debug, Hex, Display, FromStr)]
// all-zeros used in coinbase
pub struct Txid(
    #[from]
    #[from([u8; 32])]
    Bytes32StrRev,
);

impl From<Txid> for [u8; 32] {
    fn from(txid: Txid) -> Self { txid.to_byte_array() }
}

impl Txid {
    #[inline]
    pub const fn coinbase() -> Self { Self(Bytes32StrRev::zero()) }
    #[inline]
    pub fn is_coinbase(&self) -> bool { self.to_byte_array() == [0u8; 32] }
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Display, From)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BITCOIN)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(transparent))]
#[display(inner)]
// 0xFFFFFFFF used in coinbase
pub struct Vout(u32);

impl Vout {
    pub const fn from_u32(u: u32) -> Self { Vout(u) }
    #[inline]
    pub const fn into_u32(self) -> u32 { self.0 }
    #[inline]
    pub const fn into_usize(self) -> usize { self.0 as usize }
    #[inline]
    pub const fn to_u32(&self) -> u32 { self.0 }
    #[inline]
    pub const fn to_usize(&self) -> usize { self.0 as usize }
}

impl FromStr for Vout {
    type Err = ParseIntError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> { s.parse().map(Self) }
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Display)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BITCOIN)]
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
    pub const fn coinbase() -> Self {
        Self {
            txid: Txid::coinbase(),
            vout: Vout::from_u32(0),
        }
    }

    #[inline]
    pub fn vout_u32(self) -> u32 { self.vout.into_u32() }

    #[inline]
    pub fn vout_usize(self) -> usize { self.vout.into_usize() }

    #[inline]
    pub fn is_coinbase(&self) -> bool { self.txid.is_coinbase() && self.vout.into_u32() == 0 }
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

#[cfg(feature = "serde")]
mod _serde_outpoint {
    use serde::de::{SeqAccess, Visitor};
    use serde::ser::SerializeTuple;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use super::*;

    impl Serialize for Outpoint {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer {
            if serializer.is_human_readable() {
                serializer.serialize_str(&self.to_string())
            } else {
                let mut ser = serializer.serialize_tuple(2)?;
                ser.serialize_element(&self.txid)?;
                ser.serialize_element(&self.vout)?;
                ser.end()
            }
        }
    }

    impl<'de> Deserialize<'de> for Outpoint {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: Deserializer<'de> {
            use serde::de::Error;
            if deserializer.is_human_readable() {
                String::deserialize(deserializer).and_then(|string| {
                    Self::from_str(&string)
                        .map_err(|_| D::Error::custom("wrong outpoint string representation"))
                })
            } else {
                struct OutpointVisitor;

                impl<'de> Visitor<'de> for OutpointVisitor {
                    type Value = Outpoint;

                    fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                        write!(formatter, "a transaction outpoint")
                    }

                    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
                    where A: SeqAccess<'de> {
                        let mut outpoint = Outpoint::coinbase();
                        outpoint.txid =
                            seq.next_element()?.ok_or_else(|| Error::invalid_length(0, &self))?;
                        outpoint.vout =
                            seq.next_element()?.ok_or_else(|| Error::invalid_length(1, &self))?;
                        Ok(outpoint)
                    }
                }

                deserializer.deserialize_tuple(2, OutpointVisitor)
            }
        }
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BITCOIN)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all = "camelCase"))]
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
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(transparent))]
pub struct Sats(
    #[from]
    #[from(u32)]
    #[from(u16)]
    #[from(u8)]
    pub u64,
);

impl Sats {
    pub const ZERO: Self = Sats(0);
    #[allow(clippy::inconsistent_digit_grouping)]
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

    pub const fn btc_sats(&self) -> (u64, u64) { (self.btc_floor(), self.sats_rem()) }

    #[must_use]
    pub fn checked_add(&self, other: impl Into<Self>) -> Option<Self> {
        self.0.checked_add(other.into().0).map(Self)
    }
    #[must_use]
    pub fn checked_sub(&self, other: impl Into<Self>) -> Option<Self> {
        self.0.checked_sub(other.into().0).map(Self)
    }

    #[must_use]
    pub fn checked_add_assign(&mut self, other: impl Into<Self>) -> Option<Self> {
        *self = Self(self.0.checked_add(other.into().0)?);
        Some(*self)
    }

    #[must_use]
    pub fn checked_sub_assign(&mut self, other: impl Into<Self>) -> Option<Self> {
        *self = Self(self.0.checked_sub(other.into().0)?);
        Some(*self)
    }

    #[must_use]
    pub fn saturating_add(&self, other: impl Into<Self>) -> Self {
        self.0.saturating_add(other.into().0).into()
    }

    #[must_use]
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

impl Div<usize> for Sats {
    type Output = Sats;
    fn div(self, rhs: usize) -> Self::Output { Sats(self.0 / rhs as u64) }
}

impl Rem<usize> for Sats {
    type Output = Sats;
    fn rem(self, rhs: usize) -> Self::Output { Sats(self.0 % rhs as u64) }
}

impl Display for Sats {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result { Display::fmt(&self.0, f) }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, Default)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BITCOIN)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all = "camelCase"))]
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
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
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

#[derive(Clone, Eq, PartialEq, Hash, Debug, Display)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BITCOIN)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all = "camelCase"))]
#[display(LowerHex)]
pub struct Tx {
    pub version: TxVer,
    pub inputs: VarIntArray<TxIn>,
    pub outputs: VarIntArray<TxOut>,
    pub lock_time: LockTime,
}

impl LowerHex for Tx {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&self.consensus_serialize().to_hex())
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Display, Error, From)]
#[display(inner)]
pub enum BlockDataParseError {
    #[from]
    Hex(hex::Error),
    #[from]
    Consensus(ConsensusDecodeError),
}

impl FromStr for Tx {
    type Err = BlockDataParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let data = Vec::<u8>::from_hex(s)?;
        Tx::consensus_deserialize(data).map_err(BlockDataParseError::from)
    }
}

impl Tx {
    #[inline]
    pub fn inputs(&self) -> slice::Iter<TxIn> { self.inputs.iter() }

    #[inline]
    pub fn outputs(&self) -> slice::Iter<TxOut> { self.outputs.iter() }

    #[inline]
    pub fn is_segwit(&self) -> bool { self.inputs().any(|txin| !txin.witness.is_empty()) }

    #[inline]
    pub fn to_unsigned_tx(&self) -> Tx {
        let mut tx = self.clone();
        for input in &mut tx.inputs {
            input.sig_script = SigScript::empty();
            input.witness = empty!();
        }
        tx
    }

    /// Computes a "normalized TXID" which does not include any signatures.
    ///
    /// This gives a way to identify a transaction that is "the same" as
    /// another in the sense of having same inputs and outputs.
    pub fn ntxid(&self) -> [u8; 32] { self.to_unsigned_tx().txid().to_byte_array() }

    /// Computes the [`Txid`].
    ///
    /// Hashes the transaction **excluding** the segwit data (i.e. the marker,
    /// flag bytes, and the witness fields themselves). For non-segwit
    /// transactions which do not have any segwit data, this will be equal
    /// to [`Tx::wtxid()`].
    pub fn txid(&self) -> Txid {
        let mut enc = Sha256::default();
        self.version.consensus_encode(&mut enc).expect("engines don't error");
        self.inputs.consensus_encode(&mut enc).expect("engines don't error");
        self.outputs.consensus_encode(&mut enc).expect("engines don't error");
        self.lock_time.consensus_encode(&mut enc).expect("engines don't error");
        let mut double = Sha256::default();
        double.input_raw(&enc.finish());
        Txid::from_byte_array(double.finish())
    }

    /// Computes the segwit version of the transaction id.
    ///
    /// Hashes the transaction **including** all segwit data (i.e. the marker,
    /// flag bytes, and the witness fields themselves). For non-segwit
    /// transactions which do not have any segwit data, this will be equal
    /// to [`Transaction::txid()`].
    pub fn wtxid(&self) -> Wtxid {
        let mut enc = Sha256::default();
        self.consensus_encode(&mut enc).expect("engines don't error");
        let mut double = Sha256::default();
        double.input_raw(&enc.finish());
        Wtxid::from_byte_array(double.finish())
    }
}

#[cfg(test)]
mod test {
    #![cfg_attr(coverage_nightly, coverage(off))]

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

    #[test]
    fn nonsegwit_transaction() {
        let tx =
            "0100000001a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c49\
            3046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7\
            f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506e\
            fdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff0100e1f505000000001976a9140389035a9225b\
            3839e2bbf32d826a1e222031fd888ac00000000";
        let realtx = Tx::from_str(tx).unwrap();

        assert_eq!(&realtx.to_string(), tx);
        assert_eq!(&realtx.to_hex(), tx);
        assert_eq!(&format!("{realtx:x}"), tx);

        // All these tests aren't really needed because if they fail, the hash check at
        // the end will also fail. But these will show you where the failure is
        // so I'll leave them in.
        assert_eq!(realtx.version, TxVer::V1);
        assert_eq!(realtx.inputs.len(), 1);
        // In particular this one is easy to get backward -- in bitcoin hashes are
        // encoded as little-endian 256-bit numbers rather than as data strings.
        assert_eq!(
            format!("{:x}", realtx.inputs[0].prev_output.txid),
            "ce9ea9f6f5e422c6a9dbcddb3b9a14d1c78fab9ab520cb281aa2a74a09575da1".to_string()
        );
        assert_eq!(realtx.inputs[0].prev_output.vout, Vout::from_u32(1));
        assert_eq!(realtx.outputs.len(), 1);
        assert_eq!(realtx.lock_time, LockTime::ZERO);

        assert_eq!(
            format!("{:x}", realtx.txid()),
            "a6eab3c14ab5272a58a5ba91505ba1a4b6d7a3a9fcbd187b6cd99a7b6d548cb7".to_string()
        );
        assert_eq!(
            format!("{:x}", realtx.wtxid()),
            "a6eab3c14ab5272a58a5ba91505ba1a4b6d7a3a9fcbd187b6cd99a7b6d548cb7".to_string()
        );
        /* TODO: Enable once weight calculation is there
        assert_eq!(realtx.weight().to_wu() as usize, tx_bytes.len() * WITNESS_SCALE_FACTOR);
        assert_eq!(realtx.total_size(), tx_bytes.len());
        assert_eq!(realtx.vsize(), tx_bytes.len());
        assert_eq!(realtx.base_size(), tx_bytes.len());
         */
    }

    #[test]
    fn segwit_transaction() {
        let tx =
            "02000000000101595895ea20179de87052b4046dfe6fd515860505d6511a9004cf12a1f93cac7c01000000\
            00ffffffff01deb807000000000017a9140f3444e271620c736808aa7b33e370bd87cb5a078702483045022\
            100fb60dad8df4af2841adc0346638c16d0b8035f5e3f3753b88db122e70c79f9370220756e6633b17fd271\
            0e626347d28d60b0a2d6cbb41de51740644b9fb3ba7751040121028fa937ca8cba2197a37c007176ed89410\
            55d3bcb8627d085e94553e62f057dcc00000000";
        let realtx = Tx::from_str(tx).unwrap();

        assert_eq!(&realtx.to_string(), tx);
        assert_eq!(&realtx.to_hex(), tx);
        assert_eq!(&format!("{realtx:x}"), tx);

        // All these tests aren't really needed because if they fail, the hash check at
        // the end will also fail. But these will show you where the failure is
        // so I'll leave them in.
        assert_eq!(realtx.version, TxVer::V2);
        assert_eq!(realtx.inputs.len(), 1);
        // In particular this one is easy to get backward -- in bitcoin hashes are
        // encoded as little-endian 256-bit numbers rather than as data strings.
        assert_eq!(
            format!("{:x}", realtx.inputs[0].prev_output.txid),
            "7cac3cf9a112cf04901a51d605058615d56ffe6d04b45270e89d1720ea955859".to_string()
        );
        assert_eq!(realtx.inputs[0].prev_output.vout, Vout::from_u32(1));
        assert_eq!(realtx.outputs.len(), 1);
        assert_eq!(realtx.lock_time, LockTime::ZERO);

        assert_eq!(
            format!("{:x}", realtx.txid()),
            "f5864806e3565c34d1b41e716f72609d00b55ea5eac5b924c9719a842ef42206".to_string()
        );
        assert_eq!(
            format!("{:x}", realtx.wtxid()),
            "80b7d8a82d5d5bf92905b06f2014dd699e03837ca172e3a59d51426ebbe3e7f5".to_string()
        );

        /* TODO: Enable once weight calculation is there
        const EXPECTED_WEIGHT: Weight = Weight::from_wu(442);
        assert_eq!(realtx.weight(), EXPECTED_WEIGHT);
        assert_eq!(realtx.total_size(), tx_bytes.len());
        assert_eq!(realtx.vsize(), 111);

        let expected_strippedsize = (442 - realtx.total_size()) / 3;
        assert_eq!(realtx.base_size(), expected_strippedsize);

        // Construct a transaction without the witness data.
        let mut tx_without_witness = realtx;
        tx_without_witness.input.iter_mut().for_each(|input| input.witness.clear());
        assert_eq!(tx_without_witness.total_size(), tx_without_witness.total_size());
        assert_eq!(tx_without_witness.total_size(), expected_strippedsize);
         */
    }
}
