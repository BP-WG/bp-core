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

use std::fmt::{Debug, Display};
use std::str::FromStr;

use crate::LIB_NAME_BITCOIN;

/// the provided value {value} for {matter} is non-standard; while it is
/// accepted by the bitcoin consensus rules, the software prohibits from using
/// it.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Display, Error)]
#[display(doc_comments)]
pub struct NonStandardValue<T: Debug + Display> {
    pub value: T,
    pub matter: &'static str,
}

impl<T: Debug + Display> NonStandardValue<T> {
    pub const fn with(value: T, matter: &'static str) -> Self { NonStandardValue { value, matter } }
}

#[derive(Clone, Eq, PartialEq, Debug, Display, Error)]
#[display("invalid blockchain name '{0}'")]
pub struct ChainParseError(String);

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Display, Default)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BITCOIN, tags = repr, into_u8, try_from_u8)]
#[derive(CommitEncode)]
#[commit_encode(strategy = strict)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "lowercase")
)]
#[repr(u8)]
pub enum Chain {
    #[default]
    #[display("mainnet")]
    Bitcoin = 0x00,

    #[display("testnet")]
    Testnet3 = 0x83,

    #[display("regtest")]
    Regtest = 0x80,

    #[display("signet")]
    Signet = 0x84,
}

impl FromStr for Chain {
    type Err = ChainParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let chain = s.to_lowercase();
        Ok(match chain.as_str() {
            "mainnet" | "bitcoin" => Chain::Bitcoin,
            "testnet" | "testnet3" => Chain::Testnet3,
            "regtest" => Chain::Regtest,
            "signet" => Chain::Signet,
            _ => return Err(ChainParseError(chain)),
        })
    }
}

impl Chain {
    #[inline]
    pub fn is_test_chain(self) -> bool {
        match self {
            Chain::Bitcoin => false,
            Chain::Testnet3 | Chain::Regtest | Chain::Signet => true,
        }
    }
}

/// A variable-length unsigned integer.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BITCOIN)]
pub struct VarInt(pub u64);

#[allow(clippy::len_without_is_empty)] // VarInt has no concept of 'is_empty'.
impl VarInt {
    pub const fn new(u: u64) -> Self { VarInt(u) }

    pub fn with(u: impl Into<usize>) -> Self { VarInt(u.into() as u64) }

    /// Gets the length of this VarInt when encoded.
    ///
    /// Returns 1 for 0..=0xFC, 3 for 0xFD..=(2^16-1), 5 for 0x10000..=(2^32-1),
    /// and 9 otherwise.
    #[inline]
    pub const fn len(&self) -> usize {
        match self.0 {
            0..=0xFC => 1,
            0xFD..=0xFFFF => 3,
            0x10000..=0xFFFFFFFF => 5,
            _ => 9,
        }
    }

    pub const fn to_u64(&self) -> u64 { self.0 }
    pub const fn into_u64(self) -> u64 { self.0 }
    pub fn to_usize(&self) -> usize {
        usize::try_from(self.0).expect("transaction too large for a non-64 bit platform")
    }
    pub fn into_usize(self) -> usize { self.to_usize() }
}

impl<U: Into<u64> + Copy> PartialEq<U> for VarInt {
    fn eq(&self, other: &U) -> bool { self.0.eq(&(*other).into()) }
}
