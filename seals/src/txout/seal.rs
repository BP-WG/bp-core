// Bitcoin protocol single-use-seals library.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2023 by
//     Dr. Maxim Orlovsky <orlovsky@lnp-bp.org>
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

use std::str::FromStr;

use bc::{Outpoint, Txid, Vout};

use super::MethodParseError;

/// Methods common for all transaction-output based seal types.
pub trait TxoSeal {
    /// Returns method which must be used for seal closing.
    fn method(&self) -> CloseMethod;

    /// Returns [`Txid`] part of the seal definition, if known.
    fn txid(&self) -> Option<Txid>;

    /// Returns transaction output number containing the defined seal.
    fn vout(&self) -> Vout;

    /// Returns [`Outpoint`] defining the seal, if txid is known.
    fn outpoint(&self) -> Option<Outpoint>;

    /// Returns [`Txid`] part of the seal definition, if known, or the provided
    /// `default_txid`.
    fn txid_or(&self, default_txid: Txid) -> Txid;

    /// Returns [`Outpoint`] defining the seal, if txid is known, or constructs
    /// one using the provided `default_txid`.
    fn outpoint_or(&self, default_txid: Txid) -> Outpoint;
}

/// Method of single-use-seal closing.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = bc::LIB_NAME_BP, tags = repr, into_u8, try_from_u8)]
#[repr(u8)]
#[non_exhaustive]
pub enum CloseMethod {
    /// Seal is closed over the message in form of OP_RETURN commitment present
    /// in the first OP_RETURN-containing transaction output.
    #[display("opret1st")]
    #[strict_type(dumb)]
    OpretFirst = 0x00,

    /// Seal is closed over the message in form of Taproot-based OP_RETURN
    /// commitment present in the first Taproot transaction output.
    #[display("tapret1st")]
    TapretFirst = 0x01,
}

impl FromStr for CloseMethod {
    type Err = MethodParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_lowercase() {
            s if s == CloseMethod::OpretFirst.to_string() => CloseMethod::OpretFirst,
            s if s == CloseMethod::TapretFirst.to_string() => CloseMethod::TapretFirst,
            _ => return Err(MethodParseError(s.to_owned())),
        })
    }
}
