// Deterministic bitcoin commitments library.
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

use std::error::Error;
use std::fmt::Debug;
use std::str::FromStr;

use bc::Tx;
use commit_verify::mpc;
use strict_encoding::{StrictDecode, StrictDeserialize, StrictDumb, StrictEncode, StrictSerialize};

use crate::LIB_NAME_BPCORE;

/// Trait defining DBC method - or enumberation of allowed DBC methods used by
/// proofs, single-use-seals etc.
pub trait DbcMethod:
    Copy
    + Eq
    + Ord
    + std::hash::Hash
    + strict_encoding::StrictDumb
    + strict_encoding::StrictEncode
    + strict_encoding::StrictDecode
{
}

/// wrong deterministic bitcoin commitment closing method id '{0}'.
#[derive(Clone, PartialEq, Eq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub struct MethodParseError(pub String);

/// Method of DBC construction.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BPCORE, tags = repr, into_u8, try_from_u8)]
#[repr(u8)]
pub enum Method {
    /// OP_RETURN commitment present in the first OP_RETURN-containing
    /// transaction output.
    #[display("opret1st")]
    #[strict_type(dumb)]
    OpretFirst = 0x00,

    /// Taproot-based OP_RETURN commitment present in the first Taproot
    /// transaction output.
    #[display("tapret1st")]
    TapretFirst = 0x01,
}

impl DbcMethod for Method {}

impl FromStr for Method {
    type Err = MethodParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_lowercase() {
            s if s == Method::OpretFirst.to_string() => Method::OpretFirst,
            s if s == Method::TapretFirst.to_string() => Method::TapretFirst,
            _ => return Err(MethodParseError(s.to_owned())),
        })
    }
}

/// Deterministic bitcoin commitment proof types.
pub trait Proof<M: DbcMethod = Method>:
    Clone + Eq + Debug + StrictSerialize + StrictDeserialize + StrictDumb
{
    /// Verification error.
    type Error: Error;

    /// Returns DBC method used by the proof.
    const METHOD: M;

    /// Verifies DBC proof against the provided transaction.
    fn verify(&self, msg: &mpc::Commitment, tx: &Tx) -> Result<(), Self::Error>;
}
