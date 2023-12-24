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

use bc::{Tx, TxIn, TxOut};
use commit_verify::{mpc, CommitEncode};
use strict_encoding::{StrictDecode, StrictDeserialize, StrictDumb, StrictEncode, StrictSerialize};

use crate::tapret::TapretProof;
use crate::LIB_NAME_BPCORE;

pub trait Method: Copy + Eq {
    fn can_apply_to_input(&self, index: usize, script: &TxIn) -> bool;
    fn can_apply_to_output(&self, index: usize, script: &TxOut) -> bool;
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
pub enum FirstTapOpRet {
    /// Taproot-based OP_RETURN commitment present in the first Taproot
    /// transaction output.
    #[display("tapret1st")]
    TapretFirst = 0x00,

    /// OP_RETURN commitment present in the first OP_RETURN-containing
    /// transaction output.
    #[display("opret1st")]
    #[strict_type(dumb)]
    OpretFirst = 0x01,
}

impl FromStr for FirstTapOpRet {
    type Err = MethodParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_lowercase() {
            s if s == FirstTapOpRet::OpretFirst.to_string() => FirstTapOpRet::OpretFirst,
            s if s == FirstTapOpRet::TapretFirst.to_string() => FirstTapOpRet::TapretFirst,
            _ => return Err(MethodParseError(s.to_owned())),
        })
    }
}

/// Deterministic bitcoin commitment proof types.
pub trait Proof:
    Clone + Eq + Debug + CommitEncode + StrictSerialize + StrictDeserialize + StrictDumb
{
    /// Verification error.
    type Error: Error;

    /// Verifies DBC proof against the provided transaction.
    fn verify(&self, msg: &mpc::Commitment, tx: &Tx) -> Result<(), Self::Error>;
}

pub trait Protocol {
    type Proof: Proof;
    type Method: Method;
}

pub enum TapretFirst {}

impl Protocol for TapretFirst {
    type Proof = TapretProof;
    type Method = FirstTapOpRet;
}
