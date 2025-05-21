// Deterministic bitcoin commitments library.
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

//! ScriptPubkey-based OP_RETURN commitments.

mod tx;
mod txout;
mod spk;

use bc::Tx;
use commit_verify::mpc::Commitment;
use commit_verify::{CommitmentProtocol, EmbedCommitVerify, EmbedVerifyError};
use strict_encoding::{StrictDeserialize, StrictSerialize};

use crate::LIB_NAME_BPCORE;

/// Marker non-instantiable enum defining LNPBP-12 taproot OP_RETURN (`opret`) protocol.
pub enum OpretFirst {}

impl CommitmentProtocol for OpretFirst {}

/// Errors during tapret commitment.
#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all = "camelCase"))]
#[display(doc_comments)]
pub enum OpretError {
    /// transaction doesn't contain OP_RETURN output.
    NoOpretOutput,

    /// first OP_RETURN output inside the transaction already contains some
    /// data.
    InvalidOpretScript,
}

/// Empty type for use inside [`crate::Anchor`] for opret commitment scheme.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Default)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BPCORE)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all = "camelCase"))]
pub struct OpretProof(());

impl StrictSerialize for OpretProof {}
impl StrictDeserialize for OpretProof {}

impl OpretProof {
    /// Verifies opret commitment againsy the proof.
    pub fn verify(&self, msg: &Commitment, tx: &Tx) -> Result<(), EmbedVerifyError<OpretError>> {
        tx.verify(msg, self)
    }
}
