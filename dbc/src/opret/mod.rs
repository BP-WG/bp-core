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

//! ScriptPubkey-based OP_RETURN commitments.

use bc::{ScriptPubkey, Tx, Txid};
use commit_verify::mpc::Commitment;

use crate::{Proof, LIB_NAME_BPCORE};

/// Errors covering failed anchor validation.
#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
#[display(doc_comments)]
pub enum OpretVerifyError {
    /// witness transaction {txid} contains invalid OP_RETURN commitment
    /// {present:x} instead of {expected:x}.
    OpretMismatch {
        /// Transaction id
        txid: Txid,
        /// Commitment from the first OP_RETURN transaction output
        present: ScriptPubkey,
        /// Expected commitment absent in the first OP_RETURN transaction output
        expected: ScriptPubkey,
    },

    /// witness transaction {0} does not contain any OP_RETURN commitment
    /// required by the seal definition.
    OpretAbsent(Txid),
}

/// Empty type for use inside [`crate::Anchor`] for opret commitment scheme.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Default)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BPCORE)]
#[derive(CommitEncode)]
#[commit_encode(strategy = strict)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct OpretProof(());

impl Proof for OpretProof {
    type Error = OpretVerifyError;

    fn verify(&self, msg: &Commitment, tx: &Tx) -> Result<(), OpretVerifyError> {
        // TODO: Use embed-commit-verify
        for txout in &tx.outputs {
            if txout.script_pubkey.is_op_return() {
                let expected = ScriptPubkey::op_return(msg.as_slice());
                if txout.script_pubkey == expected {
                    return Ok(());
                } else {
                    return Err(OpretVerifyError::OpretMismatch {
                        txid: tx.txid(),
                        present: txout.script_pubkey.clone(),
                        expected,
                    });
                }
            }
        }
        Err(OpretVerifyError::OpretAbsent(tx.txid()))
    }
}
