// Deterministic bitcoin commitments library.
//
// SPDX-License-Identifier: Apache-2.0
//
// Designed in 2019-2025 by Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
// Written in 2024-2025 by Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association, Switzerland.
// Copyright (C) 2024-2025 LNP/BP Labs, Institute for Distributed and Cognitive Systems (InDCS).
// Copyright (C) 2019-2025 Dr Maxim Orlovsky.
// All rights under the above copyrights are reserved.
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

use bc::opcodes::OP_RETURN;
use bc::ScriptPubkey;
use commit_verify::mpc::Commitment;
use commit_verify::{EmbedCommitProof, EmbedCommitVerify, EmbedVerifyError};

use crate::opret::{OpretError, OpretFirst, OpretProof};

impl EmbedCommitProof<Commitment, ScriptPubkey, OpretFirst> for OpretProof {
    fn restore_original_container(
        &self,
        commit_container: &ScriptPubkey,
    ) -> Result<ScriptPubkey, EmbedVerifyError<OpretError>> {
        if !commit_container.is_op_return() {
            return Err(OpretError::NoOpretOutput.into());
        }
        if commit_container.len() != 34 {
            return Err(OpretError::InvalidOpretScript.into());
        }
        Ok(ScriptPubkey::from_checked(vec![OP_RETURN]))
    }
}

impl EmbedCommitVerify<Commitment, OpretFirst> for ScriptPubkey {
    type Proof = OpretProof;
    type CommitError = OpretError;

    fn embed_commit(&mut self, msg: &Commitment) -> Result<Self::Proof, Self::CommitError> {
        if !self.is_op_return() {
            return Err(OpretError::NoOpretOutput);
        }
        if self.len() != 1 {
            return Err(OpretError::InvalidOpretScript);
        }
        *self = ScriptPubkey::op_return(msg.as_slice());
        Ok(OpretProof::default())
    }
}
