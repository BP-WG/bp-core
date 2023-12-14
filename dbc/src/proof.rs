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

use bc::Tx;
use commit_verify::{mpc, CommitEncode};
use strict_encoding::{StrictDecode, StrictDumb, StrictEncode};

/// Deterministic bitcoin commitment proof types.
pub trait Proof:
    Clone + Eq + CommitEncode + Debug + StrictEncode + StrictDecode + StrictDumb
{
    /// Verification error.
    type Error: Error;

    /// Verifies DBC proof against the provided transaction.
    fn verify(&self, msg: &mpc::Commitment, tx: &Tx) -> Result<(), Self::Error>;
}
