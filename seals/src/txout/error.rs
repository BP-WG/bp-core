// Bitcoin protocol single-use-seals library.
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

use bc::{Outpoint, Txid};

/// Seal verification errors.
#[derive(Debug, Display, From, Error)]
#[display(doc_comments)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub enum VerifyError {
    /// seals provided for a batch verification have inconsistent close method.
    InconsistentCloseMethod,

    /// the provided witness transaction {0} does not closes seal {1}.
    WitnessNotClosingSeal(Txid, Outpoint),

    /// tapret commitment is invalid.
    ///
    /// Details: {0}
    #[from]
    InvalidTapretCommitment(dbc::tapret::TapretError),
}

/// Error happening if the seal data holds only witness transaction output
/// number and thus can't be used alone for constructing full bitcoin
/// transaction output data which must include the witness transaction id
/// (unknown to the seal).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display, Error)]
#[display("witness txid is unknown; unable to reconstruct full outpoint data")]
pub struct WitnessVoutError;

/// wrong transaction output-based single-use-seal closing method id '{0}'.
#[derive(Clone, PartialEq, Eq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub struct MethodParseError(pub String);
