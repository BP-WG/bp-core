// Bitcoin protocol single-use-seals library.
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

//! Witness-output enabled TxO-seals allow constructing graphs of seals, useful in protocols like
//! RGB.

use bc::{Outpoint, Vout};
use commit_verify::{Sha256, StrictHash};

use crate::{Noise, TxoSealExt};

/// A single-use seal definition type allowing seals to point to the output of the same transaction
/// (witness transaction) which commits to the message defining the seals.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = dbc::LIB_NAME_BPCORE, tags = custom, dumb = Self::Wout(strict_dumb!()))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(untagged))]
pub enum WOutpoint {
    /// A seal definition pointing to an output of a not-yet-existing witness transaction closing
    /// some other seals, which will contain a commitment to this seal definition (witness
    /// transaction).
    #[display("~:{0}")]
    #[strict_type(tag = 0)]
    Wout(Vout),

    /// A seal definition pointing to an output of an already existing transaction.
    #[display(inner)]
    #[strict_type(tag = 1)]
    Extern(Outpoint),
}

/// A composed single-use seal definition type, which includes a primary and a fallback seal.
///
/// The type allows creation of seals pointing to the output of the same transaction (witness
/// transaction) which commits to the message defining the seals.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Display)]
#[display("{primary}/{secondary}")]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = dbc::LIB_NAME_BPCORE)]
#[derive(CommitEncode)]
#[commit_encode(strategy = strict, id = StrictHash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct WTxoSeal {
    /// A primary seal definition.
    pub primary: WOutpoint,
    /// A fallback seal definition.
    pub secondary: TxoSealExt,
}

impl WTxoSeal {
    /// Creates a new witness-output-based seal definition without a fallback.
    ///
    /// # Arguments
    ///
    /// `nonce` is a deterministic incremental number, preventing from creating the same seal if the
    /// same output is used.
    pub fn vout_no_fallback(vout: Vout, noise_engine: Sha256, nonce: u64) -> Self {
        Self::with(WOutpoint::Wout(vout), noise_engine, nonce)
    }

    /// Creates a new external outpoint-based seal definition without a fallback.
    ///
    /// # Arguments
    ///
    /// `nonce` is a deterministic incremental number, preventing from creating the same seal if the
    /// same output is used.
    pub fn no_fallback(outpoint: Outpoint, noise_engine: Sha256, nonce: u64) -> Self {
        Self::with(WOutpoint::Extern(outpoint), noise_engine, nonce)
    }

    /// Creates a new seal definition without a fallback.
    ///
    /// # Arguments
    ///
    /// `nonce` is a deterministic incremental number, preventing from creating the same seal if the
    /// same output is used.
    pub fn with(outpoint: WOutpoint, noise_engine: Sha256, nonce: u64) -> Self {
        Self {
            primary: outpoint,
            secondary: TxoSealExt::Noise(Noise::with(outpoint, noise_engine, nonce)),
        }
    }
}
