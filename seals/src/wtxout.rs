// Bitcoin protocol single-use-seals library.
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

//! Witness-output enabled TxO-seals allow constructing graphs of seals, useful in protocols like
//! RGB.

use amplify::Bytes;
use bc::{Outpoint, Vout};
use commit_verify::{DigestExt, Sha256, StrictHash};
use strict_encoding::StrictSum;

use crate::{Noise, TxoSealExt};

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = dbc::LIB_NAME_BPCORE, tags = custom, dumb = Self::Wout(strict_dumb!()))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(untagged))]
pub enum WOutpoint {
    #[display("~:{0}")]
    #[strict_type(tag = 0)]
    Wout(Vout),

    #[display(inner)]
    #[strict_type(tag = 1)]
    Extern(Outpoint),
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Display)]
#[display("{primary}/{secondary}")]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = dbc::LIB_NAME_BPCORE)]
#[derive(CommitEncode)]
#[commit_encode(strategy = strict, id = StrictHash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct WTxoSeal {
    pub primary: WOutpoint,
    pub secondary: TxoSealExt,
}

impl WTxoSeal {
    /// Creates a new witness output-based seal definition without fallback.
    ///
    /// # Arguments
    ///
    /// `nonce` is a deterministic incremental number, preventing from creating the same seal if the
    /// same output is used.
    pub fn vout_no_fallback(vout: Vout, noise_engine: Sha256, nonce: u64) -> Self {
        Self::with(WOutpoint::Wout(vout), noise_engine, nonce)
    }

    /// Creates a new witness output-based seal definition without fallback.
    ///
    /// # Arguments
    ///
    /// `nonce` is a deterministic incremental number, preventing from creating the same seal if the
    /// same output is used.
    pub fn no_fallback(outpoint: Outpoint, noise_engine: Sha256, nonce: u64) -> Self {
        Self::with(WOutpoint::Extern(outpoint), noise_engine, nonce)
    }

    pub fn with(outpoint: WOutpoint, mut noise_engine: Sha256, nonce: u64) -> Self {
        noise_engine.input_raw(&nonce.to_be_bytes());
        match outpoint {
            WOutpoint::Wout(wout) => {
                noise_engine.input_raw(&[WOutpoint::ALL_VARIANTS[0].0]);
                noise_engine.input_raw(&wout.to_u32().to_be_bytes());
            }
            WOutpoint::Extern(outpoint) => {
                noise_engine.input_raw(&[WOutpoint::ALL_VARIANTS[1].0]);
                noise_engine.input_raw(outpoint.txid.as_ref());
                noise_engine.input_raw(&outpoint.vout.to_u32().to_be_bytes());
            }
        }
        let mut noise = [0xFFu8; 40];
        noise[..32].copy_from_slice(&noise_engine.finish());
        Self {
            primary: outpoint,
            secondary: TxoSealExt::Noise(Noise::from(Bytes::from(noise))),
        }
    }
}
