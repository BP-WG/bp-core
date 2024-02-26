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

//! Bitcoin single-use-seals defined by a transaction output and closed by
//! spending that output ("TxOut seals").

pub mod blind;
mod error;
pub mod explicit;
mod seal;
mod witness;

pub use blind::{BlindSeal, ChainBlindSeal, SingleBlindSeal};
pub use error::{VerifyError, WitnessVoutError};
pub use explicit::ExplicitSeal;
pub use seal::{CloseMethod, SealTxid, TxPtr, TxoSeal};
pub use witness::Witness;
