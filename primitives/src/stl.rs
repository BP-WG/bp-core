// Bitcoin protocol primitives library.
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
// Coding conventions

use strict_types::{CompileError, LibBuilder, TypeLib};

use crate::{Tx, LIB_NAME_BITCOIN};

#[deprecated(since = "0.10.8", note = "use LIB_ID_BP_TX instead")]
pub const LIB_ID_BITCOIN: &str =
    "urn:ubideco:stl:6GgF7biXPVNcus2FfQj2pQuRzau11rXApMQLfCZhojgi#money-pardon-parody";
pub const LIB_ID_BP_TX: &str =
    "urn:ubideco:stl:6GgF7biXPVNcus2FfQj2pQuRzau11rXApMQLfCZhojgi#money-pardon-parody";

#[deprecated(since = "0.10.8", note = "use _bp_tx_stl instead")]
fn _bitcoin_stl() -> Result<TypeLib, CompileError> { _bp_tx_stl() }

fn _bp_tx_stl() -> Result<TypeLib, CompileError> {
    LibBuilder::new(libname!(LIB_NAME_BITCOIN), None)
        .transpile::<Tx>()
        .compile()
}

#[deprecated(since = "0.10.8", note = "use bp_tx_stl instead")]
pub fn bitcoin_stl() -> TypeLib { bp_tx_stl() }

pub fn bp_tx_stl() -> TypeLib {
    _bp_tx_stl().expect("invalid strict type Bitcoin transaction library")
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn lib_id() {
        let lib = bp_tx_stl();
        assert_eq!(lib.id().to_string(), LIB_ID_BP_TX);
    }
}
