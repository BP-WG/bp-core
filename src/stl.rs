// Bitcoin protocol core library.
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

//! Strict types library generator methods.

use dbc::opret::OpretProof;
use dbc::tapret::TapretProof;
use dbc::LIB_NAME_BPCORE;
use strict_types::{CompileError, LibBuilder, TypeLib};

/// Strict types id for the library providing data types from [`dbc`] and
/// [`seals`] crates.
pub const LIB_ID_BPCORE: &str =
    "stl:xM0Q4fBV-9f68DxC-koz0lAW-70tm5F2-gLljyhC-YmIuIgI#inca-nevada-garbo";

fn _bp_core_stl() -> Result<TypeLib, CompileError> {
    LibBuilder::new(libname!(LIB_NAME_BPCORE), tiny_bset! {
        strict_types::stl::std_stl().to_dependency(),
        bc::stl::bp_tx_stl().to_dependency(),
        commit_verify::stl::commit_verify_stl().to_dependency()
    })
    .transpile::<seals::TxoSeal<OpretProof>>()
    .transpile::<seals::TxoSeal<TapretProof>>()
    .transpile::<seals::Anchor<OpretProof>>()
    .transpile::<seals::Anchor<TapretProof>>()
    .compile()
}

/// Generates strict type library providing data types from [`dbc`] and
/// [`seals`] crates.
pub fn bp_core_stl() -> TypeLib { _bp_core_stl().expect("invalid strict type BPCore library") }

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn lib_id() {
        let lib = bp_core_stl();
        assert_eq!(lib.id().to_string(), LIB_ID_BPCORE);
    }
}
