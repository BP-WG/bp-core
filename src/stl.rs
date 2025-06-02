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

use bc::Txid;
use strict_types::{CompileError, LibBuilder, TypeLib};

use crate::txout::TxPtr;
use crate::{txout, SecretSeal, LIB_NAME_SEALS};

/// Strict types id for the library providing data types from [`dbc`] and
/// [`seals`] crates.
pub const LIB_ID_SEALS: &str =
    "stl:p0b06g9M-oDFrSz4-_Ne1liv-0YVr10s-j8o1zLa-UlQHZBg#balloon-oscar-george";

fn _bp_seals_stl() -> Result<TypeLib, CompileError> {
    LibBuilder::with(libname!(LIB_NAME_SEALS), [
        strict_types::stl::std_stl().to_dependency_types(),
        bc::stl::bp_consensus_stl().to_dependency_types(),
        commit_verify::stl::commit_verify_stl().to_dependency_types(),
    ])
    .transpile::<txout::ExplicitSeal<TxPtr>>()
    .transpile::<txout::ExplicitSeal<Txid>>()
    .transpile::<SecretSeal>()
    .transpile::<txout::BlindSeal<TxPtr>>()
    .transpile::<txout::BlindSeal<Txid>>()
    .compile()
}

/// Generates strict type library providing data types from [`dbc`] and
/// [`seals`] crates.
pub fn bp_seals_stl() -> TypeLib { _bp_seals_stl().expect("invalid strict type BPCore library") }

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn lib_id() {
        let lib = bp_seals_stl();
        assert_eq!(lib.id().to_string(), LIB_ID_SEALS);
    }
}
