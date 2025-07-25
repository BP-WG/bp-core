// Bitcoin protocol core library.
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

//! Strict types library generator methods.

use dbc::LIB_NAME_BPCORE;
use strict_types::{CompileError, LibBuilder, TypeLib};

/// Strict types id for the library providing data types from [`dbc`] and
/// [`seals`] crates.
pub const LIB_ID_BPCORE: &str =
    "stl:nvSE47Z1-CpbRP8D-m2tdzo3-zmE6UE9-kU~HJm~-0pTqlGo#lagoon-concept-trade";

#[allow(clippy::result_large_err)]
fn _bp_core_stl() -> Result<TypeLib, CompileError> {
    LibBuilder::with(libname!(LIB_NAME_BPCORE), [
        strict_types::stl::std_stl().to_dependency_types(),
        bc::stl::bp_consensus_stl().to_dependency_types(),
        commit_verify::stl::commit_verify_stl().to_dependency_types(),
    ])
    .transpile::<seals::TxoSeal>()
    .transpile::<seals::WTxoSeal>()
    .transpile::<seals::Anchor>()
    .transpile::<seals::mpc::Source>()
    .compile()
}

/// Generates strict type library providing data types from [`dbc`] and
/// [`seals`] crates.
pub fn bp_core_stl() -> TypeLib { _bp_core_stl().expect("invalid strict type BPCore library") }

#[cfg(test)]
mod test {
    #![cfg_attr(coverage_nightly, coverage(off))]

    use super::*;

    #[test]
    fn lib_id() {
        let lib = bp_core_stl();
        assert_eq!(lib.id().to_string(), LIB_ID_BPCORE);
    }
}
