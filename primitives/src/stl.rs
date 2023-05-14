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

use strict_types::typelib::{LibBuilder, TranslateError};
use strict_types::TypeLib;

use crate::Tx;

pub const LIB_NAME_BITCOIN: &str = "Bitcoin";
pub const LIB_ID_BITCOIN: &str = "circus_report_jeep_2bj6eDer24ZBSVq6JgQW2BrARt6vx56vMWzF35J45gzY";

fn _bitcoin_stl() -> Result<TypeLib, TranslateError> {
    LibBuilder::new(libname!(LIB_NAME_BITCOIN))
        .transpile::<Tx>()
        .compile(none!())
}

pub fn bitcoin_stl() -> TypeLib { _bitcoin_stl().expect("invalid strict type Bitcoin library") }

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn lib_id() {
        let lib = bitcoin_stl();
        assert_eq!(lib.id().to_string(), LIB_ID_BITCOIN);
    }
}
