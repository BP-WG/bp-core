// Bitcoin protocol core library.
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

#[macro_use]
extern crate amplify;
#[macro_use]
extern crate strict_types;

use std::str::FromStr;

use bp::LIB_NAME_BP;
use commit_verify::{mpc, LIB_NAME_COMMIT_VERIFY};
use strict_types::typelib::LibBuilder;
use strict_types::{Dependency, TypeLibId};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sty_id =
        TypeLibId::from_str("eric_pablo_junior_6dNLcuqHACv1yYndmvNnXHuP7g3DV4qVkSf9tou6cDBm")
            .expect("embedded id");
    let imports = bmap! {
        libname!(LIB_NAME_COMMIT_VERIFY) => (lib_alias!(LIB_NAME_COMMIT_VERIFY), Dependency::with(sty_id, libname!(LIB_NAME_COMMIT_VERIFY), (0,10,0))),
    };

    let lib = LibBuilder::new(libname!(LIB_NAME_BP))
        .process::<bc::Tx>()?
        .process::<dbc::AnchorId>()?
        .process::<dbc::Anchor<mpc::MerkleTree>>()?
        .process::<dbc::Anchor<mpc::MerkleBlock>>()?
        .process::<dbc::Anchor<mpc::MerkleProof>>()?
        .process::<seals::txout::ExplicitSeal>()?
        .process::<seals::txout::blind::ConcealedSeal>()?
        .process::<seals::txout::blind::RevealedSeal>()?
        .compile(imports)?;
    let id = lib.id();

    println!(
        "{{-
  Id: {id:+}
  Name: BPCore
  Description: Consensus layer for bitcoin protocol
  Author: Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
  Copyright (C) 2023 LNP/BP Standards Association. All rights reserved.
  License: Apache-2.0
-}}\n"
    );
    println!("{lib}");
    println!("{lib:X}");

    Ok(())
}
