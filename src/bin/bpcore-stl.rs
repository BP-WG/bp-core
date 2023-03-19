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

use std::io::stdout;
use std::str::FromStr;
use std::{env, fs, io};

use amplify::num::u24;
use bc::{Txid, LIB_NAME_BITCOIN};
use commit_verify::{mpc, LIB_NAME_COMMIT_VERIFY};
use dbc::LIB_NAME_BPCORE;
use seals::txout::TxPtr;
use strict_encoding::{StrictEncode, StrictWriter};
use strict_types::typelib::LibBuilder;
use strict_types::{Dependency, TypeLib, TypeLibId};

fn export(root: &str, lib: TypeLib) -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    let id = lib.id();

    let ext = match args.get(1).map(String::as_str) {
        Some("--stl") => "stl",
        Some("--asc") => "asc.stl",
        Some("--sty") => "sty",
        _ => "sty",
    };
    let filename = args
        .get(2)
        .cloned()
        .unwrap_or_else(|| format!("stl/{root}.{ext}"));
    let mut file = match args.len() {
        1 => Box::new(stdout()) as Box<dyn io::Write>,
        2 | 3 => Box::new(fs::File::create(filename)?) as Box<dyn io::Write>,
        _ => panic!("invalid argument count"),
    };
    match ext {
        "stl" => {
            lib.strict_encode(StrictWriter::with(u24::MAX.into_usize(), file))?;
        }
        "asc.stl" => {
            writeln!(file, "{lib:X}")?;
        }
        _ => {
            writeln!(
                file,
                "{{-
  Id: {id:+}
  Name: BPCore
  Description: Consensus layer for bitcoin protocol
  Author: Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
  Copyright (C) 2023 LNP/BP Standards Association. All rights reserved.
  License: Apache-2.0
-}}\n"
            )?;
            writeln!(file, "{lib}")?;
        }
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let lib = LibBuilder::new(libname!(LIB_NAME_BITCOIN))
        .process::<bc::Tx>()?
        .compile(none!())?;
    let bitcoin_id = lib.id();
    export("Bitcoin", lib)?;

    let commit_id =
        TypeLibId::from_str("texas_year_ethnic_CPr8tcdPqWZ3KP8dXNPYavTEkbn8PG7CoJHtfwDFKRHJ")
            .expect("embedded id");
    let imports = bset! {
        Dependency::with(commit_id, libname!(LIB_NAME_COMMIT_VERIFY)),
        Dependency::with(bitcoin_id, libname!(LIB_NAME_BITCOIN)),
    };

    let lib = LibBuilder::new(libname!(LIB_NAME_BPCORE))
        .process::<dbc::AnchorId>()?
        .process::<dbc::Anchor<mpc::MerkleTree>>()?
        .process::<dbc::Anchor<mpc::MerkleBlock>>()?
        .process::<dbc::Anchor<mpc::MerkleProof>>()?
        .process::<seals::txout::ExplicitSeal<TxPtr>>()?
        .process::<seals::txout::ExplicitSeal<Txid>>()?
        .process::<seals::txout::blind::SecretSeal>()?
        .process::<seals::txout::blind::BlindSeal<TxPtr>>()?
        .process::<seals::txout::blind::BlindSeal<Txid>>()?
        .compile(imports)?;
    export("BPCore", lib)
}
