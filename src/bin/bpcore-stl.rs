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

#![cfg_attr(coverage_nightly, feature(coverage_attribute), coverage(off))]

use std::fs;
use std::io::Write;

use bc::stl::{bp_consensus_stl, bp_tx_stl};
use bp::stl::bp_core_stl;
use commit_verify::stl::commit_verify_stl;
use commit_verify::CommitmentLayout;
use seals::WTxoSeal;
use strict_encoding::libname;
use strict_types::stl::std_stl;
use strict_types::{parse_args, SystemBuilder};

fn main() {
    let (format, dir) = parse_args();

    let mut lib = bp_tx_stl();
    lib.name = libname!("Tx");
    lib.serialize(
        format,
        dir.as_ref(),
        "0.1.0",
        Some(
            "
  Description: Bitcoin transaction library
  Author: Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
  Copyright (C) 2023-2024 LNP/BP Standards Association. All rights reserved.
  Copyright (C) 2024-2025 LNP/BP Labs, Institute for Distributed and Cognitive Systems (InDCS).
  License: Apache-2.0",
        ),
    )
    .expect("unable to write to the file");

    bp_consensus_stl()
        .serialize(
            format,
            dir.as_ref(),
            "0.1.0",
            Some(
                "
  Description: Consensus library for bitcoin protocol
  Author: Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
  Copyright (C) 2023-2024 LNP/BP Standards Association. All rights reserved.
  Copyright (C) 2024-2025 LNP/BP Labs, Institute for Distributed and Cognitive Systems (InDCS).
  License: Apache-2.0",
            ),
        )
        .expect("unable to write to the file");

    bp_core_stl()
        .serialize(
            format,
            dir.as_ref(),
            "0.1.0",
            Some(
                "
  Description: Bitcoin client-side-validation library
  Author: Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
  Copyright (C) 2023-2024 LNP/BP Standards Association. All rights reserved.
  Copyright (C) 2024-2025 LNP/BP Labs, Institute for Distributed and Cognitive Systems (InDCS).
  License: Apache-2.0",
            ),
        )
        .expect("unable to write to the file");

    let std = std_stl();
    let bc = bp_consensus_stl();
    let bp = bp_core_stl();
    let cv = commit_verify_stl();

    let sys = SystemBuilder::new()
        .import(bp)
        .unwrap()
        .import(bc)
        .unwrap()
        .import(cv)
        .unwrap()
        .import(std)
        .unwrap()
        .finalize()
        .expect("not all libraries are present");

    let dir = dir.unwrap_or_else(|| ".".to_owned());

    let mut file = fs::File::create(format!("{dir}/Seals.vesper")).unwrap();
    writeln!(
        file,
        "{{-
  Description: Bitcoin WTxO blind seals
  Author: Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
  Copyright (C) 2024 LNP/BP Standards Association. All rights reserved.
  Copyright (C) 2024-2025 LNP/BP Labs, Institute for Distributed and Cognitive Systems (InDCS).
  License: Apache-2.0
-}}

Seals vesper lexicon=types+commitments
"
    )
    .unwrap();
    let layout = WTxoSeal::commitment_layout();
    writeln!(file, "{layout}").unwrap();
    let tt = sys.type_tree("BPCore.WTxoSeal").unwrap();
    writeln!(file, "{tt}").unwrap();

    let tt = sys.type_tree("BPCore.Anchor").unwrap();
    fs::write(format!("{dir}/Anchor.vesper"), format!("{tt}")).unwrap();
}
