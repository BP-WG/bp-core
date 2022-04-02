// Deterministic bitcoin commitments library, implementing LNPBP standards
// Part of bitcoin protocol core library (BP Core Lib)
//
// Written in 2020-2022 by
//     Dr. Maxim Orlovsky <orlovsky@pandoracore.com>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the Apache 2.0 License
// along with this software.
// If not, see <https://opensource.org/licenses/Apache-2.0>.

#![cfg(any(feature = "consensus", feature = "wallet"))]

use bitcoin::blockdata::opcodes::all;
use bitcoin::blockdata::script;
use bitcoin_scripts::TapScript;
use commit_verify::multi_commit::MultiCommitment;
use commit_verify::{CommitEncode, CommitVerify};

use super::Lnpbp6;

impl CommitVerify<MultiCommitment, Lnpbp6> for TapScript {
    fn commit(msg: &MultiCommitment) -> Self {
        script::Builder::new()
            .push_opcode(all::OP_RETURN)
            .push_slice(&msg.commit_serialize())
            .into_script()
            .into()
    }
}
