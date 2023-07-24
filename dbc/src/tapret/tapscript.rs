// Deterministic bitcoin commitments library.
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

use std::io;
use std::str::FromStr;

use amplify::confinement::Confined;
use baid58::{Baid58ParseError, FromBaid58, ToBaid58};
use bc::{TapCode, TapScript};
use commit_verify::{mpc, CommitEncode, CommitVerify};
use strict_encoding::{StrictDeserialize, StrictSerialize};

use super::Lnpbp12;
use crate::LIB_NAME_BPCORE;

/// Hardcoded tapret script prefix consisting of 29 `OP_RESERVED` pushes,
/// followed by `OP_RETURN` and `OP_PUSHBYTES_33`.
pub const TAPRET_SCRIPT_COMMITMENT_PREFIX: [u8; 31] = [
    0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50,
    0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x6a, 0x21,
];

/// Information about tapret commitment.
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[display(Self::to_baid58_string)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BPCORE)]
#[derive(CommitEncode)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct TapretCommitment {
    /// LNPBP-4 multi-protocol commitment.
    pub mpc: mpc::Commitment,
    /// Nonce is used to put the commitment into the correct side of the tree.
    pub nonce: u8,
}

impl StrictSerialize for TapretCommitment {}
impl StrictDeserialize for TapretCommitment {}

impl From<[u8; 33]> for TapretCommitment {
    fn from(value: [u8; 33]) -> Self {
        let buf = Confined::try_from_iter(value).expect("exact size match");
        Self::from_strict_serialized::<33>(buf).expect("exact size match")
    }
}

impl ToBaid58<33> for TapretCommitment {
    const HRI: &'static str = "tapret";
    fn to_baid58_payload(&self) -> [u8; 33] {
        let mut data = io::Cursor::new([0u8; 33]);
        self.commit_encode(&mut data);
        data.into_inner()
    }
}
impl FromBaid58<33> for TapretCommitment {}

impl TapretCommitment {
    fn to_baid58_string(&self) -> String { format!("{:0^}", self.to_baid58()) }
}

impl FromStr for TapretCommitment {
    type Err = Baid58ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> { Self::from_baid58_str(s) }
}

impl TapretCommitment {
    /// Constructs information about tapret commitment.
    pub fn with(mpc: mpc::Commitment, nonce: u8) -> Self { Self { mpc, nonce } }
}

impl CommitVerify<TapretCommitment, Lnpbp12> for TapScript {
    /// Tapret script consists of 29 `OP_RESERVED` pushes, followed by
    /// `OP_RETURN`, `OP_PUSHBYTES_33` and serialized commitment data (MPC
    /// commitment + nonce as a single slice).
    fn commit(commitment: &TapretCommitment) -> Self {
        let mut tapret = TapScript::with_capacity(64);
        for _ in 0..29 {
            tapret.push_opcode(TapCode::Reserved);
        }
        tapret.push_opcode(TapCode::Return);
        let mut data = io::Cursor::new([0u8; 33]);
        commitment.commit_encode(&mut data);
        tapret.push_slice(&data.into_inner());
        tapret
    }
}

#[cfg(test)]
mod test {
    use amplify::RawArray;

    use super::*;

    pub fn commitment() -> TapretCommitment {
        TapretCommitment {
            mpc: mpc::Commitment::from_raw_array([0x6Cu8; 32]),
            nonce: 8,
        }
    }

    #[test]
    pub fn commitment_prefix() {
        let script = TapScript::commit(&commitment());
        assert_eq!(TAPRET_SCRIPT_COMMITMENT_PREFIX, script[0..31]);
    }

    #[test]
    pub fn commiment_serialization() {
        let commitment = commitment();
        let script = TapScript::commit(&commitment);
        assert_eq!(script[63], commitment.nonce);
        assert_eq!(&script[31..63], commitment.mpc.as_slice());
    }

    #[test]
    pub fn tapret_commitment_baid58() {
        let commitment = commitment();
        let encoded = commitment.to_baid58();
        let decoded = TapretCommitment::from_baid58(encoded).unwrap();
        let s = commitment.to_string();
        assert_eq!(s, "tapret04dm9azJKdXhE27U4MHX8GsmibZEJ6WBMNmeKXGLPJDNaLPKNm9R");
        assert_eq!(Ok(commitment.clone()), TapretCommitment::from_str(&s));
        assert_eq!(decoded, commitment);
    }
}
