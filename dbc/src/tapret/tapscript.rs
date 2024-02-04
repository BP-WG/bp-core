// Deterministic bitcoin commitments library.
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

use std::fmt::{self, Display, Formatter};
use std::io;
use std::str::FromStr;

use amplify::confinement::Confined;
use bc::{TapCode, TapScript};
use commit_verify::{mpc, CommitVerify};
use strict_encoding::{
    DecodeError, DeserializeError, StrictDeserialize, StrictEncode, StrictSerialize,
};

use super::TapretFirst;
use crate::LIB_NAME_BPCORE;

/// Hardcoded tapret script prefix consisting of 29 `OP_RESERVED` pushes,
/// followed by `OP_RETURN` and `OP_PUSHBYTES_33`.
pub const TAPRET_SCRIPT_COMMITMENT_PREFIX: [u8; 31] = [
    0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50,
    0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x6a, 0x21,
];

/// Information about tapret commitment.
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BPCORE)]
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

impl TapretCommitment {
    /// Returns serialized representation of the commitment data.
    pub fn to_vec(&self) -> Vec<u8> {
        self.to_strict_serialized::<33>()
            .expect("exact size match")
            .into_inner()
    }
}

impl Display for TapretCommitment {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let s = base85::encode(&self.to_vec());
        f.write_str(&s)
    }
}
impl FromStr for TapretCommitment {
    type Err = DeserializeError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let data = base85::decode(s).map_err(|err| {
            DecodeError::DataIntegrityError(format!(
                "invalid Base85 encoding of tapret data \"{s}\": {}",
                err.to_string().to_lowercase()
            ))
        })?;
        let data = Confined::try_from(data).map_err(DecodeError::from)?;
        Self::from_strict_serialized::<33>(data)
    }
}

impl TapretCommitment {
    /// Constructs information about tapret commitment.
    pub fn with(mpc: mpc::Commitment, nonce: u8) -> Self { Self { mpc, nonce } }
}

impl CommitVerify<TapretCommitment, TapretFirst> for TapScript {
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
        commitment
            .strict_write(33, &mut data)
            .expect("tapret commitment must be fitting 33 bytes");
        debug_assert_eq!(data.position(), 33, "tapret commitment must take exactly 33 bytes");
        tapret.push_slice(&data.into_inner());
        tapret
    }
}

#[cfg(test)]
mod test {
    use amplify::ByteArray;
    use commit_verify::{Digest, Sha256};

    use super::*;

    pub fn commitment() -> TapretCommitment {
        let msg = Sha256::digest("test data");
        TapretCommitment {
            mpc: mpc::Commitment::from_byte_array(msg),
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
        let s = commitment.to_string();
        assert_eq!(s, "k#7JerF92P=PEN7cf&`GWfS*?rIEdfEup1%zausI2m");
        assert_eq!(Ok(commitment.clone()), TapretCommitment::from_str(&s));
    }
}
