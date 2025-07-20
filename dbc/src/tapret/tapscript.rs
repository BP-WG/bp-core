// Deterministic bitcoin commitments library.
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

use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use amplify::confinement::Confined;
use base58::{FromBase58, ToBase58};
use bc::{TapCode, TapScript};
use commit_verify::{mpc, CommitVerify};
use strict_encoding::{
    DecodeError, DeserializeError, StreamWriter, StrictDeserialize, StrictEncode, StrictSerialize,
};

use super::TapretFirst;
use crate::LIB_NAME_BPCORE;

/// Hardcoded tapret script prefix consisting of 29 `OP_NOP` pushes,
/// followed by `OP_RETURN` and `OP_PUSHBYTES_33`.
pub const TAPRET_SCRIPT_COMMITMENT_PREFIX: [u8; 31] = [
    0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
    0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x6a, 0x21,
];

/// Information about tapret commitment.
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BPCORE)]
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
        let buf = Confined::from_iter_checked(value);
        Self::from_strict_serialized::<33>(buf).expect("exact size match")
    }
}

impl TapretCommitment {
    /// Returns serialized representation of the commitment data.
    pub fn to_vec(&self) -> Vec<u8> {
        self.to_strict_serialized::<33>().expect("exact size match").release()
    }
}

impl Display for TapretCommitment {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let s = self.to_vec().to_base58();
        f.write_str(&s)
    }
}
impl FromStr for TapretCommitment {
    type Err = DeserializeError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let data = s.from_base58().map_err(|_| {
            DecodeError::DataIntegrityError(format!(
                "invalid Base58 encoding of tapret data \"{s}\"",
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
    /// Tapret script consists of 29 `OP_NOP` pushes, followed by
    /// `OP_RETURN`, `OP_PUSHBYTES_33` and serialized commitment data (MPC
    /// commitment + nonce as a single slice).
    // It was OP_RESERVER1, but with TapCode differentiation it is not there anymore,
    // so it makes more sense to use OP_NOP here.
    fn commit(commitment: &TapretCommitment) -> Self {
        let mut tapret = TapScript::with_capacity(64);
        for _ in 0..29 {
            tapret.push_opcode(TapCode::Nop);
        }
        tapret.push_opcode(TapCode::Return);
        let mut writer = StreamWriter::in_memory::<33>();
        commitment.strict_write(&mut writer).expect("tapret commitment must be fitting 33 bytes");
        let data = writer.unconfine();
        debug_assert_eq!(data.len(), 33, "tapret commitment must take exactly 33 bytes");
        tapret.push_slice(&data);
        tapret
    }
}

#[cfg(feature = "serde")]
mod _serde {
    use amplify::{Bytes, Wrapper};
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use super::*;

    impl Serialize for TapretCommitment {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer {
            if serializer.is_human_readable() {
                self.to_string().serialize(serializer)
            } else {
                self.to_vec().serialize(serializer)
            }
        }
    }

    impl<'de> Deserialize<'de> for TapretCommitment {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: Deserializer<'de> {
            if deserializer.is_human_readable() {
                let s = String::deserialize(deserializer)?;
                Self::from_str(&s).map_err(D::Error::custom)
            } else {
                let slice = Bytes::<33>::deserialize(deserializer)?;
                Ok(Self::from(slice.into_inner()))
            }
        }
    }
}

#[cfg(test)]
mod test {
    #![cfg_attr(coverage_nightly, coverage(off))]

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
    pub fn tapret_commitment_base58() {
        let commitment = commitment();
        let s = commitment.to_string();
        assert_eq!(s, "kCmE8g7LJYxPC977vnhUQv4YqMGc5jzip3Rio6Aqau3yZ");
        assert_eq!(Ok(commitment.clone()), TapretCommitment::from_str(&s));
    }
}
