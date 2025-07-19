// Bitcoin protocol consensus library.
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

use amplify::{Bytes20, Bytes32, Wrapper};
use commit_verify::{DigestExt, Ripemd160, Sha256};

use crate::{
    CompressedPk, LegacyPk, RedeemScript, UncompressedPk, WitnessScript, LIB_NAME_BITCOIN,
};

#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrapper(Index, RangeOps, AsSlice, BorrowSlice, Hex, Display, FromStr)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BITCOIN)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(transparent))]
pub struct PubkeyHash(
    #[from]
    #[from([u8; 20])]
    pub Bytes20,
);

impl From<PubkeyHash> for [u8; 20] {
    fn from(value: PubkeyHash) -> Self { value.0.into_inner() }
}

impl From<CompressedPk> for PubkeyHash {
    fn from(pk: CompressedPk) -> Self {
        let mut engine = Sha256::default();
        engine.input_raw(&pk.to_byte_array());
        let mut engine2 = Ripemd160::default();
        engine2.input_raw(&engine.finish());
        Self(engine2.finish().into())
    }
}

impl From<UncompressedPk> for PubkeyHash {
    fn from(pk: UncompressedPk) -> Self {
        let mut engine = Sha256::default();
        engine.input_raw(&pk.to_byte_array());
        let mut engine2 = Ripemd160::default();
        engine2.input_raw(&engine.finish());
        Self(engine2.finish().into())
    }
}

impl From<LegacyPk> for PubkeyHash {
    fn from(pk: LegacyPk) -> Self {
        let mut engine = Sha256::default();
        engine.input_raw(&pk.to_vec());
        let mut engine2 = Ripemd160::default();
        engine2.input_raw(&engine.finish());
        Self(engine2.finish().into())
    }
}

#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrapper(Index, RangeOps, AsSlice, BorrowSlice, Hex, Display, FromStr)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BITCOIN)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(transparent))]
pub struct ScriptHash(
    #[from]
    #[from([u8; 20])]
    pub Bytes20,
);

impl From<ScriptHash> for [u8; 20] {
    fn from(value: ScriptHash) -> Self { value.0.into_inner() }
}

impl From<&RedeemScript> for ScriptHash {
    fn from(redeem_script: &RedeemScript) -> Self {
        let mut engine = Sha256::default();
        engine.input_raw(redeem_script.as_slice());
        let mut engine2 = Ripemd160::default();
        engine2.input_raw(&engine.finish());
        Self(engine2.finish().into())
    }
}

#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrapper(Index, RangeOps, AsSlice, BorrowSlice, Hex, Display, FromStr)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BITCOIN)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(transparent))]
pub struct WPubkeyHash(
    #[from]
    #[from([u8; 20])]
    pub Bytes20,
);

impl From<WPubkeyHash> for [u8; 20] {
    fn from(value: WPubkeyHash) -> Self { value.0.into_inner() }
}

impl From<CompressedPk> for WPubkeyHash {
    fn from(pk: CompressedPk) -> Self {
        let mut engine = Sha256::default();
        engine.input_raw(&pk.to_byte_array());
        let mut engine2 = Ripemd160::default();
        engine2.input_raw(&engine.finish());
        Self(engine2.finish().into())
    }
}

#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrapper(Index, RangeOps, AsSlice, BorrowSlice, Hex, Display, FromStr)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BITCOIN)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(transparent))]
pub struct WScriptHash(
    #[from]
    #[from([u8; 32])]
    pub Bytes32,
);

impl From<WScriptHash> for [u8; 32] {
    fn from(value: WScriptHash) -> Self { value.0.into_inner() }
}

impl From<&WitnessScript> for WScriptHash {
    fn from(witness_script: &WitnessScript) -> Self {
        let mut engine = Sha256::default();
        engine.input_raw(witness_script.as_slice());
        Self(engine.finish().into())
    }
}
