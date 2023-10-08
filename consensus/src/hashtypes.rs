// Bitcoin protocol consensus library.
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

use amplify::{Bytes20, Bytes32, Wrapper};

use crate::LIB_NAME_BITCOIN;

#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrapper(Index, RangeOps, AsSlice, BorrowSlice, Hex, Display, FromStr)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BITCOIN)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct PubkeyHash(
    #[from]
    #[from([u8; 20])]
    pub Bytes20,
);

impl From<PubkeyHash> for [u8; 20] {
    fn from(value: PubkeyHash) -> Self { value.0.into_inner() }
}

#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrapper(Index, RangeOps, AsSlice, BorrowSlice, Hex, Display, FromStr)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BITCOIN)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct ScriptHash(
    #[from]
    #[from([u8; 20])]
    pub Bytes20,
);

impl From<ScriptHash> for [u8; 20] {
    fn from(value: ScriptHash) -> Self { value.0.into_inner() }
}

#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrapper(Index, RangeOps, AsSlice, BorrowSlice, Hex, Display, FromStr)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BITCOIN)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct WPubkeyHash(
    #[from]
    #[from([u8; 20])]
    pub Bytes20,
);

impl From<WPubkeyHash> for [u8; 20] {
    fn from(value: WPubkeyHash) -> Self { value.0.into_inner() }
}

#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrapper(Index, RangeOps, AsSlice, BorrowSlice, Hex, Display, FromStr)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BITCOIN)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct WScriptHash(
    #[from]
    #[from([u8; 32])]
    pub Bytes32,
);

impl From<WScriptHash> for [u8; 32] {
    fn from(value: WScriptHash) -> Self { value.0.into_inner() }
}
