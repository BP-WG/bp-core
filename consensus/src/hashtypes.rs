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

use std::fmt;
use std::fmt::{Debug, Formatter};

use amplify::hex::ToHex;
use amplify::{Array, Wrapper};

#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Display, From)]
#[wrapper(BorrowSlice, Index, RangeOps, FromStr, Hex)]
#[display(LowerHex)]
pub struct PubkeyHash(
    #[from]
    #[from([u8; 20])]
    Array<u8, 20>,
);

impl AsRef<[u8; 20]> for PubkeyHash {
    fn as_ref(&self) -> &[u8; 20] { self.0.as_inner() }
}

impl AsRef<[u8]> for PubkeyHash {
    fn as_ref(&self) -> &[u8] { self.0.as_ref() }
}

impl From<PubkeyHash> for [u8; 20] {
    fn from(value: PubkeyHash) -> Self { value.0.into_inner() }
}

impl Debug for PubkeyHash {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PubkeyHash").field(&self.to_hex()).finish()
    }
}

#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Display, From)]
#[wrapper(BorrowSlice, Index, RangeOps, FromStr, Hex)]
#[display(LowerHex)]
pub struct ScriptHash(
    #[from]
    #[from([u8; 20])]
    Array<u8, 20>,
);

impl AsRef<[u8; 20]> for ScriptHash {
    fn as_ref(&self) -> &[u8; 20] { self.0.as_inner() }
}

impl AsRef<[u8]> for ScriptHash {
    fn as_ref(&self) -> &[u8] { self.0.as_ref() }
}

impl From<ScriptHash> for [u8; 20] {
    fn from(value: ScriptHash) -> Self { value.0.into_inner() }
}

impl Debug for ScriptHash {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ScriptHash").field(&self.to_hex()).finish()
    }
}

#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Display, From)]
#[wrapper(BorrowSlice, Index, RangeOps, FromStr, Hex)]
#[display(LowerHex)]
pub struct WPubkeyHash(
    #[from]
    #[from([u8; 20])]
    Array<u8, 20>,
);

impl AsRef<[u8; 20]> for WPubkeyHash {
    fn as_ref(&self) -> &[u8; 20] { self.0.as_inner() }
}

impl AsRef<[u8]> for WPubkeyHash {
    fn as_ref(&self) -> &[u8] { self.0.as_ref() }
}

impl From<WPubkeyHash> for [u8; 20] {
    fn from(value: WPubkeyHash) -> Self { value.0.into_inner() }
}

impl Debug for WPubkeyHash {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_tuple("WPubkeyHash").field(&self.to_hex()).finish()
    }
}

#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Display, From)]
#[wrapper(BorrowSlice, Index, RangeOps, FromStr, Hex)]
#[display(LowerHex)]
pub struct WScriptHash(
    #[from]
    #[from([u8; 32])]
    Array<u8, 32>,
);

impl AsRef<[u8; 32]> for WScriptHash {
    fn as_ref(&self) -> &[u8; 32] { self.0.as_inner() }
}

impl AsRef<[u8]> for WScriptHash {
    fn as_ref(&self) -> &[u8] { self.0.as_ref() }
}

impl From<WScriptHash> for [u8; 32] {
    fn from(value: WScriptHash) -> Self { value.0.into_inner() }
}

impl Debug for WScriptHash {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_tuple("WScriptHash").field(&self.to_hex()).finish()
    }
}
