// Bitcoin protocol core library.
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

use strict_encoding::{StrictDecode, StrictDumb, StrictEncode};

/// Enumeration over types related to bitcoin protocol-compatible chains.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = dbc::LIB_NAME_BPCORE, tags = custom, dumb = Self::Bitcoin(strict_dumb!()))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all = "camelCase"))]
pub enum Bp<T>
where T: StrictDumb + StrictEncode + StrictDecode
{
    /// Bitcoin blockchain-based.
    ///
    /// NB: The type does not distinguish mainnet from testnets.
    #[strict_type(tag = 0x00)]
    Bitcoin(T),

    /// Liquid blockchain-based
    ///
    /// NB: The type does not distinguish mainnet from testnets.
    #[strict_type(tag = 0x01)]
    Liquid(T),
}

impl<T: StrictDumb + StrictEncode + StrictDecode> Bp<T> {
    /// Detects if the variant matches bitcoin blockchain.
    pub fn is_bitcoin(&self) -> bool { matches!(self, Bp::Bitcoin(_)) }
    /// Detects if the variant matches liquid blockchain.
    pub fn is_liquid(&self) -> bool { matches!(self, Bp::Liquid(_)) }
    /// Returns bitcoin blockchain variant as an optional.
    pub fn as_bitcoin(&self) -> Option<&T> {
        match self {
            Bp::Bitcoin(t) => Some(t),
            Bp::Liquid(_) => None,
        }
    }
    /// Returns liquid blockchain variant as an optional.
    pub fn as_liquid(&self) -> Option<&T> {
        match self {
            Bp::Bitcoin(_) => None,
            Bp::Liquid(t) => Some(t),
        }
    }
    /// Converts into bitcoin blockchain optional.
    pub fn into_bitcoin(self) -> Option<T> {
        match self {
            Bp::Bitcoin(t) => Some(t),
            Bp::Liquid(_) => None,
        }
    }
    /// Converts into liquid blockchain optional.
    pub fn into_liquid(self) -> Option<T> {
        match self {
            Bp::Bitcoin(_) => None,
            Bp::Liquid(t) => Some(t),
        }
    }

    /// Maps the value from one internal type into another.
    pub fn map<U: StrictDumb + StrictEncode + StrictDecode>(self, f: impl FnOnce(T) -> U) -> Bp<U> {
        match self {
            Bp::Bitcoin(t) => Bp::Bitcoin(f(t)),
            Bp::Liquid(t) => Bp::Liquid(f(t)),
        }
    }

    /// Maps the value from one internal type into another, covering cases which
    /// may error.
    pub fn try_map<U: StrictDumb + StrictEncode + StrictDecode, E>(
        self,
        f: impl FnOnce(T) -> Result<U, E>,
    ) -> Result<Bp<U>, E> {
        match self {
            Bp::Bitcoin(t) => f(t).map(Bp::Bitcoin),
            Bp::Liquid(t) => f(t).map(Bp::Liquid),
        }
    }

    /// Maps the value from one internal type into another, covering cases which
    /// may result in an optional value.
    pub fn maybe_map<U: StrictDumb + StrictEncode + StrictDecode>(
        self,
        f: impl FnOnce(T) -> Option<U>,
    ) -> Option<Bp<U>> {
        match self {
            Bp::Bitcoin(t) => f(t).map(Bp::Bitcoin),
            Bp::Liquid(t) => f(t).map(Bp::Liquid),
        }
    }
}
