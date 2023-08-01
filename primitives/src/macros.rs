// Bitcoin protocol primitives library.
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

/// Satoshi made all SHA245d-based hashes to be displayed as hex strings in a
/// big endian order. Thus we need this manual implementation.
macro_rules! impl_sha256d_hashtype {
    ($ty:ident, $name:literal) => {
        mod _sha256_hash_impl {
            use core::fmt::{self, Debug, Formatter, LowerHex, UpperHex};
            use core::str::FromStr;

            use amplify::hex::{self, FromHex, ToHex};
            use amplify::{Bytes32, RawArray, Wrapper};

            use super::$ty;

            impl From<$ty> for [u8; 32] {
                fn from(value: $ty) -> Self { value.0.into_inner() }
            }

            impl Debug for $ty {
                fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
                    f.debug_tuple($name).field(&self.to_hex()).finish()
                }
            }

            impl LowerHex for $ty {
                fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
                    let mut slice = self.to_raw_array();
                    slice.reverse();
                    f.write_str(&slice.to_hex())
                }
            }

            impl UpperHex for $ty {
                fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
                    f.write_str(&self.to_hex().to_uppercase())
                }
            }

            impl FromStr for $ty {
                type Err = hex::Error;
                fn from_str(s: &str) -> Result<Self, Self::Err> { Self::from_hex(s) }
            }

            impl FromHex for $ty {
                fn from_byte_iter<I>(iter: I) -> Result<Self, hex::Error>
                where I: Iterator<Item = Result<u8, hex::Error>>
                        + ExactSizeIterator
                        + DoubleEndedIterator {
                    Bytes32::from_byte_iter(iter.rev()).map(Self::from)
                }
            }
        }
    };
}
