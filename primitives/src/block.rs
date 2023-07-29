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

use std::fmt::{self, Debug, Formatter, LowerHex, UpperHex};
use std::str::FromStr;

use amplify::hex::{FromHex, ToHex};
use amplify::{hex, Bytes32, RawArray, Wrapper};

use crate::LIB_NAME_BITCOIN;

#[derive(Wrapper, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Display, From)]
#[display(LowerHex)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BITCOIN)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
#[wrapper(BorrowSlice, Index, RangeOps)]
pub struct BlockHash(
    #[from]
    #[from([u8; 32])]
    Bytes32,
);

impl AsRef<[u8; 32]> for BlockHash {
    fn as_ref(&self) -> &[u8; 32] { self.0.as_inner() }
}

impl AsRef<[u8]> for BlockHash {
    fn as_ref(&self) -> &[u8] { self.0.as_ref() }
}

impl From<BlockHash> for [u8; 32] {
    fn from(value: BlockHash) -> Self { value.0.into_inner() }
}

impl Debug for BlockHash {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_tuple("BlockHash").field(&self.to_hex()).finish()
    }
}

/// Satoshi made all SHA245d-based hashes to be displayed as hex strings in a
/// big endian order. Thus we need this manual implementation.
impl LowerHex for BlockHash {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut slice = self.to_raw_array();
        slice.reverse();
        f.write_str(&slice.to_hex())
    }
}

impl UpperHex for BlockHash {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex().to_uppercase())
    }
}

impl FromStr for BlockHash {
    type Err = hex::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> { Self::from_hex(s) }
}

/// Satoshi made all SHA245d-based hashes to be displayed as hex strings in a
/// big endian order. Thus we need this manual implementation.
impl FromHex for BlockHash {
    fn from_byte_iter<I>(iter: I) -> Result<Self, hex::Error>
    where I: Iterator<Item = Result<u8, hex::Error>> + ExactSizeIterator + DoubleEndedIterator {
        Bytes32::from_byte_iter(iter.rev()).map(Self::from)
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct BlockHeader {
    /// Block version, now repurposed for soft fork signalling.
    pub version: i32,
    /// Reference to the previous block in the chain.
    pub prev_block_hash: BlockHash,
    /// The root hash of the merkle tree of transactions in the block.
    pub merkle_root: Bytes32,
    /// The timestamp of the block, as claimed by the miner.
    pub time: u32,
    /// The target value below which the blockhash must lie.
    pub bits: u32,
    /// The nonce, selected to obtain a low enough blockhash.
    pub nonce: u32,
}
