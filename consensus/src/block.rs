// Bitcoin protocol consensus library.
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

use std::fmt;
use std::fmt::{Formatter, LowerHex};
use std::str::FromStr;

use amplify::hex::{FromHex, ToHex};
use amplify::{ByteArray, Bytes32StrRev, Wrapper};
use commit_verify::{DigestExt, Sha256};

use crate::{BlockDataParseError, ConsensusDecode, ConsensusEncode, LIB_NAME_BITCOIN};

#[derive(Wrapper, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, From)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BITCOIN)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(transparent))]
#[wrapper(BorrowSlice, Index, RangeOps, Debug, Hex, Display, FromStr)]
pub struct BlockHash(
    #[from]
    #[from([u8; 32])]
    Bytes32StrRev,
);

#[derive(Wrapper, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, From)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BITCOIN)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(transparent))]
#[wrapper(BorrowSlice, Index, RangeOps, Debug, Hex, Display, FromStr)]
pub struct BlockMerkleRoot(
    #[from]
    #[from([u8; 32])]
    Bytes32StrRev,
);

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[display(LowerHex)]
#[derive(StrictType, StrictEncode, StrictDecode, StrictDumb)]
#[strict_type(lib = LIB_NAME_BITCOIN)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all = "camelCase"))]
pub struct BlockHeader {
    /// Block version, now repurposed for soft fork signalling.
    pub version: i32,
    /// Reference to the previous block in the chain.
    pub prev_block_hash: BlockHash,
    /// The root hash of the merkle tree of transactions in the block.
    pub merkle_root: BlockMerkleRoot,
    /// The timestamp of the block, as claimed by the miner.
    pub time: u32,
    /// The target value below which the blockhash must lie.
    pub bits: u32,
    /// The nonce, selected to obtain a low enough blockhash.
    pub nonce: u32,
}

impl LowerHex for BlockHeader {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&self.consensus_serialize().to_hex())
    }
}

impl FromStr for BlockHeader {
    type Err = BlockDataParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let data = Vec::<u8>::from_hex(s)?;
        BlockHeader::consensus_deserialize(data).map_err(BlockDataParseError::from)
    }
}

impl BlockHeader {
    pub fn block_hash(&self) -> BlockHash {
        let mut enc = Sha256::default();
        self.consensus_encode(&mut enc).expect("engines don't error");
        let mut double = Sha256::default();
        double.input_raw(&enc.finish());
        BlockHash::from_byte_array(double.finish())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    // block height 835056
    fn modern_block_header() {
        let header_str = "00006020333eaffe61bc29a9a387aa56bd424b3c73ebb536cc4a03000000000000000000\
        af225b062c7acf90aac833cc4e0789f17b13ef53564cdd3b748e7897d7df20ff25bcf665595a03170bcd54ad";
        let header = BlockHeader::from_str(header_str).unwrap();
        assert_eq!(header.version, 0x20600000);
        assert_eq!(
            header.merkle_root.to_string(),
            "ff20dfd797788e743bdd4c5653ef137bf189074ecc33c8aa90cf7a2c065b22af"
        );
        assert_eq!(
            header.prev_block_hash.to_string(),
            "000000000000000000034acc36b5eb733c4b42bd56aa87a3a929bc61feaf3e33"
        );
        assert_eq!(header.bits, 0x17035a59);
        assert_eq!(header.nonce, 0xad54cd0b);
        assert_eq!(header.time, 1710668837);
        assert_eq!(header.to_string(), header_str);
        assert_eq!(
            header.block_hash().to_string(),
            "00000000000000000000a885d748631afdf2408d2db66e616e963d08c31a65df"
        );
    }
}
