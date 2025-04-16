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

use crate::{
    BlockDataParseError, ConsensusDecode, ConsensusEncode, Tx, VarIntArray, LIB_NAME_BITCOIN,
};

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

impl BlockHash {
    pub const GENESIS_MAINNET: BlockHash = BlockHash::from_u64_be_array([
        0x00000000_0019d668,
        0x9c085ae1_65831e93,
        0x4ff763ae_46a2a6c1,
        0x72b3f1b6_0a8ce26f,
    ]);
    pub const GENESIS_TESTNET3: BlockHash = BlockHash::from_u64_be_array([
        0x00000000_0933ea01,
        0xad0ee984_209779ba,
        0xaec3ced9_0fa3f408,
        0x719526f8_d77f4943,
    ]);
    pub const GENESIS_TESTNET4: BlockHash = BlockHash::from_u64_be_array([
        0x00000000_da84f2ba,
        0xfbbc53de_e25a72ae,
        0x507ff491_4b867c56,
        0x5be350b0_da8bf043,
    ]);
    pub const GENESIS_SIGNET: BlockHash = BlockHash::from_u64_be_array([
        0x00000008_819873e9,
        0x25422c1f_f0f99f7c,
        0xc9bbb232_af63a077,
        0xa480a363_3bee1ef6,
    ]);
    pub const GENESIS_REGTEST: BlockHash = BlockHash::from_u64_be_array([
        0x0f9188f1_3cb7b2c7,
        0x1f2a335e_3a4fc328,
        0xbf5beb43_6012afca,
        0x590b1a11_466e2206,
    ]);
    #[cfg(feature = "liquid")]
    pub const LIQUID_MAINNET: BlockHash = BlockHash::from_u64_be_array([
        0x14662758_36220db2,
        0x944ca059_a3a10ef6,
        0xfd2ea684_b0688d2c,
        0x37929688_8a206003,
    ]);
    #[cfg(feature = "liquid")]
    pub const LIQUID_TESTNET: BlockHash = BlockHash::from_u64_be_array([
        0xa771da8e_52ee6ad5,
        0x81ed1e9a_99825e5b,
        0x3b799222_5534eaa2,
        0xae23244f_e26ab1c1,
    ]);

    pub const fn from_u64_be_array(array: [u64; 4]) -> Self {
        let mut buf = [0u8; 32];
        let x = array[0].to_be_bytes();
        buf[31] = x[0];
        buf[30] = x[1];
        buf[29] = x[2];
        buf[28] = x[3];
        buf[27] = x[4];
        buf[26] = x[5];
        buf[25] = x[6];
        buf[24] = x[7];
        let x = array[1].to_be_bytes();
        buf[23] = x[0];
        buf[22] = x[1];
        buf[21] = x[2];
        buf[20] = x[3];
        buf[19] = x[4];
        buf[18] = x[5];
        buf[17] = x[6];
        buf[16] = x[7];
        let x = array[2].to_be_bytes();
        buf[15] = x[0];
        buf[14] = x[1];
        buf[13] = x[2];
        buf[12] = x[3];
        buf[11] = x[4];
        buf[10] = x[5];
        buf[9] = x[6];
        buf[8] = x[7];
        let x = array[3].to_be_bytes();
        buf[7] = x[0];
        buf[6] = x[1];
        buf[5] = x[2];
        buf[4] = x[3];
        buf[3] = x[4];
        buf[2] = x[5];
        buf[1] = x[6];
        buf[0] = x[7];
        Self(Bytes32StrRev::from_array(buf))
    }
}

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

#[derive(Clone, PartialEq, Eq, Hash, Debug, Display)]
#[display(LowerHex)]
#[derive(StrictType, StrictEncode, StrictDecode, StrictDumb)]
#[strict_type(lib = LIB_NAME_BITCOIN)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: VarIntArray<Tx>,
}

impl LowerHex for Block {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&self.consensus_serialize().to_hex())
    }
}

impl FromStr for Block {
    type Err = BlockDataParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let data = Vec::<u8>::from_hex(s)?;
        Block::consensus_deserialize(data).map_err(BlockDataParseError::from)
    }
}

impl Block {
    pub fn block_hash(&self) -> BlockHash { self.header.block_hash() }
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

    #[test]
    fn bitcoin_genesis_hashes() {
        assert_eq!(
            &BlockHash::GENESIS_MAINNET.to_string(),
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        );
        assert_eq!(
            &BlockHash::GENESIS_TESTNET3.to_string(),
            "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"
        );
        assert_eq!(
            &BlockHash::GENESIS_TESTNET4.to_string(),
            "00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043"
        );
        assert_eq!(
            &BlockHash::GENESIS_SIGNET.to_string(),
            "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6"
        );
        assert_eq!(
            &BlockHash::GENESIS_REGTEST.to_string(),
            "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
        );
    }

    #[test]
    #[cfg(feature = "liquid")]
    fn liquid_genesis_hashes() {
        assert_eq!(
            &BlockHash::LIQUID_MAINNET.to_string(),
            "1466275836220db2944ca059a3a10ef6fd2ea684b0688d2c379296888a206003"
        );
        assert_eq!(
            &BlockHash::LIQUID_TESTNET.to_string(),
            "a771da8e52ee6ad581ed1e9a99825e5b3b7992225534eaa2ae23244fe26ab1c1"
        );
    }
}
