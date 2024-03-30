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

use std::io::{self, Cursor, Read, Write};

use amplify::confinement::{Confined, MediumBlob, SmallBlob, TinyBlob, U32};
use amplify::{confinement, ByteArray, Bytes32, IoError, Wrapper};

use crate::{
    BlockHash, BlockHeader, BlockMerkleRoot, ControlBlock, InternalPk, InvalidLeafVer, LeafVer,
    LockTime, Outpoint, Parity, RedeemScript, Sats, ScriptBytes, ScriptPubkey, SeqNo, SigScript,
    TapBranchHash, TapMerklePath, TapScript, Tx, TxIn, TxOut, TxVer, Txid, Vout, Witness,
    WitnessScript, LIB_NAME_BITCOIN,
};

/// Bitcoin consensus allows arrays which length is encoded as VarInt to grow up
/// to 64-bit values. However, at the same time no consensus rule allows any
/// block data structure to exceed 2^32 bytes (4GB), and any change to that rule
/// will be a hardfork. So for practical reasons we are safe to restrict the
/// maximum size here with just 32 bits.
pub type VarIntArray<T> = Confined<Vec<T>, 0, U32>;

pub type VarIntBytes = Confined<Vec<u8>, 0, U32>;

/// A variable-length unsigned integer.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BITCOIN)]
pub struct VarInt(pub u64);

#[allow(clippy::len_without_is_empty)] // VarInt has no concept of 'is_empty'.
impl VarInt {
    pub const fn new(u: u64) -> Self { VarInt(u) }

    pub fn with(u: impl Into<usize>) -> Self { VarInt(u.into() as u64) }

    /// Gets the length of this VarInt when encoded.
    ///
    /// Returns 1 for 0..=0xFC, 3 for 0xFD..=(2^16-1), 5 for 0x10000..=(2^32-1),
    /// and 9 otherwise.
    #[inline]
    pub const fn len(&self) -> usize {
        match self.0 {
            0..=0xFC => 1,
            0xFD..=0xFFFF => 3,
            0x10000..=0xFFFFFFFF => 5,
            _ => 9,
        }
    }

    pub const fn to_u64(&self) -> u64 { self.0 }
    pub const fn into_u64(self) -> u64 { self.0 }
    pub fn to_usize(&self) -> usize {
        usize::try_from(self.0).expect("transaction too large for a non-64 bit platform")
    }
    pub fn into_usize(self) -> usize { self.to_usize() }
}

impl<U: Into<u64> + Copy> PartialEq<U> for VarInt {
    fn eq(&self, other: &U) -> bool { self.0.eq(&(*other).into()) }
}

pub trait LenVarInt {
    fn len_var_int(&self) -> VarInt;
}

impl<T> LenVarInt for VarIntArray<T> {
    fn len_var_int(&self) -> VarInt { VarInt::with(self.len()) }
}

#[derive(Wrapper, WrapperMut, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Default, Debug, From)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BITCOIN)]
#[wrapper(Deref, Index, RangeOps, BorrowSlice, Hex)]
#[wrapper_mut(DerefMut, IndexMut, RangeMut, BorrowSliceMut)]
pub struct ByteStr(VarIntBytes);

impl AsRef<[u8]> for ByteStr {
    fn as_ref(&self) -> &[u8] { self.0.as_slice() }
}

impl From<Vec<u8>> for ByteStr {
    fn from(value: Vec<u8>) -> Self { Self(Confined::try_from(value).expect("u32 >= usize")) }
}

impl From<TinyBlob> for ByteStr {
    fn from(vec: TinyBlob) -> Self { ByteStr(Confined::from_collection_unsafe(vec.into_inner())) }
}

impl From<SmallBlob> for ByteStr {
    fn from(vec: SmallBlob) -> Self { ByteStr(Confined::from_collection_unsafe(vec.into_inner())) }
}

impl From<MediumBlob> for ByteStr {
    fn from(vec: MediumBlob) -> Self { ByteStr(Confined::from_collection_unsafe(vec.into_inner())) }
}

impl ByteStr {
    pub fn len_var_int(&self) -> VarInt { VarInt(self.len() as u64) }

    pub fn into_vec(self) -> Vec<u8> { self.0.into_inner() }
}

#[cfg(feature = "serde")]
mod _serde {
    use amplify::hex::{FromHex, ToHex};
    use serde_crate::de::Error;
    use serde_crate::{Deserialize, Deserializer, Serialize, Serializer};

    use super::*;

    impl Serialize for ByteStr {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer {
            if serializer.is_human_readable() {
                serializer.serialize_str(&self.to_hex())
            } else {
                serializer.serialize_bytes(self.as_slice())
            }
        }
    }

    impl<'de> Deserialize<'de> for ByteStr {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: Deserializer<'de> {
            if deserializer.is_human_readable() {
                String::deserialize(deserializer).and_then(|string| {
                    Self::from_hex(&string).map_err(|_| D::Error::custom("wrong hex data"))
                })
            } else {
                let bytes = Vec::<u8>::deserialize(deserializer)?;
                Ok(Self::from(bytes))
            }
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Display, Error, From)]
#[display(inner)]
pub enum ConsensusDecodeError {
    #[from]
    #[from(io::Error)]
    Io(IoError),

    #[display(inner)]
    #[from]
    #[from(InvalidLeafVer)]
    #[from(confinement::Error)]
    Data(ConsensusDataError),
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum ConsensusDataError {
    /// consensus data are followed by some excessive bytes.
    DataNotConsumed,

    /// not a minimally-encoded variable integer.
    NonMinimalVarInt,

    /// invalid BIP340 (x-only) pubkey data.
    InvalidXonlyPubkey(Bytes32),

    /// taproot Merkle path length exceeds BIP-341 consensus limit of 128
    /// elements.
    LongTapMerklePath,

    /// Merkle path in the `PSBT_IN_TAP_TREE` is not encoded correctly.
    InvalidTapMerklePath,

    #[from]
    #[display(inner)]
    InvalidLeafVer(InvalidLeafVer),

    #[from]
    #[display(inner)]
    Confined(confinement::Error),

    /// unsupported Segwit flag {0}.
    UnsupportedSegwitFlag(u8),
}

pub trait ConsensusEncode {
    fn consensus_encode(&self, writer: &mut impl Write) -> Result<usize, IoError>;
    fn consensus_serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.consensus_encode(&mut buf)
            .expect("in-memory writing can't fail");
        buf
    }
}

pub trait ConsensusDecode
where Self: Sized
{
    fn consensus_decode(reader: &mut impl Read) -> Result<Self, ConsensusDecodeError>;
    fn consensus_deserialize(bytes: impl AsRef<[u8]>) -> Result<Self, ConsensusDecodeError> {
        let mut cursor = Cursor::new(bytes.as_ref());
        let me = Self::consensus_decode(&mut cursor)?;
        if cursor.position() as usize != bytes.as_ref().len() {
            return Err(ConsensusDataError::DataNotConsumed.into());
        }
        Ok(me)
    }
}

impl ConsensusEncode for BlockHeader {
    fn consensus_encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        let mut counter = self.version.consensus_encode(writer)?;
        counter += self.prev_block_hash.consensus_encode(writer)?;
        counter += self.merkle_root.consensus_encode(writer)?;
        counter += self.time.consensus_encode(writer)?;
        counter += self.bits.consensus_encode(writer)?;
        counter += self.nonce.consensus_encode(writer)?;
        Ok(counter)
    }
}

impl ConsensusDecode for BlockHeader {
    fn consensus_decode(reader: &mut impl Read) -> Result<Self, ConsensusDecodeError> {
        let version = i32::consensus_decode(reader)?;
        let prev_block_hash = BlockHash::consensus_decode(reader)?;
        let merkle_root = BlockMerkleRoot::consensus_decode(reader)?;
        let time = u32::consensus_decode(reader)?;
        let bits = u32::consensus_decode(reader)?;
        let nonce = u32::consensus_decode(reader)?;
        Ok(BlockHeader {
            version,
            prev_block_hash,
            merkle_root,
            time,
            bits,
            nonce,
        })
    }
}

impl ConsensusEncode for BlockHash {
    fn consensus_encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        writer.write_all(&self.to_byte_array())?;
        Ok(32)
    }
}

impl ConsensusDecode for BlockHash {
    fn consensus_decode(reader: &mut impl Read) -> Result<Self, ConsensusDecodeError> {
        <[u8; 32]>::consensus_decode(reader).map(Self::from)
    }
}

impl ConsensusEncode for BlockMerkleRoot {
    fn consensus_encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        writer.write_all(&self.to_byte_array())?;
        Ok(32)
    }
}

impl ConsensusDecode for BlockMerkleRoot {
    fn consensus_decode(reader: &mut impl Read) -> Result<Self, ConsensusDecodeError> {
        <[u8; 32]>::consensus_decode(reader).map(Self::from)
    }
}

impl ConsensusEncode for Tx {
    fn consensus_encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        let mut counter = self.version.consensus_encode(writer)?;
        if self.is_segwit() && !self.inputs.is_empty() {
            0x00_u8.consensus_encode(writer)?;
            0x01_u8.consensus_encode(writer)?;
            counter += 2;
        }
        counter += self.inputs.consensus_encode(writer)?;
        counter += self.outputs.consensus_encode(writer)?;
        if self.is_segwit() {
            for input in self.inputs() {
                counter += input.witness.consensus_encode(writer)?;
            }
        }
        counter += self.lock_time.consensus_encode(writer)?;
        Ok(counter)
    }
}

impl ConsensusDecode for Tx {
    fn consensus_decode(reader: &mut impl Read) -> Result<Self, ConsensusDecodeError> {
        let version = TxVer::consensus_decode(reader)?;
        let prefix = VarInt::consensus_decode(reader)?;

        let segwit = prefix == 0u8;
        let mut inputs = if segwit {
            // SegWit
            let flag = u8::consensus_decode(reader)?;
            if flag != 0x01 {
                Err(ConsensusDataError::UnsupportedSegwitFlag(flag))?
            }
            VarIntArray::<TxIn>::consensus_decode(reader)?
        } else {
            // our prefix is the number of inputs
            let mut inputs = Vec::with_capacity(prefix.to_usize());
            for _ in 0..prefix.to_u64() {
                inputs.push(TxIn::consensus_decode(reader)?);
            }
            VarIntArray::try_from(inputs)?
        };

        let outputs = VarIntArray::consensus_decode(reader)?;
        if segwit {
            for input in &mut inputs {
                input.witness = Witness::consensus_decode(reader)?;
            }
        }
        let lock_time = LockTime::consensus_decode(reader)?;

        Ok(Tx {
            version,
            inputs,
            outputs,
            lock_time,
        })
    }
}

impl ConsensusEncode for TxVer {
    fn consensus_encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        self.to_consensus_i32().consensus_encode(writer)
    }
}

impl ConsensusDecode for TxVer {
    fn consensus_decode(reader: &mut impl Read) -> Result<Self, ConsensusDecodeError> {
        i32::consensus_decode(reader).map(Self::from_consensus_i32)
    }
}

impl ConsensusEncode for TxIn {
    fn consensus_encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        let mut counter = self.prev_output.consensus_encode(writer)?;
        counter += self.sig_script.consensus_encode(writer)?;
        counter += self.sequence.consensus_encode(writer)?;
        Ok(counter)
    }
}

impl ConsensusDecode for TxIn {
    fn consensus_decode(reader: &mut impl Read) -> Result<Self, ConsensusDecodeError> {
        let prev_output = Outpoint::consensus_decode(reader)?;
        let sig_script = SigScript::consensus_decode(reader)?;
        let sequence = SeqNo::consensus_decode(reader)?;
        Ok(TxIn {
            prev_output,
            sig_script,
            sequence,
            witness: none!(),
        })
    }
}

impl ConsensusEncode for TxOut {
    fn consensus_encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        let mut counter = self.value.consensus_encode(writer)?;
        counter += self.script_pubkey.consensus_encode(writer)?;
        Ok(counter)
    }
}

impl ConsensusDecode for TxOut {
    fn consensus_decode(reader: &mut impl Read) -> Result<Self, ConsensusDecodeError> {
        let value = Sats::consensus_decode(reader)?;
        let script_pubkey = ScriptPubkey::consensus_decode(reader)?;
        Ok(TxOut {
            value,
            script_pubkey,
        })
    }
}

impl ConsensusEncode for Outpoint {
    fn consensus_encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        let mut counter = self.txid.consensus_encode(writer)?;
        counter += self.vout.consensus_encode(writer)?;
        Ok(counter)
    }
}

impl ConsensusDecode for Outpoint {
    fn consensus_decode(reader: &mut impl Read) -> Result<Self, ConsensusDecodeError> {
        let txid = Txid::consensus_decode(reader)?;
        let vout = Vout::consensus_decode(reader)?;
        Ok(Outpoint { txid, vout })
    }
}

impl ConsensusEncode for Txid {
    fn consensus_encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        writer.write_all(&self.to_byte_array())?;
        Ok(32)
    }
}

impl ConsensusDecode for Txid {
    fn consensus_decode(reader: &mut impl Read) -> Result<Self, ConsensusDecodeError> {
        <[u8; 32]>::consensus_decode(reader).map(Self::from)
    }
}

impl ConsensusEncode for Vout {
    fn consensus_encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        self.into_u32().consensus_encode(writer)
    }
}

impl ConsensusDecode for Vout {
    fn consensus_decode(reader: &mut impl Read) -> Result<Self, ConsensusDecodeError> {
        u32::consensus_decode(reader).map(Self::from)
    }
}

impl ConsensusEncode for SeqNo {
    fn consensus_encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        self.to_consensus_u32().consensus_encode(writer)
    }
}

impl ConsensusDecode for SeqNo {
    fn consensus_decode(reader: &mut impl Read) -> Result<Self, ConsensusDecodeError> {
        u32::consensus_decode(reader).map(Self::from_consensus_u32)
    }
}

impl ConsensusEncode for LockTime {
    fn consensus_encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        self.to_consensus_u32().consensus_encode(writer)
    }
}

impl ConsensusDecode for LockTime {
    fn consensus_decode(reader: &mut impl Read) -> Result<Self, ConsensusDecodeError> {
        u32::consensus_decode(reader).map(Self::from_consensus_u32)
    }
}

impl ConsensusEncode for ScriptBytes {
    fn consensus_encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        self.as_var_int_array().consensus_encode(writer)
    }
}

impl ConsensusDecode for ScriptBytes {
    fn consensus_decode(reader: &mut impl Read) -> Result<Self, ConsensusDecodeError> {
        VarIntArray::consensus_decode(reader).map(Self::from_inner)
    }
}

impl ConsensusEncode for ScriptPubkey {
    fn consensus_encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        self.as_script_bytes().consensus_encode(writer)
    }
}

impl ConsensusDecode for ScriptPubkey {
    fn consensus_decode(reader: &mut impl Read) -> Result<Self, ConsensusDecodeError> {
        ScriptBytes::consensus_decode(reader).map(Self::from_inner)
    }
}

impl ConsensusEncode for WitnessScript {
    fn consensus_encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        self.as_script_bytes().consensus_encode(writer)
    }
}

impl ConsensusDecode for WitnessScript {
    fn consensus_decode(reader: &mut impl Read) -> Result<Self, ConsensusDecodeError> {
        ScriptBytes::consensus_decode(reader).map(Self::from_inner)
    }
}

impl ConsensusEncode for RedeemScript {
    fn consensus_encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        self.as_script_bytes().consensus_encode(writer)
    }
}

impl ConsensusDecode for RedeemScript {
    fn consensus_decode(reader: &mut impl Read) -> Result<Self, ConsensusDecodeError> {
        ScriptBytes::consensus_decode(reader).map(Self::from_inner)
    }
}

impl ConsensusEncode for TapScript {
    fn consensus_encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        self.as_script_bytes().consensus_encode(writer)
    }
}

impl ConsensusDecode for TapScript {
    fn consensus_decode(reader: &mut impl Read) -> Result<Self, ConsensusDecodeError> {
        ScriptBytes::consensus_decode(reader).map(Self::from_inner)
    }
}

impl ConsensusEncode for SigScript {
    fn consensus_encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        self.as_script_bytes().consensus_encode(writer)
    }
}

impl ConsensusDecode for SigScript {
    fn consensus_decode(reader: &mut impl Read) -> Result<Self, ConsensusDecodeError> {
        ScriptBytes::consensus_decode(reader).map(Self::from_inner)
    }
}

impl ConsensusEncode for Witness {
    fn consensus_encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        self.as_var_int_array().consensus_encode(writer)
    }
}

impl ConsensusDecode for Witness {
    fn consensus_decode(reader: &mut impl Read) -> Result<Self, ConsensusDecodeError> {
        VarIntArray::consensus_decode(reader).map(Self::from_inner)
    }
}

impl ConsensusEncode for InternalPk {
    fn consensus_encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        writer.write_all(&self.to_byte_array())?;
        Ok(32)
    }
}

impl ConsensusEncode for TapBranchHash {
    fn consensus_encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        writer.write_all(&self.to_byte_array())?;
        Ok(32)
    }
}

impl ConsensusDecode for TapBranchHash {
    fn consensus_decode(reader: &mut impl Read) -> Result<Self, ConsensusDecodeError> {
        let mut buf = [0u8; 32];
        reader.read_exact(&mut buf)?;
        Ok(TapBranchHash::from_byte_array(buf))
    }
}

impl ConsensusDecode for InternalPk {
    fn consensus_decode(reader: &mut impl Read) -> Result<Self, ConsensusDecodeError> {
        let mut buf = [0u8; 32];
        reader.read_exact(&mut buf)?;
        InternalPk::from_byte_array(buf)
            .map_err(|_| ConsensusDataError::InvalidXonlyPubkey(buf.into()).into())
    }
}

impl ConsensusEncode for ControlBlock {
    fn consensus_encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        let mut counter = 1;

        let first_byte =
            self.leaf_version.to_consensus_u8() & self.output_key_parity.to_consensus_u8();
        first_byte.consensus_encode(writer)?;

        counter += self.internal_pk.consensus_encode(writer)?;
        for step in &self.merkle_branch {
            counter += step.consensus_encode(writer)?;
        }

        Ok(counter)
    }
}

impl ConsensusDecode for ControlBlock {
    fn consensus_decode(reader: &mut impl Read) -> Result<Self, ConsensusDecodeError> {
        let first_byte = u8::consensus_decode(reader)?;
        let leaf_version = LeafVer::from_consensus_u8(first_byte & 0xFE)?;
        let output_key_parity = Parity::from_consensus_u8(first_byte & 0x01).expect("binary value");

        let internal_key = InternalPk::consensus_decode(reader)?;

        let mut buf = vec![];
        reader.read_to_end(&mut buf)?;
        let mut iter = buf.chunks_exact(32);
        let merkle_branch = iter.by_ref().map(TapBranchHash::from_slice_unsafe);
        let merkle_branch = TapMerklePath::try_from_iter(merkle_branch)
            .map_err(|_| ConsensusDataError::LongTapMerklePath)?;
        if !iter.remainder().is_empty() {
            return Err(ConsensusDataError::InvalidTapMerklePath.into());
        }

        Ok(ControlBlock {
            leaf_version,
            output_key_parity,
            internal_pk: internal_key,
            merkle_branch,
        })
    }
}

impl ConsensusEncode for Sats {
    fn consensus_encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        self.0.consensus_encode(writer)
    }
}

impl ConsensusDecode for Sats {
    fn consensus_decode(reader: &mut impl Read) -> Result<Self, ConsensusDecodeError> {
        u64::consensus_decode(reader).map(Self)
    }
}

impl ConsensusEncode for VarInt {
    fn consensus_encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        match self.0 {
            0..=0xFC => {
                (self.0 as u8).consensus_encode(writer)?;
                Ok(1)
            }
            0xFD..=0xFFFF => {
                0xFDu8.consensus_encode(writer)?;
                (self.0 as u16).consensus_encode(writer)?;
                Ok(3)
            }
            0x10000..=0xFFFFFFFF => {
                0xFEu8.consensus_encode(writer)?;
                (self.0 as u32).consensus_encode(writer)?;
                Ok(5)
            }
            _ => {
                0xFFu8.consensus_encode(writer)?;
                self.0.consensus_encode(writer)?;
                Ok(9)
            }
        }
    }
}

impl ConsensusDecode for VarInt {
    fn consensus_decode(reader: &mut impl Read) -> Result<Self, ConsensusDecodeError> {
        let n = u8::consensus_decode(reader)?;
        match n {
            0xFF => {
                let x = u64::consensus_decode(reader)?;
                if x < 0x100000000 {
                    Err(ConsensusDataError::NonMinimalVarInt)?
                } else {
                    Ok(VarInt::new(x))
                }
            }
            0xFE => {
                let x = u32::consensus_decode(reader)?;
                if x < 0x10000 {
                    Err(ConsensusDataError::NonMinimalVarInt)?
                } else {
                    Ok(VarInt::new(x as u64))
                }
            }
            0xFD => {
                let x = u16::consensus_decode(reader)?;
                if x < 0xFD {
                    Err(ConsensusDataError::NonMinimalVarInt)?
                } else {
                    Ok(VarInt::with(x))
                }
            }
            n => Ok(VarInt::with(n)),
        }
    }
}

impl ConsensusEncode for ByteStr {
    fn consensus_encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        self.0.consensus_encode(writer)
    }
}

impl ConsensusDecode for ByteStr {
    fn consensus_decode(reader: &mut impl Read) -> Result<Self, ConsensusDecodeError> {
        VarIntArray::consensus_decode(reader).map(Self::from_inner)
    }
}

impl<T: ConsensusEncode> ConsensusEncode for VarIntArray<T> {
    fn consensus_encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        let mut counter = self.len_var_int().consensus_encode(writer)?;
        for item in self {
            counter += item.consensus_encode(writer)?;
        }
        Ok(counter)
    }
}

impl<T: ConsensusDecode> ConsensusDecode for VarIntArray<T> {
    fn consensus_decode(reader: &mut impl Read) -> Result<Self, ConsensusDecodeError> {
        let len = VarInt::consensus_decode(reader)?;
        let mut arr = Vec::new();
        for _ in 0..len.0 {
            arr.push(T::consensus_decode(reader)?);
        }
        VarIntArray::try_from(arr).map_err(ConsensusDecodeError::from)
    }
}

impl ConsensusEncode for u8 {
    fn consensus_encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        writer.write_all(&[*self])?;
        Ok(1)
    }
}

impl ConsensusDecode for u8 {
    fn consensus_decode(reader: &mut impl Read) -> Result<Self, ConsensusDecodeError> {
        let mut buf = [0u8; (Self::BITS / 8) as usize];
        reader.read_exact(&mut buf)?;
        Ok(Self::from_le_bytes(buf))
    }
}

impl ConsensusEncode for u16 {
    fn consensus_encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        writer.write_all(&self.to_le_bytes())?;
        Ok(2)
    }
}

impl ConsensusDecode for u16 {
    fn consensus_decode(reader: &mut impl Read) -> Result<Self, ConsensusDecodeError> {
        let mut buf = [0u8; (Self::BITS / 8) as usize];
        reader.read_exact(&mut buf)?;
        Ok(Self::from_le_bytes(buf))
    }
}

impl ConsensusEncode for u32 {
    fn consensus_encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        writer.write_all(&self.to_le_bytes())?;
        Ok(4)
    }
}

impl ConsensusDecode for u32 {
    fn consensus_decode(reader: &mut impl Read) -> Result<Self, ConsensusDecodeError> {
        let mut buf = [0u8; (Self::BITS / 8) as usize];
        reader.read_exact(&mut buf)?;
        Ok(Self::from_le_bytes(buf))
    }
}

impl ConsensusEncode for i32 {
    fn consensus_encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        writer.write_all(&self.to_le_bytes())?;
        Ok(4)
    }
}

impl ConsensusDecode for i32 {
    fn consensus_decode(reader: &mut impl Read) -> Result<Self, ConsensusDecodeError> {
        let mut buf = [0u8; (Self::BITS / 8) as usize];
        reader.read_exact(&mut buf)?;
        Ok(Self::from_le_bytes(buf))
    }
}

impl ConsensusEncode for u64 {
    fn consensus_encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        writer.write_all(&self.to_le_bytes())?;
        Ok(8)
    }
}

impl ConsensusDecode for u64 {
    fn consensus_decode(reader: &mut impl Read) -> Result<Self, ConsensusDecodeError> {
        let mut buf = [0u8; (Self::BITS / 8) as usize];
        reader.read_exact(&mut buf)?;
        Ok(Self::from_le_bytes(buf))
    }
}

impl ConsensusDecode for [u8; 32] {
    fn consensus_decode(reader: &mut impl Read) -> Result<Self, ConsensusDecodeError> {
        let mut buf = [0u8; 32];
        reader.read_exact(&mut buf)?;
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn serialize(t: &impl ConsensusEncode) -> Vec<u8> {
        let mut vec = Vec::new();
        t.consensus_encode(&mut vec).unwrap();
        vec
    }

    fn deserialize<T: ConsensusDecode>(d: impl AsRef<[u8]>) -> Result<T, ConsensusDecodeError> {
        T::consensus_deserialize(d)
    }

    fn deserialize_partial<T: ConsensusDecode>(
        d: impl AsRef<[u8]>,
    ) -> Result<T, ConsensusDataError> {
        let mut cursor = Cursor::new(d.as_ref());
        T::consensus_decode(&mut cursor).map_err(|err| match err {
            ConsensusDecodeError::Data(e) => e,
            ConsensusDecodeError::Io(_) => unreachable!(),
        })
    }

    #[test]
    fn serialize_int_test() {
        // u8
        assert_eq!(serialize(&1u8), vec![1u8]);
        assert_eq!(serialize(&0u8), vec![0u8]);
        assert_eq!(serialize(&255u8), vec![255u8]);
        // u16
        assert_eq!(serialize(&1u16), vec![1u8, 0]);
        assert_eq!(serialize(&256u16), vec![0u8, 1]);
        assert_eq!(serialize(&5000u16), vec![136u8, 19]);
        // u32
        assert_eq!(serialize(&1u32), vec![1u8, 0, 0, 0]);
        assert_eq!(serialize(&256u32), vec![0u8, 1, 0, 0]);
        assert_eq!(serialize(&5000u32), vec![136u8, 19, 0, 0]);
        assert_eq!(serialize(&500000u32), vec![32u8, 161, 7, 0]);
        assert_eq!(serialize(&168430090u32), vec![10u8, 10, 10, 10]);
        // i32
        assert_eq!(serialize(&-1i32), vec![255u8, 255, 255, 255]);
        assert_eq!(serialize(&-256i32), vec![0u8, 255, 255, 255]);
        assert_eq!(serialize(&-5000i32), vec![120u8, 236, 255, 255]);
        assert_eq!(serialize(&-500000i32), vec![224u8, 94, 248, 255]);
        assert_eq!(serialize(&-168430090i32), vec![246u8, 245, 245, 245]);
        assert_eq!(serialize(&1i32), vec![1u8, 0, 0, 0]);
        assert_eq!(serialize(&256i32), vec![0u8, 1, 0, 0]);
        assert_eq!(serialize(&5000i32), vec![136u8, 19, 0, 0]);
        assert_eq!(serialize(&500000i32), vec![32u8, 161, 7, 0]);
        assert_eq!(serialize(&168430090i32), vec![10u8, 10, 10, 10]);
        // u64
        assert_eq!(serialize(&1u64), vec![1u8, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(serialize(&256u64), vec![0u8, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(serialize(&5000u64), vec![136u8, 19, 0, 0, 0, 0, 0, 0]);
        assert_eq!(serialize(&500000u64), vec![32u8, 161, 7, 0, 0, 0, 0, 0]);
        assert_eq!(serialize(&723401728380766730u64), vec![10u8, 10, 10, 10, 10, 10, 10, 10]);
    }

    #[test]
    fn serialize_varint_test() {
        assert_eq!(serialize(&VarInt(10)), vec![10u8]);
        assert_eq!(serialize(&VarInt(0xFC)), vec![0xFCu8]);
        assert_eq!(serialize(&VarInt(0xFD)), vec![0xFDu8, 0xFD, 0]);
        assert_eq!(serialize(&VarInt(0xFFF)), vec![0xFDu8, 0xFF, 0xF]);
        assert_eq!(serialize(&VarInt(0xF0F0F0F)), vec![0xFEu8, 0xF, 0xF, 0xF, 0xF]);
        assert_eq!(serialize(&VarInt(0xF0F0F0F0F0E0)), vec![
            0xFFu8, 0xE0, 0xF0, 0xF0, 0xF0, 0xF0, 0xF0, 0, 0
        ]);
        assert_eq!(
            test_varint_encode(0xFF, &0x100000000_u64.to_le_bytes()).unwrap(),
            VarInt(0x100000000)
        );
        assert_eq!(test_varint_encode(0xFE, &0x10000_u64.to_le_bytes()).unwrap(), VarInt(0x10000));
        assert_eq!(test_varint_encode(0xFD, &0xFD_u64.to_le_bytes()).unwrap(), VarInt(0xFD));

        // Test that length calc is working correctly
        test_varint_len(VarInt(0), 1);
        test_varint_len(VarInt(0xFC), 1);
        test_varint_len(VarInt(0xFD), 3);
        test_varint_len(VarInt(0xFFFF), 3);
        test_varint_len(VarInt(0x10000), 5);
        test_varint_len(VarInt(0xFFFFFFFF), 5);
        test_varint_len(VarInt(0xFFFFFFFF + 1), 9);
        test_varint_len(VarInt(u64::MAX), 9);
    }

    fn test_varint_len(varint: VarInt, expected: usize) {
        let mut encoder = vec![];
        assert_eq!(varint.consensus_encode(&mut encoder).unwrap(), expected);
        assert_eq!(varint.len(), expected);
    }

    fn test_varint_encode(n: u8, x: &[u8]) -> Result<VarInt, ConsensusDataError> {
        let mut input = [0u8; 9];
        input[0] = n;
        input[1..x.len() + 1].copy_from_slice(x);
        deserialize_partial::<VarInt>(&input)
    }

    #[test]
    fn deserialize_nonminimal_vec() {
        // Check the edges for variant int
        assert_eq!(
            test_varint_encode(0xFF, &(0x100000000_u64 - 1).to_le_bytes()).unwrap_err(),
            ConsensusDataError::NonMinimalVarInt
        );
        assert_eq!(
            test_varint_encode(0xFE, &(0x10000_u64 - 1).to_le_bytes()).unwrap_err(),
            ConsensusDataError::NonMinimalVarInt
        );
        assert_eq!(
            test_varint_encode(0xFD, &(0xFD_u64 - 1).to_le_bytes()).unwrap_err(),
            ConsensusDataError::NonMinimalVarInt
        );

        assert_eq!(
            deserialize::<VarIntArray<u8>>(&[0xfd, 0x00, 0x00]).unwrap_err(),
            ConsensusDataError::NonMinimalVarInt.into()
        );
        assert_eq!(
            deserialize::<VarIntArray<u8>>(&[0xfd, 0xfc, 0x00]).unwrap_err(),
            ConsensusDataError::NonMinimalVarInt.into()
        );
        assert_eq!(
            deserialize::<VarIntArray<u8>>(&[0xfd, 0xfc, 0x00]).unwrap_err(),
            ConsensusDataError::NonMinimalVarInt.into()
        );
        assert_eq!(
            deserialize::<VarIntArray<u8>>(&[0xfe, 0xff, 0x00, 0x00, 0x00]).unwrap_err(),
            ConsensusDataError::NonMinimalVarInt.into()
        );
        assert_eq!(
            deserialize::<VarIntArray<u8>>(&[0xfe, 0xff, 0xff, 0x00, 0x00]).unwrap_err(),
            ConsensusDataError::NonMinimalVarInt.into()
        );
        assert_eq!(
            deserialize::<VarIntArray<u8>>(&[0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
                .unwrap_err(),
            ConsensusDataError::NonMinimalVarInt.into()
        );
        assert_eq!(
            deserialize::<VarIntArray<u8>>(&[0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00])
                .unwrap_err(),
            ConsensusDataError::NonMinimalVarInt.into()
        );

        let mut vec_256 = vec![0; 259];
        vec_256[0] = 0xfd;
        vec_256[1] = 0x00;
        vec_256[2] = 0x01;
        assert!(deserialize::<VarIntArray<u8>>(&vec_256).is_ok());

        let mut vec_253 = vec![0; 256];
        vec_253[0] = 0xfd;
        vec_253[1] = 0xfd;
        vec_253[2] = 0x00;
        assert!(deserialize::<VarIntArray<u8>>(&vec_253).is_ok());
    }

    #[test]
    fn deserialize_int_test() {
        // u8
        assert_eq!(deserialize([58u8]).ok(), Some(58u8));

        // u16
        assert_eq!(deserialize([0x01u8, 0x02]).ok(), Some(0x0201u16));
        assert_eq!(deserialize([0xABu8, 0xCD]).ok(), Some(0xCDABu16));
        assert_eq!(deserialize([0xA0u8, 0x0D]).ok(), Some(0xDA0u16));
        let failure16: Result<u16, _> = deserialize([1u8]);
        assert!(failure16.is_err());

        // u32
        assert_eq!(deserialize([0xABu8, 0xCD, 0, 0]).ok(), Some(0xCDABu32));
        assert_eq!(deserialize([0xA0u8, 0x0D, 0xAB, 0xCD]).ok(), Some(0xCDAB0DA0u32));

        let failure32: Result<u32, _> = deserialize([1u8, 2, 3]);
        assert!(failure32.is_err());

        // i32
        assert_eq!(deserialize([0xABu8, 0xCD, 0, 0]).ok(), Some(0xCDABi32));
        assert_eq!(deserialize([0xA0u8, 0x0D, 0xAB, 0x2D]).ok(), Some(0x2DAB0DA0i32));

        assert_eq!(deserialize([0, 0, 0, 0]).ok(), Some(-0_i32));
        assert_eq!(deserialize([0, 0, 0, 0]).ok(), Some(0_i32));

        assert_eq!(deserialize([0xFF, 0xFF, 0xFF, 0xFF]).ok(), Some(-1_i32));
        assert_eq!(deserialize([0xFE, 0xFF, 0xFF, 0xFF]).ok(), Some(-2_i32));
        assert_eq!(deserialize([0x01, 0xFF, 0xFF, 0xFF]).ok(), Some(-255_i32));
        assert_eq!(deserialize([0x02, 0xFF, 0xFF, 0xFF]).ok(), Some(-254_i32));

        let failurei32: Result<i32, _> = deserialize([1u8, 2, 3]);
        assert!(failurei32.is_err());

        // u64
        assert_eq!(deserialize([0xABu8, 0xCD, 0, 0, 0, 0, 0, 0]).ok(), Some(0xCDABu64));
        assert_eq!(
            deserialize([0xA0u8, 0x0D, 0xAB, 0xCD, 0x99, 0, 0, 0x99]).ok(),
            Some(0x99000099CDAB0DA0u64)
        );
        let failure64: Result<u64, _> = deserialize([1u8, 2, 3, 4, 5, 6, 7]);
        assert!(failure64.is_err());
    }
}
