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

use std::io::{self, Cursor, Read, Write};

use amplify::confinement::{Confined, U32};
use amplify::{confinement, IoError, RawArray, Wrapper};

use crate::{
    LockTime, Outpoint, Sats, ScriptBytes, ScriptPubkey, SeqNo, SigScript, Tx, TxIn, TxOut, TxVer,
    Txid, VarInt, Vout, Witness,
};

pub type VarIntArray<T> = Confined<Vec<T>, 0, U32>;

pub trait VarIntSize {
    fn var_int_size(&self) -> VarInt;
}

impl<T> VarIntSize for VarIntArray<T> {
    fn var_int_size(&self) -> VarInt { VarInt::with(self.len()) }
}

#[derive(Clone, Debug, Display, Error, From)]
#[display(inner)]
pub enum ConsensusDecodeError {
    #[from]
    #[from(io::Error)]
    Io(IoError),

    #[from]
    #[from(confinement::Error)]
    Data(ConsensusDataError),
}

#[derive(Clone, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum ConsensusDataError {
    /// consensus data are followed by some excessive bytes
    DataNotConsumed,

    /// not a minimally-encoded variable integer
    NonMinimalVarInt,

    #[from]
    #[display(inner)]
    Confined(confinement::Error),

    /// invalid SegWit transaction encoding missing required flag 0x01 in the
    /// six byte
    InvalidSegWitEncoding,
}

pub trait ConsensusEncode {
    fn consensus_encode(&self, writer: &mut impl Write) -> Result<usize, IoError>;
}

pub trait ConsensusDecode
where Self: Sized
{
    fn consensus_decode(reader: &mut impl Read) -> Result<Self, ConsensusDecodeError>;
    fn consensus_deserialize(bytes: impl AsRef<[u8]>) -> Result<Self, ConsensusDataError> {
        let mut cursor = Cursor::new(bytes.as_ref());
        let me = Self::consensus_decode(&mut cursor).map_err(|err| match err {
            ConsensusDecodeError::Data(e) => e,
            ConsensusDecodeError::Io(_) => unreachable!(),
        })?;
        if cursor.position() as usize != bytes.as_ref().len() {
            return Err(ConsensusDataError::DataNotConsumed);
        }
        Ok(me)
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
                Err(ConsensusDataError::InvalidSegWitEncoding)?
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

        if segwit {
            for input in &mut inputs {
                input.witness = Witness::consensus_decode(reader)?;
            }
        }

        let outputs = VarIntArray::consensus_decode(reader)?;
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
        writer.write_all(&self.to_raw_array())?;
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

impl<T: ConsensusEncode> ConsensusEncode for VarIntArray<T> {
    fn consensus_encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        let mut counter = self.var_int_size().consensus_encode(writer)?;
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
