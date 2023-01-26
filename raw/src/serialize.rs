// BP Core Library implementing LNP/BP specifications & standards related to
// bitcoin protocol
//
// Written in 2020-2022 by
//     Dr. Maxim Orlovsky <orlovsky@pandoracore.com>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the Apache 2.0 License
// along with this software.
// If not, see <https://opensource.org/licenses/Apache-2.0>.

use super::VarIntBytes;

pub struct NoData;
pub struct TooLarge;

pub trait ConsensusRead {
    fn is_empty(&self) -> bool;
    fn read_u8(&mut self) -> Result<u8, NoData>;
    fn read_u32(&mut self) -> Result<u32, NoData>;
    fn read_var_int(&mut self) -> Result<u64, NoData>;
    fn read_bytes(&mut self, len: u64) -> Result<VarIntBytes, NoData>;
}

pub trait ConsensusWrite {
    fn write_u8(&mut self, val: u8) -> Result<(), TooLarge>;
    fn write_u32(&mut self, val: u32) -> Result<(), TooLarge>;
    fn write_var_int(&mut self, val: u64) -> Result<(), TooLarge>;
    fn write_bytes(&mut self, bytes: &VarIntBytes) -> Result<(), TooLarge>;
}

impl<T: ConsensusRead> ConsensusRead for &mut T {
    fn is_empty(&self) -> bool { (*self).is_empty() }
    fn read_u8(&mut self) -> Result<u8, NoData> { (*self).read_u8() }
    fn read_u32(&mut self) -> Result<u32, NoData> { (*self).read_u32() }
    fn read_var_int(&mut self) -> Result<u64, NoData> { (*self).read_var_int() }
    fn read_bytes(&mut self, len: u64) -> Result<VarIntBytes, NoData> {
        (*self).read_bytes(len)
    }
}

impl<T: ConsensusWrite> ConsensusWrite for &mut T {
    fn write_u8(&mut self, val: u8) -> Result<(), TooLarge> {
        (*self).write_u8(val)
    }
    fn write_u32(&mut self, val: u32) -> Result<(), TooLarge> {
        (*self).write_u32(val)
    }
    fn write_var_int(&mut self, val: u64) -> Result<(), TooLarge> {
        (*self).write_var_int(val)
    }
    fn write_bytes(&mut self, bytes: &VarIntBytes) -> Result<(), TooLarge> {
        (*self).write_bytes(bytes)
    }
}

#[derive(Clone, Debug, Default)]
pub struct MemBuf {
    pos: u32, // Can't be larger than 4000000
    buf: Vec<u8>,
}

impl ConsensusRead for MemBuf {
    fn is_empty(&self) -> bool { todo!() }

    fn read_u8(&mut self) -> Result<u8, NoData> { todo!() }

    fn read_u32(&mut self) -> Result<u32, NoData> { todo!() }

    fn read_var_int(&mut self) -> Result<u64, NoData> { todo!() }

    fn read_bytes(&mut self, len: u64) -> Result<VarIntBytes, NoData> {
        todo!()
    }
}

impl ConsensusWrite for MemBuf {
    fn write_u8(&mut self, val: u8) -> Result<(), TooLarge> { todo!() }

    fn write_u32(&mut self, val: u32) -> Result<(), TooLarge> { todo!() }

    fn write_var_int(&mut self, val: u64) -> Result<(), TooLarge> { todo!() }

    fn write_bytes(&mut self, bytes: &VarIntBytes) -> Result<(), TooLarge> {
        todo!()
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum DataError {
    #[from(NoData)]
    /// end of data reached while parsing with bitcoin consensus rules
    NoData,

    /// data left after complete deserialization of bitcoin structure
    ExcessiveData,
}

pub trait Deserialize: Sized {
    fn deserialize_from(reader: impl ConsensusRead) -> Result<Self, DataError>;
    fn deserialize_all(
        mut reader: impl ConsensusRead,
    ) -> Result<Self, DataError> {
        let me = Self::deserialize_from(&mut reader)?;
        if !reader.is_empty() {
            return Err(DataError::ExcessiveData);
        }
        Ok(me)
    }
}

pub trait Serialize {
    fn serialize_into(&self, into: impl ConsensusWrite)
        -> Result<(), TooLarge>;
}
