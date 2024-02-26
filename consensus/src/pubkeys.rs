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

use std::io;
use std::str::FromStr;

use amplify::hex::FromHex;
use amplify::{hex, Bytes, Wrapper};
use secp256k1::PublicKey;
use strict_encoding::{
    DecodeError, ReadStruct, ReadTuple, StrictDecode, StrictEncode, TypedRead, TypedWrite,
    WriteStruct,
};

use crate::LIB_NAME_BITCOIN;

#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum PubkeyParseError<const LEN: usize> {
    #[from]
    Hex(hex::Error),
    #[from]
    InvalidPubkey(InvalidPubkey<LEN>),
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, Display, From, Error)]
pub enum InvalidPubkey<const LEN: usize> {
    #[from(secp256k1::Error)]
    #[display("invalid public key")]
    Unspecified,

    #[from]
    #[display("invalid public key {0:x}")]
    Specified(Bytes<LEN>),
}

#[derive(Wrapper, WrapperMut, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrapper(Deref, LowerHex, Display)]
#[wrapper_mut(DerefMut)]
#[derive(StrictType, StrictDumb)]
#[strict_type(lib = LIB_NAME_BITCOIN, dumb = Self::dumb())]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct CompressedPk(PublicKey);

impl CompressedPk {
    fn dumb() -> Self { Self(PublicKey::from_slice(&[2u8; 33]).unwrap()) }

    pub fn from_byte_array(data: [u8; 33]) -> Result<Self, InvalidPubkey<33>> {
        PublicKey::from_slice(&data)
            .map(Self)
            .map_err(|_| InvalidPubkey::Specified(data.into()))
    }
    pub fn to_byte_array(&self) -> [u8; 33] { self.0.serialize() }

    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, InvalidPubkey<33>> {
        Ok(CompressedPk(PublicKey::from_slice(bytes.as_ref())?))
    }
}

impl StrictEncode for CompressedPk {
    fn strict_encode<W: TypedWrite>(&self, writer: W) -> io::Result<W> {
        let bytes = Bytes::<33>::from(self.0.serialize());
        writer.write_newtype::<Self>(&bytes)
    }
}

impl StrictDecode for CompressedPk {
    fn strict_decode(reader: &mut impl TypedRead) -> Result<Self, DecodeError> {
        reader.read_tuple(|r| {
            let bytes: Bytes<33> = r.read_field()?;
            PublicKey::from_slice(bytes.as_slice())
                .map(Self)
                .map_err(|_| InvalidPubkey::Specified(bytes).into())
        })
    }
}

impl FromStr for CompressedPk {
    type Err = PubkeyParseError<33>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let data = <[u8; 33]>::from_hex(s)?;
        let pk = Self::from_byte_array(data)?;
        Ok(pk)
    }
}

#[derive(Wrapper, WrapperMut, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrapper(Deref, LowerHex, Display)]
#[wrapper_mut(DerefMut)]
#[derive(StrictType, StrictDumb)]
#[strict_type(lib = LIB_NAME_BITCOIN, dumb = Self::dumb())]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct UncompressedPk(PublicKey);

impl UncompressedPk {
    fn dumb() -> Self { Self(PublicKey::from_slice(&[2u8; 33]).unwrap()) }

    pub fn from_byte_array(data: [u8; 65]) -> Result<Self, InvalidPubkey<65>> {
        PublicKey::from_slice(&data)
            .map(Self)
            .map_err(|_| InvalidPubkey::Specified(data.into()))
    }
    pub fn to_byte_array(&self) -> [u8; 65] { self.0.serialize_uncompressed() }
}

impl StrictEncode for UncompressedPk {
    fn strict_encode<W: TypedWrite>(&self, writer: W) -> io::Result<W> {
        let bytes = Bytes::<65>::from(self.0.serialize_uncompressed());
        writer.write_newtype::<Self>(&bytes)
    }
}

impl StrictDecode for UncompressedPk {
    fn strict_decode(reader: &mut impl TypedRead) -> Result<Self, DecodeError> {
        reader.read_tuple(|r| {
            let bytes: Bytes<65> = r.read_field()?;
            PublicKey::from_slice(bytes.as_slice())
                .map(Self)
                .map_err(|_| InvalidPubkey::Specified(bytes).into())
        })
    }
}

impl FromStr for UncompressedPk {
    type Err = PubkeyParseError<65>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let data = <[u8; 65]>::from_hex(s)?;
        let pk = Self::from_byte_array(data)?;
        Ok(pk)
    }
}

#[derive(Wrapper, WrapperMut, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[wrapper(Deref, LowerHex, Display)]
#[wrapper_mut(DerefMut)]
#[derive(StrictType, StrictDumb)]
#[strict_type(lib = LIB_NAME_BITCOIN, dumb = Self::dumb())]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct LegacyPk {
    pub compressed: bool,
    #[wrap]
    pub pubkey: PublicKey,
}

impl From<PublicKey> for LegacyPk {
    fn from(pk: PublicKey) -> Self { LegacyPk::compressed(pk) }
}

impl From<CompressedPk> for LegacyPk {
    fn from(pk: CompressedPk) -> Self { LegacyPk::compressed(pk.0) }
}

impl From<UncompressedPk> for LegacyPk {
    fn from(pk: UncompressedPk) -> Self { LegacyPk::uncompressed(pk.0) }
}

impl LegacyPk {
    fn dumb() -> Self { Self::compressed(PublicKey::from_slice(&[2u8; 33]).unwrap()) }

    pub const fn compressed(pubkey: PublicKey) -> Self {
        LegacyPk {
            compressed: true,
            pubkey,
        }
    }

    pub const fn uncompressed(pubkey: PublicKey) -> Self {
        LegacyPk {
            compressed: false,
            pubkey,
        }
    }

    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, InvalidPubkey<65>> {
        let bytes = bytes.as_ref();
        let pubkey = PublicKey::from_slice(bytes)?;
        Ok(match bytes.len() {
            33 => Self::compressed(pubkey),
            65 => Self::uncompressed(pubkey),
            _ => unreachable!(),
        })
    }

    pub fn to_vec(&self) -> Vec<u8> {
        match self.compressed {
            true => self.pubkey.serialize().to_vec(),
            false => self.pubkey.serialize_uncompressed().to_vec(),
        }
    }
}

impl StrictEncode for LegacyPk {
    fn strict_encode<W: TypedWrite>(&self, writer: W) -> io::Result<W> {
        writer.write_struct::<Self>(|w| {
            let bytes = Bytes::<33>::from(self.pubkey.serialize());
            Ok(w.write_field(fname!("compressed"), &self.compressed)?
                .write_field(fname!("pubkey"), &bytes)?
                .complete())
        })
    }
}

impl StrictDecode for LegacyPk {
    fn strict_decode(reader: &mut impl TypedRead) -> Result<Self, DecodeError> {
        reader.read_struct(|r| {
            let compressed = r.read_field(fname!("compressed"))?;
            let bytes: Bytes<33> = r.read_field(fname!("pubkey"))?;
            let pubkey = PublicKey::from_slice(bytes.as_slice())
                .map_err(|_| InvalidPubkey::Specified(bytes))?;
            Ok(LegacyPk { compressed, pubkey })
        })
    }
}

impl FromStr for LegacyPk {
    type Err = PubkeyParseError<65>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let data = Vec::<u8>::from_hex(s)?;
        let pk = Self::from_bytes(data)?;
        Ok(pk)
    }
}
