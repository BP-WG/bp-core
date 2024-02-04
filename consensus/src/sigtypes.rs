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

use std::iter;

use secp256k1::{ecdsa, schnorr};

use crate::{NonStandardValue, LIB_NAME_BITCOIN};

#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash, Default)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BITCOIN, tags = repr, into_u8, try_from_u8)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
#[repr(u8)]
pub enum SighashFlag {
    /// 0x1: Sign all outputs.
    #[default]
    All = 0x01,
    /// 0x2: Sign no outputs --- anyone can choose the destination.
    None = 0x02,
    /// 0x3: Sign the output whose index matches this input's index. If none
    /// exists, sign the hash
    /// `0000000000000000000000000000000000000000000000000000000000000001`.
    /// (This rule is probably an unintentional C++ism, but it's consensus so we
    /// have to follow it.)
    Single = 0x03,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash, Default)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BITCOIN)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct SighashType {
    pub flag: SighashFlag,
    pub anyone_can_pay: bool,
}

impl SighashType {
    pub const fn all() -> Self {
        SighashType {
            flag: SighashFlag::All,
            anyone_can_pay: false,
        }
    }
    pub const fn none() -> Self {
        SighashType {
            flag: SighashFlag::None,
            anyone_can_pay: false,
        }
    }
    pub const fn single() -> Self {
        SighashType {
            flag: SighashFlag::Single,
            anyone_can_pay: false,
        }
    }

    pub const fn all_anyone_can_pay() -> Self {
        SighashType {
            flag: SighashFlag::All,
            anyone_can_pay: true,
        }
    }
    pub const fn none_anyone_can_pay() -> Self {
        SighashType {
            flag: SighashFlag::None,
            anyone_can_pay: true,
        }
    }
    pub const fn single_anyone_can_pay() -> Self {
        SighashType {
            flag: SighashFlag::Single,
            anyone_can_pay: true,
        }
    }

    /// Creates a [`SighashType`] from a raw `u32`.
    ///
    /// **Note**: this replicates consensus behaviour, for current standardness
    /// rules correctness you probably want [`Self::from_standard_u32`].
    ///
    /// This might cause unexpected behavior because it does not roundtrip. That
    /// is, `LegacySighashType::from_consensus(n) as u32 != n` for
    /// non-standard values of `n`. While verifying signatures, the user
    /// should retain the `n` and use it compute the signature hash message.
    pub fn from_consensus_u32(n: u32) -> SighashType {
        // In Bitcoin Core, the SignatureHash function will mask the (int32) value with
        // 0x1f to (apparently) deactivate ACP when checking for SINGLE and NONE bits.
        // We however want to be matching also against on ACP-masked ALL, SINGLE, and
        // NONE. So here we re-activate ACP.
        let mask = 0x1f | 0x80;
        let (flag, anyone_can_pay) = match n & mask {
            // "real" sighashes
            0x01 => (SighashFlag::All, false),
            0x02 => (SighashFlag::None, false),
            0x03 => (SighashFlag::Single, false),
            0x81 => (SighashFlag::All, true),
            0x82 => (SighashFlag::None, true),
            0x83 => (SighashFlag::Single, true),
            // catchalls
            x if x & 0x80 == 0x80 => (SighashFlag::All, true),
            _ => (SighashFlag::All, false),
        };
        SighashType {
            flag,
            anyone_can_pay,
        }
    }

    /// Creates a [`SighashType`] from a raw `u32`.
    ///
    /// # Errors
    ///
    /// If `n` is a non-standard sighash value.
    pub fn from_standard_u32(n: u32) -> Result<SighashType, NonStandardValue<u32>> {
        let (flag, anyone_can_pay) = match n {
            // Standard sighashes, see https://github.com/bitcoin/bitcoin/blob/b805dbb0b9c90dadef0424e5b3bf86ac308e103e/src/script/interpreter.cpp#L189-L198
            0x01 => (SighashFlag::All, false),
            0x02 => (SighashFlag::None, false),
            0x03 => (SighashFlag::Single, false),
            0x81 => (SighashFlag::All, true),
            0x82 => (SighashFlag::None, true),
            0x83 => (SighashFlag::Single, true),
            non_standard => return Err(NonStandardValue::with(non_standard, "SighashType")),
        };
        Ok(SighashType {
            flag,
            anyone_can_pay,
        })
    }

    /// Converts [`SighashType`] to a `u32` sighash flag.
    ///
    /// The returned value is guaranteed to be a valid according to standardness
    /// rules.
    #[inline]
    pub const fn into_consensus_u32(self) -> u32 { self.into_consensus_u8() as u32 }

    /// Converts [`SighashType`] to a `u32` sighash flag.
    ///
    /// The returned value is guaranteed to be a valid according to standardness
    /// rules.
    #[inline]
    pub const fn to_consensus_u32(&self) -> u32 { self.into_consensus_u32() }

    pub const fn into_consensus_u8(self) -> u8 {
        let flag = self.flag as u8;
        let mask = (self.anyone_can_pay as u8) << 7;
        flag | mask
    }

    pub const fn to_consensus_u8(self) -> u8 {
        let flag = self.flag as u8;
        let mask = (self.anyone_can_pay as u8) << 7;
        flag | mask
    }
}

/// An ECDSA signature-related error.
#[derive(Clone, PartialEq, Eq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum SigError {
    /// Non-standard sighash type.
    #[display(inner)]
    #[from]
    SighashType(NonStandardValue<u32>),

    /// empty signature.
    EmptySignature,

    /// invalid signature DER encoding.
    DerEncoding,

    /// invalid BIP340 signature length ({0}).
    Bip340Encoding(usize),

    /// invalid BIP340 signature.
    InvalidSignature,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
#[derive(StrictType)]
#[strict_type(lib = LIB_NAME_BITCOIN)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct LegacySig {
    /// The underlying ECDSA Signature
    pub sig: ecdsa::Signature,
    /// The corresponding hash type
    pub sighash_type: SighashType,
}

impl LegacySig {
    /// Constructs an ECDSA bitcoin signature for [`SighashType::All`].
    pub fn sighash_all(sig: ecdsa::Signature) -> LegacySig {
        LegacySig {
            sig,
            sighash_type: SighashType::all(),
        }
    }

    /// Deserializes from slice following the standardness rules for
    /// [`SighashType`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SigError> {
        let (hash_ty, sig) = bytes.split_last().ok_or(SigError::EmptySignature)?;
        let sighash_type = SighashType::from_standard_u32(*hash_ty as u32)?;
        let sig = ecdsa::Signature::from_der(sig).map_err(|_| SigError::DerEncoding)?;
        Ok(LegacySig { sig, sighash_type })
    }

    /// Serializes an Legacy signature (inner secp256k1 signature in DER format)
    /// into `Vec`.
    // TODO: add support to serialize to a writer to SerializedSig
    pub fn to_vec(self) -> Vec<u8> {
        self.sig
            .serialize_der()
            .iter()
            .copied()
            .chain(iter::once(self.sighash_type.into_consensus_u8()))
            .collect()
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
#[derive(StrictType)]
#[strict_type(lib = LIB_NAME_BITCOIN)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct Bip340Sig {
    /// The underlying ECDSA Signature
    pub sig: schnorr::Signature,
    /// The corresponding hash type
    pub sighash_type: Option<SighashType>,
}

impl Bip340Sig {
    /// Constructs an ECDSA bitcoin signature for [`SighashType::All`].
    pub fn sighash_default(sig: schnorr::Signature) -> Self {
        Bip340Sig {
            sig,
            sighash_type: None,
        }
    }

    /// Deserializes from slice following the standardness rules for
    /// [`SighashType`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SigError> {
        let (hash_ty, sig) = match bytes.len() {
            0 => return Err(SigError::EmptySignature),
            64 => (None, bytes),
            65 => (Some(bytes[64] as u32), &bytes[..64]),
            invalid => return Err(SigError::Bip340Encoding(invalid)),
        };
        let sighash_type = hash_ty.map(SighashType::from_standard_u32).transpose()?;
        let sig = schnorr::Signature::from_slice(sig).map_err(|_| SigError::InvalidSignature)?;
        Ok(Bip340Sig { sig, sighash_type })
    }

    /// Serializes an ECDSA signature (inner secp256k1 signature in DER format)
    /// into `Vec`.
    // TODO: add support to serialize to a writer to SerializedSig
    pub fn to_vec(self) -> Vec<u8> {
        let mut ser = Vec::<u8>::with_capacity(65);
        ser.extend_from_slice(&self.sig[..]);
        if let Some(sighash_type) = self.sighash_type {
            ser.push(sighash_type.into_consensus_u8())
        }
        ser
    }
}

mod _strict_encode {
    use std::io;

    use amplify::confinement::TinyBlob;
    use amplify::hex::FromHex;
    use amplify::Bytes64;
    use strict_encoding::{
        DecodeError, ReadStruct, StrictDecode, StrictDumb, StrictEncode, TypedRead, TypedWrite,
        WriteStruct,
    };

    use super::*;

    impl StrictDumb for LegacySig {
        fn strict_dumb() -> Self {
            Self {
                sig: ecdsa::Signature::from_der(&Vec::<u8>::from_hex(
                    "304402206fa6c164fb89906e2e1d291cc5461ceadf0f115c6b71e58f87482c94d512c3630220\
                    0ab641f3ece1d77f13ad2d8910cb7abd5a9b85f0f9036317dbb1470f22e7714c").unwrap()
                ).expect("hardcoded signature"),
                sighash_type: default!(),
            }
        }
    }

    impl StrictEncode for LegacySig {
        fn strict_encode<W: TypedWrite>(&self, writer: W) -> io::Result<W> {
            writer.write_struct::<Self>(|w| {
                Ok(w.write_field(
                    fname!("sig"),
                    &TinyBlob::try_from(self.sig.serialize_der().to_vec())
                        .expect("invalid signature"),
                )?
                .write_field(fname!("sighash_type"), &self.sighash_type)?
                .complete())
            })
        }
    }

    impl StrictDecode for LegacySig {
        fn strict_decode(reader: &mut impl TypedRead) -> Result<Self, DecodeError> {
            reader.read_struct(|r| {
                let bytes: TinyBlob = r.read_field(fname!("sig"))?;
                let sig = ecdsa::Signature::from_der(bytes.as_slice()).map_err(|_| {
                    DecodeError::DataIntegrityError(s!("invalid signature DER encoding"))
                })?;
                let sighash_type = r.read_field(fname!("sighash_type"))?;
                Ok(Self { sig, sighash_type })
            })
        }
    }

    impl StrictDumb for Bip340Sig {
        fn strict_dumb() -> Self {
            Bip340Sig::from_bytes(&Vec::<u8>::from_hex(
                "a12b3f4c224619d7834f0bad0a598b79111ba08146ae1205f3e6220a132aef0ed8290379624db643\
                e6b861d8dcd37b406a11f91a51bf5a6cdf9b3c9b772f67c301"
            ).unwrap())
            .expect("hardcoded signature")
        }
    }

    impl StrictEncode for Bip340Sig {
        fn strict_encode<W: TypedWrite>(&self, writer: W) -> io::Result<W> {
            writer.write_struct::<Self>(|w| {
                Ok(w.write_field(fname!("sig"), &Bytes64::from(*self.sig.as_ref()))?
                    .write_field(fname!("sighash_type"), &self.sighash_type)?
                    .complete())
            })
        }
    }

    impl StrictDecode for Bip340Sig {
        fn strict_decode(reader: &mut impl TypedRead) -> Result<Self, DecodeError> {
            reader.read_struct(|r| {
                let bytes: Bytes64 = r.read_field(fname!("sig"))?;
                let sig = schnorr::Signature::from_slice(bytes.as_slice()).map_err(|_| {
                    DecodeError::DataIntegrityError(format!(
                        "invalid signature BIP340 encoding '{bytes:x}'"
                    ))
                })?;
                let sighash_type = r.read_field(fname!("sighash_type"))?;
                Ok(Self { sig, sighash_type })
            })
        }
    }
}
