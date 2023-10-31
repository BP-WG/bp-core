// Bitcoin protocol consensus library.
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

use amplify::confinement;
use amplify::confinement::Confined;

use crate::opcodes::*;
use crate::{VarInt, VarIntArray, LIB_NAME_BITCOIN};

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Display)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
// TODO: Replace `try_from` with `from` since opcodes cover whole range of u8
#[strict_type(lib = LIB_NAME_BITCOIN, tags = repr, into_u8, try_from_u8)]
#[non_exhaustive]
#[repr(u8)]
pub enum OpCode {
    /// Push an empty array onto the stack.
    #[display("OP_PUSH_BYTES0")]
    PushBytes0 = OP_PUSHBYTES_0,

    /// Push the next 32 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES32")]
    PushBytes32 = OP_PUSHBYTES_32,

    /// Synonym for OP_RETURN.
    Reserved = OP_RESERVED,

    /// Fail the script immediately.
    #[display("OP_RETURN")]
    #[strict_type(dumb)]
    Return = OP_RETURN,

    /// Read the next byte as N; push the next N bytes as an array onto the
    /// stack.
    #[display("OP_PUSH_DATA1")]
    PushData1 = OP_PUSHDATA1,
    /// Read the next 2 bytes as N; push the next N bytes as an array onto the
    /// stack.
    #[display("OP_PUSH_DATA2")]
    PushData2 = OP_PUSHDATA2,
    /// Read the next 4 bytes as N; push the next N bytes as an array onto the
    /// stack.
    #[display("OP_PUSH_DATA3")]
    PushData4 = OP_PUSHDATA4,

    /// Push the array `0x01` onto the stack.
    #[display("OP_PUSHNUM_1")]
    PushNum1 = OP_PUSHNUM_1,

    /// Duplicates the top stack item.
    #[display("OP_DUP")]
    Dup = OP_DUP,

    /// Pushes 1 if the inputs are exactly equal, 0 otherwise.
    #[display("OP_EQUAL")]
    Equal = OP_EQUAL,

    /// Returns success if the inputs are exactly equal, failure otherwise.
    #[display("OP_EQUALVERIFY")]
    EqualVerify = OP_EQUALVERIFY,

    /// Pop the top stack item and push its RIPEMD160 hash.
    #[display("OP_RIPEMD160")]
    Ripemd160 = OP_RIPEMD160,

    /// Pop the top stack item and push its SHA1 hash.
    #[display("OP_SHA1")]
    Sha1 = OP_SHA1,

    /// Pop the top stack item and push its SHA256 hash.
    #[display("OP_SHA256")]
    Sha256 = OP_SHA256,

    /// Pop the top stack item and push its RIPEMD(SHA256) hash.
    #[display("OP_HASH160")]
    Hash160 = OP_HASH160,

    /// Pop the top stack item and push its SHA256(SHA256) hash.
    #[display("OP_HASH256")]
    Hash256 = OP_HASH256,

    /// <https://en.bitcoin.it/wiki/OP_CHECKSIG> pushing 1/0 for success/failure.
    #[display("OP_CHECKSIG")]
    CheckSig = OP_CHECKSIG,

    /// <https://en.bitcoin.it/wiki/OP_CHECKSIG> returning success/failure.
    #[display("OP_CHECKSIGVERIFY")]
    CheckSigVerify = OP_CHECKSIGVERIFY,
}

#[derive(Wrapper, WrapperMut, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From, Default)]
#[wrapper(Deref, AsSlice, Hex)]
#[wrapper_mut(DerefMut, AsSliceMut)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BITCOIN)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct SigScript(ScriptBytes);

impl TryFrom<Vec<u8>> for SigScript {
    type Error = confinement::Error;
    fn try_from(script_bytes: Vec<u8>) -> Result<Self, Self::Error> {
        ScriptBytes::try_from(script_bytes).map(Self)
    }
}

impl SigScript {
    #[inline]
    pub fn empty() -> Self { SigScript::default() }

    #[inline]
    pub fn new() -> Self { Self::default() }

    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        Self(ScriptBytes::from(Confined::with_capacity(capacity)))
    }

    /// Constructs script object assuming the script length is less than 4GB.
    /// Panics otherwise.
    #[inline]
    pub fn from_unsafe(script_bytes: Vec<u8>) -> Self {
        Self(ScriptBytes::from_unsafe(script_bytes))
    }

    #[inline]
    pub fn as_script_bytes(&self) -> &ScriptBytes { &self.0 }
}

#[derive(Wrapper, WrapperMut, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From, Default)]
#[wrapper(Deref, AsSlice, Hex)]
#[wrapper_mut(DerefMut, AsSliceMut)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BITCOIN)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct ScriptPubkey(ScriptBytes);

impl TryFrom<Vec<u8>> for ScriptPubkey {
    type Error = confinement::Error;
    fn try_from(script_bytes: Vec<u8>) -> Result<Self, Self::Error> {
        ScriptBytes::try_from(script_bytes).map(Self)
    }
}

impl ScriptPubkey {
    #[inline]
    pub fn new() -> Self { Self::default() }

    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        Self(ScriptBytes::from(Confined::with_capacity(capacity)))
    }

    /// Constructs script object assuming the script length is less than 4GB.
    /// Panics otherwise.
    #[inline]
    pub fn from_unsafe(script_bytes: Vec<u8>) -> Self {
        Self(ScriptBytes::from_unsafe(script_bytes))
    }

    pub fn p2pkh(hash: impl Into<[u8; 20]>) -> Self {
        let mut script = Self::with_capacity(25);
        script.push_opcode(OpCode::Dup);
        script.push_opcode(OpCode::Hash160);
        script.push_slice(&hash.into());
        script.push_opcode(OpCode::EqualVerify);
        script.push_opcode(OpCode::CheckSig);
        script
    }

    pub fn p2sh(hash: impl Into<[u8; 20]>) -> Self {
        let mut script = Self::with_capacity(23);
        script.push_opcode(OpCode::Hash160);
        script.push_slice(&hash.into());
        script.push_opcode(OpCode::Equal);
        script
    }

    pub fn op_return(data: &[u8]) -> Self {
        let mut script = Self::with_capacity(ScriptBytes::len_for_slice(data.len()) + 1);
        script.push_opcode(OpCode::Return);
        script.push_slice(data);
        script
    }

    /// Checks whether a script pubkey is a P2PKH output.
    #[inline]
    pub fn is_p2pkh(&self) -> bool {
        self.0.len() == 25 &&
            self.0[0] == OP_DUP &&
            self.0[1] == OP_HASH160 &&
            self.0[2] == OP_PUSHBYTES_20 &&
            self.0[23] == OP_EQUALVERIFY &&
            self.0[24] == OP_CHECKSIG
    }

    /// Checks whether a script pubkey is a P2SH output.
    #[inline]
    pub fn is_p2sh(&self) -> bool {
        self.0.len() == 23 &&
            self.0[0] == OP_HASH160 &&
            self.0[1] == OP_PUSHBYTES_20 &&
            self.0[22] == OP_EQUAL
    }

    #[inline]
    pub fn is_op_return(&self) -> bool { self[0] == OpCode::Return as u8 }

    /// Adds a single opcode to the script.
    #[inline]
    pub fn push_opcode(&mut self, op_code: OpCode) { self.0.push(op_code as u8) }

    #[inline]
    pub fn as_script_bytes(&self) -> &ScriptBytes { &self.0 }
}

#[derive(Wrapper, WrapperMut, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From, Default)]
#[wrapper(Deref, AsSlice, Hex)]
#[wrapper_mut(DerefMut, AsSliceMut)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BITCOIN)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct RedeemScript(ScriptBytes);

impl TryFrom<Vec<u8>> for RedeemScript {
    type Error = confinement::Error;
    fn try_from(script_bytes: Vec<u8>) -> Result<Self, Self::Error> {
        ScriptBytes::try_from(script_bytes).map(Self)
    }
}

impl RedeemScript {
    #[inline]
    pub fn new() -> Self { Self::default() }

    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        Self(ScriptBytes::from(Confined::with_capacity(capacity)))
    }

    /// Constructs script object assuming the script length is less than 4GB.
    /// Panics otherwise.
    #[inline]
    pub fn from_unsafe(script_bytes: Vec<u8>) -> Self {
        Self(ScriptBytes::from_unsafe(script_bytes))
    }

    /// Adds a single opcode to the script.
    #[inline]
    pub fn push_opcode(&mut self, op_code: OpCode) { self.0.push(op_code as u8); }

    #[inline]
    pub fn as_script_bytes(&self) -> &ScriptBytes { &self.0 }
}

#[derive(Wrapper, WrapperMut, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Default, Debug, From)]
#[wrapper(Deref, AsSlice, Hex)]
#[wrapper_mut(DerefMut, AsSliceMut)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BITCOIN)]
pub struct ScriptBytes(VarIntArray<u8>);

impl TryFrom<Vec<u8>> for ScriptBytes {
    type Error = confinement::Error;
    fn try_from(script_bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Confined::try_from(script_bytes).map(Self)
    }
}

impl ScriptBytes {
    /// Constructs script object assuming the script length is less than 4GB.
    /// Panics otherwise.
    #[inline]
    pub fn from_unsafe(script_bytes: Vec<u8>) -> Self {
        Self(Confined::try_from(script_bytes).expect("script exceeding 4GB"))
    }

    /// Adds instructions to push some arbitrary data onto the stack.
    ///
    /// ## Panics
    ///
    /// The method panics if `data` length is greater or equal to
    /// 0x100000000.
    pub fn push_slice(&mut self, data: &[u8]) {
        // Start with a PUSH opcode
        match data.len() as u64 {
            n if n < OP_PUSHDATA1 as u64 => {
                self.push(n as u8);
            }
            n if n < 0x100 => {
                self.push(OP_PUSHDATA1);
                self.push(n as u8);
            }
            n if n < 0x10000 => {
                self.push(OP_PUSHDATA2);
                self.push((n % 0x100) as u8);
                self.push((n / 0x100) as u8);
            }
            n if n < 0x100000000 => {
                self.push(OP_PUSHDATA4);
                self.push((n % 0x100) as u8);
                self.push(((n / 0x100) % 0x100) as u8);
                self.push(((n / 0x10000) % 0x100) as u8);
                self.push((n / 0x1000000) as u8);
            }
            _ => panic!("tried to put a 4bn+ sized object into a script!"),
        }
        // Then push the raw bytes
        self.extend(data);
    }

    #[inline]
    pub(crate) fn push(&mut self, data: u8) { self.0.push(data).expect("script exceeds 4GB") }

    #[inline]
    pub(crate) fn extend(&mut self, data: &[u8]) {
        self.0
            .extend(data.iter().copied())
            .expect("script exceeds 4GB")
    }

    /// Computes the sum of `len` and the lenght of an appropriate push
    /// opcode.
    pub fn len_for_slice(len: usize) -> usize {
        len + match len {
            0..=0x4b => 1,
            0x4c..=0xff => 2,
            0x100..=0xffff => 3,
            // we don't care about oversized, the other fn will panic anyway
            _ => 5,
        }
    }

    pub fn len_var_int(&self) -> VarInt { VarInt(self.len() as u64) }

    pub fn into_vec(self) -> Vec<u8> { self.0.into_inner() }

    pub(crate) fn as_var_int_array(&self) -> &VarIntArray<u8> { &self.0 }
}

#[cfg(feature = "serde")]
mod _serde {
    use amplify::hex::{FromHex, ToHex};
    use serde::{Deserialize, Serialize};
    use serde_crate::de::Error;
    use serde_crate::{Deserializer, Serializer};

    use super::*;

    impl Serialize for ScriptBytes {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer {
            if serializer.is_human_readable() {
                serializer.serialize_str(&self.to_hex())
            } else {
                serializer.serialize_bytes(self.as_slice())
            }
        }
    }

    impl<'de> Deserialize<'de> for ScriptBytes {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: Deserializer<'de> {
            if deserializer.is_human_readable() {
                String::deserialize(deserializer).and_then(|string| {
                    Self::from_hex(&string).map_err(|_| D::Error::custom("wrong hex data"))
                })
            } else {
                let bytes = Vec::<u8>::deserialize(deserializer)?;
                ScriptBytes::try_from(bytes)
                    .map_err(|_| D::Error::custom("invalid script length exceeding 4GB"))
            }
        }
    }
}
