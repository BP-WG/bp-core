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

use amplify::confinement;
use amplify::confinement::Confined;

use crate::opcodes::*;
use crate::{ScriptHash, VarInt, VarIntBytes, WitnessVer, LIB_NAME_BITCOIN};

#[derive(Wrapper, WrapperMut, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From, Default)]
#[wrapper(Deref, AsSlice, Hex)]
#[wrapper_mut(DerefMut, AsSliceMut)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BITCOIN)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(transparent))]
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
    pub fn from_checked(script_bytes: Vec<u8>) -> Self {
        Self(ScriptBytes::from_checked(script_bytes))
    }

    #[inline]
    pub fn as_script_bytes(&self) -> &ScriptBytes { &self.0 }
}

#[derive(Wrapper, WrapperMut, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From, Default)]
#[wrapper(Deref, AsSlice, Hex)]
#[wrapper_mut(DerefMut, AsSliceMut)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BITCOIN)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(transparent))]
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
    pub fn from_checked(script_bytes: Vec<u8>) -> Self {
        Self(ScriptBytes::from_checked(script_bytes))
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
        self.0.len() == 25
            && self.0[0] == OP_DUP
            && self.0[1] == OP_HASH160
            && self.0[2] == OP_PUSHBYTES_20
            && self.0[23] == OP_EQUALVERIFY
            && self.0[24] == OP_CHECKSIG
    }

    /// Checks whether a script pubkey is a P2SH output.
    #[inline]
    pub fn is_p2sh(&self) -> bool {
        self.0.len() == 23
            && self.0[0] == OP_HASH160
            && self.0[1] == OP_PUSHBYTES_20
            && self.0[22] == OP_EQUAL
    }

    #[inline]
    pub fn is_op_return(&self) -> bool { !self.is_empty() && self[0] == OpCode::Return as u8 }

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
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(transparent))]
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
    pub fn from_checked(script_bytes: Vec<u8>) -> Self {
        Self(ScriptBytes::from_checked(script_bytes))
    }

    pub fn p2sh_wpkh(hash: impl Into<[u8; 20]>) -> Self {
        Self::with_witness_program_unchecked(WitnessVer::V0, &hash.into())
    }

    pub fn p2sh_wsh(hash: impl Into<[u8; 32]>) -> Self {
        Self::with_witness_program_unchecked(WitnessVer::V0, &hash.into())
    }

    fn with_witness_program_unchecked(ver: WitnessVer, prog: &[u8]) -> Self {
        let mut script = Self::with_capacity(ScriptBytes::len_for_slice(prog.len()) + 2);
        script.push_opcode(ver.op_code());
        script.push_slice(prog);
        script
    }

    pub fn is_p2sh_wpkh(&self) -> bool {
        self.len() == 22 && self[0] == WitnessVer::V0.op_code() as u8 && self[1] == OP_PUSHBYTES_20
    }

    pub fn is_p2sh_wsh(&self) -> bool {
        self.len() == 34 && self[0] == WitnessVer::V0.op_code() as u8 && self[1] == OP_PUSHBYTES_32
    }

    /// Adds a single opcode to the script.
    #[inline]
    pub fn push_opcode(&mut self, op_code: OpCode) { self.0.push(op_code as u8); }

    pub fn to_script_pubkey(&self) -> ScriptPubkey { ScriptPubkey::p2sh(ScriptHash::from(self)) }

    #[inline]
    pub fn as_script_bytes(&self) -> &ScriptBytes { &self.0 }
}

#[derive(Wrapper, WrapperMut, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Default, Debug, From)]
#[wrapper(Deref, AsSlice, Hex)]
#[wrapper_mut(DerefMut, AsSliceMut)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BITCOIN)]
pub struct ScriptBytes(VarIntBytes);

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
    pub fn from_checked(script_bytes: Vec<u8>) -> Self {
        Self(Confined::try_from(script_bytes).expect("script exceeding 4GB"))
    }

    /// Adds instructions to push a number from 0 to 16 to the stack.
    ///
    /// # Panics
    ///
    /// If the number is greater than 16
    pub fn push_num(&mut self, num: i64) {
        // Taken from rust-bitcoin
        //
        // Encodes an integer in script(minimal CScriptNum) format.
        //
        // Writes bytes into the buffer and returns the number of bytes written.
        //
        // Note that `write_scriptint`/`read_scriptint` do not roundtrip if the value written
        // requires more than 4 bytes, this is in line with Bitcoin Core (see
        // [`CScriptNum::serialize`]).
        //
        // [`CScriptNum::serialize`]: <https://github.com/bitcoin/bitcoin/blob/8ae2808a4354e8dcc697f76bacc5e2f2befe9220/src/script/script.h#L345>
        pub fn write_scriptint(out: &mut [u8; 8], n: i64) -> usize {
            let mut len = 0;
            if n == 0 {
                return len;
            }

            let neg = n < 0;

            let mut abs = n.unsigned_abs();
            while abs > 0xFF {
                out[len] = (abs & 0xFF) as u8;
                len += 1;
                abs >>= 8;
            }
            // If the number's value causes the sign bit to be set, we need an extra
            // byte to get the correct value and correct sign bit
            if abs & 0x80 != 0 {
                out[len] = abs as u8;
                len += 1;
                out[len] = if neg { 0x80u8 } else { 0u8 };
                len += 1;
            }
            // Otherwise we just set the sign bit ourselves
            else {
                abs |= if neg { 0x80 } else { 0 };
                out[len] = abs as u8;
                len += 1;
            }
            len
        }

        match num {
            -1 => self.push(OP_PUSHNUM_NEG1),
            0 => self.push(OP_PUSHBYTES_0),
            1..=16 => self.push(num as u8 + (OP_PUSHNUM_1 - 1)),
            _ => {
                let mut buf = [0u8; 8];
                let len = write_scriptint(&mut buf, num);
                self.push_slice(&buf[..len]);
            }
        };
    }

    /// Adds instructions to push some arbitrary data onto the stack.
    ///
    /// # Panics
    ///
    /// The method panics if `data` length is greater or equal to 0x100000000.
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
        self.0.extend(data.iter().copied()).expect("script exceeds 4GB")
    }

    /// Computes the sum of `len` and the length of an appropriate push
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

    pub fn into_vec(self) -> Vec<u8> { self.0.release() }

    pub(crate) fn as_var_int_bytes(&self) -> &VarIntBytes { &self.0 }
}

#[cfg(feature = "serde")]
mod _serde {
    use amplify::hex::{FromHex, ToHex};
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

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
                Self::try_from(bytes)
                    .map_err(|_| D::Error::custom("invalid script length exceeding 4GB"))
            }
        }
    }
}

#[cfg(test)]
mod test {
    #![cfg_attr(coverage_nightly, coverage(off))]

    use amplify::hex::ToHex;

    use super::*;

    #[test]
    fn script_index() {
        let mut script = ScriptPubkey::op_return(&[0u8; 40]);
        assert_eq!(script[0], OP_RETURN);
        assert_eq!(&script[..2], &[OP_RETURN, OP_PUSHBYTES_40]);
        assert_eq!(&script[40..], &[0u8, 0u8]);
        assert_eq!(&script[2..4], &[0u8, 0u8]);
        assert_eq!(&script[2..=3], &[0u8, 0u8]);

        script[0] = 0xFF;
        script[..2].copy_from_slice(&[0xFF, 0xFF]);
        script[40..].copy_from_slice(&[0xFF, 0xFF]);
        script[2..4].copy_from_slice(&[0xFF, 0xFF]);
        script[2..=3].copy_from_slice(&[0xFF, 0xFF]);

        assert_eq!(script[0], 0xFF);
        assert_eq!(&script[..2], &[0xFF, 0xFF]);
        assert_eq!(&script[40..], &[0xFF, 0xFF]);
        assert_eq!(&script[2..4], &[0xFF, 0xFF]);
        assert_eq!(&script[2..=3], &[0xFF, 0xFF]);

        assert_eq!(
            &script.to_hex(),
            "ffffffff000000000000000000000000000000000000000000000000000000000000000000000000ffff"
        );
    }
}
