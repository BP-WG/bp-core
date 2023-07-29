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

use amplify::confinement::Confined;

use crate::opcodes::*;
use crate::{ScriptBytes, LIB_NAME_BITCOIN};

#[derive(Copy, Clone, Eq, PartialEq, Debug, Display)]
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
#[wrapper(Deref, Index, RangeOps, BorrowSlice, LowerHex, UpperHex)]
#[wrapper_mut(DerefMut, IndexMut, RangeMut, BorrowSliceMut)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BITCOIN)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct SigScript(
    #[from]
    #[from(Vec<u8>)]
    ScriptBytes,
);

#[derive(Wrapper, WrapperMut, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From, Default)]
#[wrapper(Deref, Index, RangeOps, BorrowSlice, LowerHex, UpperHex)]
#[wrapper_mut(DerefMut, IndexMut, RangeMut, BorrowSliceMut)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BITCOIN)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct ScriptPubkey(
    #[from]
    #[from(Vec<u8>)]
    ScriptBytes,
);

impl ScriptPubkey {
    pub fn new() -> Self { Self::default() }

    pub fn with_capacity(capacity: usize) -> Self {
        Self(ScriptBytes::from(Confined::with_capacity(capacity)))
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

    pub fn is_op_return(&self) -> bool { self[0] == OpCode::Return as u8 }

    /// Adds a single opcode to the script.
    pub fn push_opcode(&mut self, op_code: OpCode) {
        self.0.push(op_code as u8).expect("script exceeds 4GB");
    }
}
