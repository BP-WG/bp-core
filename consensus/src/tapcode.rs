// Bitcoin protocol consensus library.
//
// SPDX-License-Identifier: Apache-2.0
//
// Designed in 2019-2025 by Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
// Written in 2024-2025 by Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association, Switzerland.
// Copyright (C) 2024-2025 LNP/BP Labs, Institute for Distributed and Cognitive Systems (InDCS).
// Copyright (C) 2019-2025 Dr Maxim Orlovsky.
// All rights under the above copyrights are reserved.
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

use crate::opcodes::*;
use crate::LIB_NAME_BITCOIN;

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Display)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BITCOIN, tags = repr, into_u8, try_from_u8)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[non_exhaustive]
#[repr(u8)]
pub enum TapCode {
    /// Push an empty array onto the stack.
    ///
    /// Also, a synonym for `OP_0` and `OP_FALSE`.
    #[display("OP_PUSH_BYTES0")]
    PushBytes0 = OP_PUSHBYTES_0,
    /// Push the next byte as an array onto the stack.
    #[display("OP_PUSH_BYTES1")]
    PushBytes1 = OP_PUSHBYTES_1,
    /// Push the next 2 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES2")]
    PushBytes2 = OP_PUSHBYTES_2,
    /// Push the next 3 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES3")]
    PushBytes3 = OP_PUSHBYTES_3,
    /// Push the next 4 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES4")]
    PushBytes4 = OP_PUSHBYTES_4,
    /// Push the next 5 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES5")]
    PushBytes5 = OP_PUSHBYTES_5,
    /// Push the next 6 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES6")]
    PushBytes6 = OP_PUSHBYTES_6,
    /// Push the next 7 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES7")]
    PushBytes7 = OP_PUSHBYTES_7,
    /// Push the next 8 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES8")]
    PushBytes8 = OP_PUSHBYTES_8,
    /// Push the next 9 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES9")]
    PushBytes9 = OP_PUSHBYTES_9,
    /// Push the next 10 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES10")]
    PushBytes10 = OP_PUSHBYTES_10,
    /// Push the next 11 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES11")]
    PushBytes11 = OP_PUSHBYTES_11,
    /// Push the next 12 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES12")]
    PushBytes12 = OP_PUSHBYTES_12,
    /// Push the next 13 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES13")]
    PushBytes13 = OP_PUSHBYTES_13,
    /// Push the next 14 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES14")]
    PushBytes14 = OP_PUSHBYTES_14,
    /// Push the next 15 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES15")]
    PushBytes15 = OP_PUSHBYTES_15,
    /// Push the next 16 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES16")]
    PushBytes16 = OP_PUSHBYTES_16,
    /// Push the next 17 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES17")]
    PushBytes17 = OP_PUSHBYTES_17,
    /// Push the next 18 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES18")]
    PushBytes18 = OP_PUSHBYTES_18,
    /// Push the next 19 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES19")]
    PushBytes19 = OP_PUSHBYTES_19,
    /// Push the next 20 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES20")]
    PushBytes20 = OP_PUSHBYTES_20,
    /// Push the next 21 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES21")]
    PushBytes21 = OP_PUSHBYTES_21,
    /// Push the next 22 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES22")]
    PushBytes22 = OP_PUSHBYTES_22,
    /// Push the next 23 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES23")]
    PushBytes23 = OP_PUSHBYTES_23,
    /// Push the next 24 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES24")]
    PushBytes24 = OP_PUSHBYTES_24,
    /// Push the next 25 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES25")]
    PushBytes25 = OP_PUSHBYTES_25,
    /// Push the next 26 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES26")]
    PushBytes26 = OP_PUSHBYTES_26,
    /// Push the next 27 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES27")]
    PushBytes27 = OP_PUSHBYTES_27,
    /// Push the next 28 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES28")]
    PushBytes28 = OP_PUSHBYTES_28,
    /// Push the next 29 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES29")]
    PushBytes29 = OP_PUSHBYTES_29,
    /// Push the next 30 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES30")]
    PushBytes30 = OP_PUSHBYTES_30,
    /// Push the next 31 byte as an array onto the stack.
    #[display("OP_PUSH_BYTES31")]
    PushBytes31 = OP_PUSHBYTES_31,
    /// Push the next 32 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES32")]
    PushBytes32 = OP_PUSHBYTES_32,
    /// Push the next 33 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES33")]
    PushBytes33 = OP_PUSHBYTES_33,
    /// Push the next 34 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES34")]
    PushBytes34 = OP_PUSHBYTES_34,
    /// Push the next 35 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES35")]
    PushBytes35 = OP_PUSHBYTES_35,
    /// Push the next 36 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES36")]
    PushBytes36 = OP_PUSHBYTES_36,
    /// Push the next 37 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES37")]
    PushBytes37 = OP_PUSHBYTES_37,
    /// Push the next 38 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES38")]
    PushBytes38 = OP_PUSHBYTES_38,
    /// Push the next 39 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES39")]
    PushBytes39 = OP_PUSHBYTES_39,
    /// Push the next 40 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES40")]
    PushBytes40 = OP_PUSHBYTES_40,
    /// Push the next 41 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES41")]
    PushBytes41 = OP_PUSHBYTES_41,
    /// Push the next 42 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES42")]
    PushBytes42 = OP_PUSHBYTES_42,
    /// Push the next 43 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES43")]
    PushBytes43 = OP_PUSHBYTES_43,
    /// Push the next 44 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES44")]
    PushBytes44 = OP_PUSHBYTES_44,
    /// Push the next 45 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES45")]
    PushBytes45 = OP_PUSHBYTES_45,
    /// Push the next 46 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES46")]
    PushBytes46 = OP_PUSHBYTES_46,
    /// Push the next 47 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES47")]
    PushBytes47 = OP_PUSHBYTES_47,
    /// Push the next 48 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES48")]
    PushBytes48 = OP_PUSHBYTES_48,
    /// Push the next 49 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES49")]
    PushBytes49 = OP_PUSHBYTES_49,
    /// Push the next 50 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES50")]
    PushBytes50 = OP_PUSHBYTES_50,
    /// Push the next 51 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES51")]
    PushBytes51 = OP_PUSHBYTES_51,
    /// Push the next 52 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES52")]
    PushBytes52 = OP_PUSHBYTES_52,
    /// Push the next 53 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES53")]
    PushBytes53 = OP_PUSHBYTES_53,
    /// Push the next 54 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES54")]
    PushBytes54 = OP_PUSHBYTES_54,
    /// Push the next 55 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES55")]
    PushBytes55 = OP_PUSHBYTES_55,
    /// Push the next 56 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES56")]
    PushBytes56 = OP_PUSHBYTES_56,
    /// Push the next 57 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES57")]
    PushBytes57 = OP_PUSHBYTES_57,
    /// Push the next 58 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES58")]
    PushBytes58 = OP_PUSHBYTES_58,
    /// Push the next 59 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES59")]
    PushBytes59 = OP_PUSHBYTES_59,
    /// Push the next 60 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES60")]
    PushBytes60 = OP_PUSHBYTES_60,
    /// Push the next 61 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES61")]
    PushBytes61 = OP_PUSHBYTES_61,
    /// Push the next 62 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES62")]
    PushBytes62 = OP_PUSHBYTES_62,
    /// Push the next 63 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES63")]
    PushBytes63 = OP_PUSHBYTES_63,
    /// Push the next 64 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES64")]
    PushBytes64 = OP_PUSHBYTES_64,
    /// Push the next 65 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES65")]
    PushBytes65 = OP_PUSHBYTES_65,
    /// Push the next 66 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES66")]
    PushBytes66 = OP_PUSHBYTES_66,
    /// Push the next 67 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES67")]
    PushBytes67 = OP_PUSHBYTES_67,
    /// Push the next 68 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES68")]
    PushBytes68 = OP_PUSHBYTES_68,
    /// Push the next 69 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES69")]
    PushBytes69 = OP_PUSHBYTES_69,
    /// Push the next 70 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES70")]
    PushBytes70 = OP_PUSHBYTES_70,
    /// Push the next 71 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES71")]
    PushBytes71 = OP_PUSHBYTES_71,
    /// Push the next 72 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES72")]
    PushBytes72 = OP_PUSHBYTES_72,
    /// Push the next 73 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES73")]
    PushBytes73 = OP_PUSHBYTES_73,
    /// Push the next 74 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES74")]
    PushByte764 = OP_PUSHBYTES_74,
    /// Push the next 75 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES75")]
    PushBytes75 = OP_PUSHBYTES_75,

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

    /// Push the array `0x81` onto the stack.
    #[display("OP_PUSHNUM_NEG1")]
    PushNumNeg1 = OP_PUSHNUM_NEG1,

    /// One of `OP_SUCCESSx` op-codes.
    #[display("OP_SUCCESS80")]
    Success80 = OP_RESERVED,

    /// Push the array `0x01` onto the stack.
    ///
    /// Also, a synonym for `OP_1` and `OP_TRUE`.
    #[display("OP_PUSHNUM_1")]
    PushNum1 = OP_PUSHNUM_1,
    /// Push the array `0x02` onto the stack.
    #[display("OP_PUSHNUM_2")]
    PushNum2 = OP_PUSHNUM_2,
    /// Push the array `0x03` onto the stack.
    #[display("OP_PUSHNUM_3")]
    PushNum3 = OP_PUSHNUM_3,
    /// Push the array `0x04` onto the stack.
    #[display("OP_PUSHNUM_4")]
    PushNum4 = OP_PUSHNUM_4,
    /// Push the array `0x05` onto the stack.
    #[display("OP_PUSHNUM_5")]
    PushNum5 = OP_PUSHNUM_5,
    /// Push the array `0x06` onto the stack.
    #[display("OP_PUSHNUM_6")]
    PushNum6 = OP_PUSHNUM_6,
    /// Push the array `0x07` onto the stack.
    #[display("OP_PUSHNUM_7")]
    PushNum7 = OP_PUSHNUM_7,
    /// Push the array `0x08` onto the stack.
    #[display("OP_PUSHNUM_8")]
    PushNum8 = OP_PUSHNUM_8,
    /// Push the array `0x09` onto the stack.
    #[display("OP_PUSHNUM_9")]
    PushNum9 = OP_PUSHNUM_9,
    /// Push the array `0x0A` onto the stack.
    #[display("OP_PUSHNUM_10")]
    PushNum10 = OP_PUSHNUM_10,
    /// Push the array `0x0B` onto the stack.
    #[display("OP_PUSHNUM_11")]
    PushNum11 = OP_PUSHNUM_11,
    /// Push the array `0x0C` onto the stack.
    #[display("OP_PUSHNUM_12")]
    PushNum12 = OP_PUSHNUM_12,
    /// Push the array `0x0D` onto the stack.
    #[display("OP_PUSHNUM_13")]
    PushNum13 = OP_PUSHNUM_13,
    /// Push the array `0x0E` onto the stack.
    #[display("OP_PUSHNUM_14")]
    PushNum14 = OP_PUSHNUM_14,
    /// Push the array `0x0F` onto the stack.
    #[display("OP_PUSHNUM_15")]
    PushNum15 = OP_PUSHNUM_15,
    /// Push the array `0x10` onto the stack.
    #[display("OP_PUSHNUM_16")]
    PushNum16 = OP_PUSHNUM_16,

    /// Does nothing.
    #[display("OP_NOP")]
    Nop = OP_NOP,

    /// One of `OP_SUCCESSx` op-codes.
    #[display("OP_SUCCESS98")]
    Success98 = OP_VER,

    /// Pop and execute the next statements if a nonzero element was popped.
    #[display("OP_IF")]
    If = OP_IF,
    /// Pop and execute the next statements if a zero element was popped.
    #[display("OP_NOTIF")]
    NotIf = OP_NOTIF,
    /// Fail the script unconditionally, does not even need to be executed.
    #[display("OP_VERIF")]
    VerIf = OP_VERIF,
    /// Fail the script unconditionally, does not even need to be executed.
    #[display("OP_VERNOTIF")]
    VerNotIf = OP_VERNOTIF,
    /// Execute statements if those after the previous OP_IF were not, and
    /// vice versa. If there is no previous OP_IF, this acts as an OP_RETURN.
    #[display("OP_ELSE")]
    Else = OP_ELSE,
    /// Pop and execute the next statements if a zero element was popped.
    #[display("OP_ENDIF")]
    EndIf = OP_ENDIF,
    /// If the top value is zero or the stack is empty, fail; otherwise, pop the
    /// stack.
    #[display("OP_VERIFY")]
    Verify = OP_VERIFY,

    /// Fail the script immediately.
    #[display("OP_RETURN")]
    #[strict_type(dumb)]
    Return = OP_RETURN,

    #[display("OP_TOALTSTACK")]
    ToAltStack = OP_TOALTSTACK,
    /// Pop one element from the alt stack onto the main stack.
    #[display("OP_FROMALTSTACK")]
    FromAltStack = OP_FROMALTSTACK,
    /// Drops the top two stack items.
    #[display("OP_2DROP")]
    Drop2 = OP_2DROP,
    /// Duplicates the top two stack items as AB -> ABAB.
    #[display("OP_2DUP")]
    Dup2 = OP_2DUP,
    /// Duplicates the two three stack items as ABC -> ABCABC.
    #[display("OP_3DUP")]
    Dup3 = OP_3DUP,
    /// Copies the two stack items of items two spaces back to the front, as xxAB ->
    /// ABxxAB.
    #[display("OP_2OVER")]
    Over2 = OP_2OVER,
    /// Moves the two stack items four spaces back to the front, as xxxxAB ->
    /// ABxxxx.
    #[display("OP_2ROT")]
    Rot2 = OP_2ROT,
    /// Swaps the top two pairs, as ABCD -> CDAB.
    #[display("OP_2SWAP")]
    Swap2 = OP_2SWAP,
    /// Duplicate the top stack element unless it is zero.
    #[display("OP_IFDUP")]
    IfDup = OP_IFDUP,
    /// Push the current number of stack items onto the stack.
    #[display("OP_DEPTH")]
    Depth = OP_DEPTH,
    /// Drops the top stack item.
    #[display("OP_DROP")]
    Drop = OP_DROP,
    /// Duplicates the top stack item.
    #[display("OP_DUP")]
    Dup = OP_DUP,
    /// Drops the second-to-top stack item.
    #[display("OP_NIP")]
    Nip = OP_NIP,
    /// Copies the second-to-top stack item, as xA -> AxA.
    #[display("OP_OVER")]
    Over = OP_OVER,
    /// Pop the top stack element as N. Copy the Nth stack element to the top.
    #[display("OP_PICK")]
    Pick = OP_PICK,
    /// Pop the top stack element as N. Move the Nth stack element to the top.
    #[display("OP_ROLL")]
    Roll = OP_ROLL,
    /// Rotate the top three stack items, as [top next1 next2] -> [next2 top next1].
    #[display("OP_ROT")]
    Rot = OP_ROT,
    /// Swap the top two stack items.
    #[display("OP_SWAP")]
    Swap = OP_SWAP,
    /// Copy the top stack item to before the second item, as [top next] -> [top
    /// next top].
    #[display("OP_TUCK")]
    Tuck = OP_TUCK,

    /// One of `OP_SUCCESSx` op-codes.
    #[display("OP_SUCCESS126")]
    Success126 = OP_CAT,
    /// One of `OP_SUCCESSx` op-codes.
    #[display("OP_SUCCESS127")]
    Success127 = OP_SUBSTR,
    /// One of `OP_SUCCESSx` op-codes.
    #[display("OP_SUCCESS128")]
    Success128 = OP_LEFT,
    /// One of `OP_SUCCESSx` op-codes.
    #[display("OP_SUCCESS129")]
    Success129 = OP_RIGHT,

    /// Pushes the length of the top stack item onto the stack.
    #[display("OP_SIZE")]
    Size = OP_SIZE,

    /// One of `OP_SUCCESSx` op-codes.
    #[display("OP_SUCCESS131")]
    Success131 = OP_INVERT,
    /// One of `OP_SUCCESSx` op-codes.
    #[display("OP_SUCCESS132")]
    Success132 = OP_AND,
    /// One of `OP_SUCCESSx` op-codes.
    #[display("OP_SUCCESS133")]
    Success133 = OP_OR,
    /// One of `OP_SUCCESSx` op-codes.
    #[display("OP_SUCCESS134")]
    Success134 = OP_XOR,

    /// Pushes 1 if the inputs are exactly equal, 0 otherwise.
    #[display("OP_EQUAL")]
    Equal = OP_EQUAL,
    /// Returns success if the inputs are exactly equal, failure otherwise.
    #[display("OP_EQUALVERIFY")]
    EqualVerify = OP_EQUALVERIFY,

    /// One of `OP_SUCCESSx` op-codes.
    #[display("OP_SUCCESS137")]
    Success137 = OP_RESERVED1,
    /// One of `OP_SUCCESSx` op-codes.
    #[display("OP_SUCCESS138")]
    Success138 = OP_RESERVED2,

    /// Increment the top stack element in place.
    #[display("OP_1ADD")]
    Add1 = OP_1ADD,
    /// Decrement the top stack element in place.
    #[display("OP_1SUB")]
    Sub1 = OP_1SUB,

    /// One of `OP_SUCCESSx` op-codes.
    #[display("OP_SUCCESS141")]
    Success141 = OP_2MUL,
    /// One of `OP_SUCCESSx` op-codes.
    #[display("OP_SUCCESS141")]
    Success142 = OP_2DIV,

    /// Multiply the top stack item by -1 in place.
    #[display("OP_NEGATE")]
    Negate = OP_NEGATE,
    /// Absolute value the top stack item in place.
    #[display("OP_ABS")]
    Abs = OP_ABS,
    /// Map 0 to 1 and everything else to 0, in place.
    #[display("OP_NOT")]
    Not = OP_NOT,
    /// Map 0 to 0 and everything else to 1, in place.
    #[display("OP_0NOTEQUAL")]
    NotEqual0 = OP_0NOTEQUAL,
    /// Pop two stack items and push their sum.
    #[display("OP_ADD")]
    Add = OP_ADD,
    /// Pop two stack items and push the second minus the top.
    #[display("OP_SUB")]
    Sub = OP_SUB,

    /// One of `OP_SUCCESSx` op-codes.
    #[display("OP_SUCCESS149")]
    Success149 = OP_MUL,
    /// One of `OP_SUCCESSx` op-codes.
    #[display("OP_SUCCESS150")]
    Success150 = OP_DIV,
    /// One of `OP_SUCCESSx` op-codes.
    #[display("OP_SUCCESS151")]
    Success151 = OP_MOD,
    /// One of `OP_SUCCESSx` op-codes.
    #[display("OP_SUCCESS152")]
    Success152 = OP_LSHIFT,
    /// One of `OP_SUCCESSx` op-codes.
    #[display("OP_SUCCESS153")]
    Success153 = OP_RSHIFT,

    /// Pop the top two stack items and push 1 if both are nonzero, else push 0.
    #[display("OP_BOOLAND")]
    BoolAnd = OP_BOOLAND,
    /// Pop the top two stack items and push 1 if either is nonzero, else push 0.
    #[display("OP_BOOLOR")]
    BoolOr = OP_BOOLOR,

    /// Pop the top two stack items and push 1 if both are numerically equal, else
    /// push 0.
    #[display("OP_NUMEQUAL")]
    NumEqual = OP_NUMEQUAL,
    /// Pop the top two stack items and return success if both are numerically
    /// equal, else return failure.
    #[display("OP_NUMEQUALVERIFY")]
    NumEqualVerify = OP_NUMEQUALVERIFY,
    /// Pop the top two stack items and push 0 if both are numerically equal, else
    /// push 1.
    #[display("OP_NUMNOTEQUAL")]
    NumNotEqual = OP_NUMNOTEQUAL,
    /// Pop the top two items; push 1 if the second is less than the top, 0
    /// otherwise.
    #[display("OP_LESSTHAN")]
    LessThan = OP_LESSTHAN,
    /// Pop the top two items; push 1 if the second is greater than the top, 0
    /// otherwise.
    #[display("OP_GREATERTHAN")]
    GreaterThan = OP_GREATERTHAN,
    /// Pop the top two items; push 1 if the second is <= the top, 0 otherwise.
    #[display("OP_LESSTHANOREQUAL")]
    LessThanOrEqual = OP_LESSTHANOREQUAL,
    /// Pop the top two items; push 1 if the second is >= the top, 0 otherwise.
    #[display("OP_GREATERTHANOREQUAL")]
    GreaterThanOrEqual = OP_GREATERTHANOREQUAL,
    /// Pop the top two items; push the smaller.
    #[display("OP_MIN")]
    Min = OP_MIN,
    /// Pop the top two items; push the larger.
    #[display("OP_MAX")]
    Max = OP_MAX,
    /// Pop the top three items; if the top is >= the second and < the third, push
    /// 1, otherwise push 0.
    #[display("OP_WITHIN")]
    Within = OP_WITHIN,

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

    /// Ignore this and everything preceding when deciding what to sign when
    /// signature-checking.
    #[display("OP_CODESEPARATOR")]
    CodeSeparator = OP_CODESEPARATOR,

    /// <https://en.bitcoin.it/wiki/OP_CHECKSIG> pushing 1/0 for success/failure.
    #[display("OP_CHECKSIG")]
    CheckSig = OP_CHECKSIG,
    /// <https://en.bitcoin.it/wiki/OP_CHECKSIG> returning success/failure.
    #[display("OP_CHECKSIGVERIFY")]
    CheckSigVerify = OP_CHECKSIGVERIFY,

    /// Does nothing.
    #[display("OP_NOP1")]
    Nop1 = OP_NOP1,
    /// <https://github.com/bitcoin/bips/blob/master/bip-0065.mediawiki>
    #[display("OP_CLTV")]
    Cltv = OP_CLTV,
    /// <https://github.com/bitcoin/bips/blob/master/bip-0112.mediawiki>
    #[display("OP_CSV")]
    Csv = OP_CSV,
    /// Does nothing.
    #[display("OP_NOP4")]
    Nop4 = OP_NOP4,
    /// Does nothing.
    #[display("OP_NOP5")]
    Nop5 = OP_NOP5,
    /// Does nothing.
    #[display("OP_NOP6")]
    Nop6 = OP_NOP6,
    /// Does nothing.
    #[display("OP_NOP7")]
    Nop7 = OP_NOP7,
    /// Does nothing.
    #[display("OP_NOP8")]
    Nop8 = OP_NOP8,
    /// Does nothing.
    #[display("OP_NOP9")]
    Nop9 = OP_NOP9,
    /// Does nothing.
    #[display("OP_NOP10")]
    Nop10 = OP_NOP10,
    /// OP_CHECKSIGADD post tapscript.
    #[display("OP_CHECKSIGADD")]
    CheckSigAdd = OP_CHECKSIGADD,

    // Every other opcode acts as OP_SUCCESSx
    /// Synonym for OP_RETURN.
    #[display("OP_INVALIDOPCODE")]
    InvalidOpCode = OP_INVALIDOPCODE,
}
