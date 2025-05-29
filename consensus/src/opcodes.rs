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

use crate::LIB_NAME_BITCOIN;

/// Push an empty array onto the stack.
///
/// Also, a synonym for `OP_0` and `OP_FALSE`.
pub const OP_PUSHBYTES_0: u8 = 0x00;
/// Push the next byte as an array onto the stack.
pub const OP_PUSHBYTES_1: u8 = 0x01;
/// Push the next 2 bytes as an array onto the stack.
pub const OP_PUSHBYTES_2: u8 = 0x02;
/// Push the next 3 bytes as an array onto the stack.
pub const OP_PUSHBYTES_3: u8 = 0x03;
/// Push the next 4 bytes as an array onto the stack.
pub const OP_PUSHBYTES_4: u8 = 0x04;
/// Push the next 5 bytes as an array onto the stack.
pub const OP_PUSHBYTES_5: u8 = 0x05;
/// Push the next 6 bytes as an array onto the stack.
pub const OP_PUSHBYTES_6: u8 = 0x06;
/// Push the next 7 bytes as an array onto the stack.
pub const OP_PUSHBYTES_7: u8 = 0x07;
/// Push the next 8 bytes as an array onto the stack.
pub const OP_PUSHBYTES_8: u8 = 0x08;
/// Push the next 9 bytes as an array onto the stack.
pub const OP_PUSHBYTES_9: u8 = 0x09;
/// Push the next 10 bytes as an array onto the stack.
pub const OP_PUSHBYTES_10: u8 = 0x0a;
/// Push the next 11 bytes as an array onto the stack.
pub const OP_PUSHBYTES_11: u8 = 0x0b;
/// Push the next 12 bytes as an array onto the stack.
pub const OP_PUSHBYTES_12: u8 = 0x0c;
/// Push the next 13 bytes as an array onto the stack.
pub const OP_PUSHBYTES_13: u8 = 0x0d;
/// Push the next 14 bytes as an array onto the stack.
pub const OP_PUSHBYTES_14: u8 = 0x0e;
/// Push the next 15 bytes as an array onto the stack.
pub const OP_PUSHBYTES_15: u8 = 0x0f;
/// Push the next 16 bytes as an array onto the stack.
pub const OP_PUSHBYTES_16: u8 = 0x10;
/// Push the next 17 bytes as an array onto the stack.
pub const OP_PUSHBYTES_17: u8 = 0x11;
/// Push the next 18 bytes as an array onto the stack.
pub const OP_PUSHBYTES_18: u8 = 0x12;
/// Push the next 19 bytes as an array onto the stack.
pub const OP_PUSHBYTES_19: u8 = 0x13;
/// Push the next 20 bytes as an array onto the stack.
pub const OP_PUSHBYTES_20: u8 = 0x14;
/// Push the next 21 bytes as an array onto the stack.
pub const OP_PUSHBYTES_21: u8 = 0x15;
/// Push the next 22 bytes as an array onto the stack.
pub const OP_PUSHBYTES_22: u8 = 0x16;
/// Push the next 23 bytes as an array onto the stack.
pub const OP_PUSHBYTES_23: u8 = 0x17;
/// Push the next 24 bytes as an array onto the stack.
pub const OP_PUSHBYTES_24: u8 = 0x18;
/// Push the next 25 bytes as an array onto the stack.
pub const OP_PUSHBYTES_25: u8 = 0x19;
/// Push the next 26 bytes as an array onto the stack.
pub const OP_PUSHBYTES_26: u8 = 0x1a;
/// Push the next 27 bytes as an array onto the stack.
pub const OP_PUSHBYTES_27: u8 = 0x1b;
/// Push the next 28 bytes as an array onto the stack.
pub const OP_PUSHBYTES_28: u8 = 0x1c;
/// Push the next 29 bytes as an array onto the stack.
pub const OP_PUSHBYTES_29: u8 = 0x1d;
/// Push the next 30 bytes as an array onto the stack.
pub const OP_PUSHBYTES_30: u8 = 0x1e;
/// Push the next 31 bytes as an array onto the stack.
pub const OP_PUSHBYTES_31: u8 = 0x1f;
/// Push the next 32 bytes as an array onto the stack.
pub const OP_PUSHBYTES_32: u8 = 0x20;
/// Push the next 33 bytes as an array onto the stack.
pub const OP_PUSHBYTES_33: u8 = 0x21;
/// Push the next 34 bytes as an array onto the stack.
pub const OP_PUSHBYTES_34: u8 = 0x22;
/// Push the next 35 bytes as an array onto the stack.
pub const OP_PUSHBYTES_35: u8 = 0x23;
/// Push the next 36 bytes as an array onto the stack.
pub const OP_PUSHBYTES_36: u8 = 0x24;
/// Push the next 37 bytes as an array onto the stack.
pub const OP_PUSHBYTES_37: u8 = 0x25;
/// Push the next 38 bytes as an array onto the stack.
pub const OP_PUSHBYTES_38: u8 = 0x26;
/// Push the next 39 bytes as an array onto the stack.
pub const OP_PUSHBYTES_39: u8 = 0x27;
/// Push the next 40 bytes as an array onto the stack.
pub const OP_PUSHBYTES_40: u8 = 0x28;
/// Push the next 41 bytes as an array onto the stack.
pub const OP_PUSHBYTES_41: u8 = 0x29;
/// Push the next 42 bytes as an array onto the stack.
pub const OP_PUSHBYTES_42: u8 = 0x2a;
/// Push the next 43 bytes as an array onto the stack.
pub const OP_PUSHBYTES_43: u8 = 0x2b;
/// Push the next 44 bytes as an array onto the stack.
pub const OP_PUSHBYTES_44: u8 = 0x2c;
/// Push the next 45 bytes as an array onto the stack.
pub const OP_PUSHBYTES_45: u8 = 0x2d;
/// Push the next 46 bytes as an array onto the stack.
pub const OP_PUSHBYTES_46: u8 = 0x2e;
/// Push the next 47 bytes as an array onto the stack.
pub const OP_PUSHBYTES_47: u8 = 0x2f;
/// Push the next 48 bytes as an array onto the stack.
pub const OP_PUSHBYTES_48: u8 = 0x30;
/// Push the next 49 bytes as an array onto the stack.
pub const OP_PUSHBYTES_49: u8 = 0x31;
/// Push the next 50 bytes as an array onto the stack.
pub const OP_PUSHBYTES_50: u8 = 0x32;
/// Push the next 51 bytes as an array onto the stack.
pub const OP_PUSHBYTES_51: u8 = 0x33;
/// Push the next 52 bytes as an array onto the stack.
pub const OP_PUSHBYTES_52: u8 = 0x34;
/// Push the next 53 bytes as an array onto the stack.
pub const OP_PUSHBYTES_53: u8 = 0x35;
/// Push the next 54 bytes as an array onto the stack.
pub const OP_PUSHBYTES_54: u8 = 0x36;
/// Push the next 55 bytes as an array onto the stack.
pub const OP_PUSHBYTES_55: u8 = 0x37;
/// Push the next 56 bytes as an array onto the stack.
pub const OP_PUSHBYTES_56: u8 = 0x38;
/// Push the next 57 bytes as an array onto the stack.
pub const OP_PUSHBYTES_57: u8 = 0x39;
/// Push the next 58 bytes as an array onto the stack.
pub const OP_PUSHBYTES_58: u8 = 0x3a;
/// Push the next 59 bytes as an array onto the stack.
pub const OP_PUSHBYTES_59: u8 = 0x3b;
/// Push the next 60 bytes as an array onto the stack.
pub const OP_PUSHBYTES_60: u8 = 0x3c;
/// Push the next 61 bytes as an array onto the stack.
pub const OP_PUSHBYTES_61: u8 = 0x3d;
/// Push the next 62 bytes as an array onto the stack.
pub const OP_PUSHBYTES_62: u8 = 0x3e;
/// Push the next 63 bytes as an array onto the stack.
pub const OP_PUSHBYTES_63: u8 = 0x3f;
/// Push the next 64 bytes as an array onto the stack.
pub const OP_PUSHBYTES_64: u8 = 0x40;
/// Push the next 65 bytes as an array onto the stack.
pub const OP_PUSHBYTES_65: u8 = 0x41;
/// Push the next 66 bytes as an array onto the stack.
pub const OP_PUSHBYTES_66: u8 = 0x42;
/// Push the next 67 bytes as an array onto the stack.
pub const OP_PUSHBYTES_67: u8 = 0x43;
/// Push the next 68 bytes as an array onto the stack.
pub const OP_PUSHBYTES_68: u8 = 0x44;
/// Push the next 69 bytes as an array onto the stack.
pub const OP_PUSHBYTES_69: u8 = 0x45;
/// Push the next 70 bytes as an array onto the stack.
pub const OP_PUSHBYTES_70: u8 = 0x46;
/// Push the next 71 bytes as an array onto the stack.
pub const OP_PUSHBYTES_71: u8 = 0x47;
/// Push the next 72 bytes as an array onto the stack.
pub const OP_PUSHBYTES_72: u8 = 0x48;
/// Push the next 73 bytes as an array onto the stack.
pub const OP_PUSHBYTES_73: u8 = 0x49;
/// Push the next 74 bytes as an array onto the stack.
pub const OP_PUSHBYTES_74: u8 = 0x4a;
/// Push the next 75 bytes as an array onto the stack.
pub const OP_PUSHBYTES_75: u8 = 0x4b;
/// Read the next byte as N; push the next N bytes as an array onto the stack.
pub const OP_PUSHDATA1: u8 = 0x4c;
/// Read the next 2 bytes as N; push the next N bytes as an array onto the
/// stack.
pub const OP_PUSHDATA2: u8 = 0x4d;
/// Read the next 4 bytes as N; push the next N bytes as an array onto the
/// stack.
pub const OP_PUSHDATA4: u8 = 0x4e;
/// Push the array `0x81` onto the stack.
pub const OP_PUSHNUM_NEG1: u8 = 0x4f;
/// Synonym for OP_RETURN.
pub const OP_RESERVED: u8 = 0x50;
/// Push the array `0x01` onto the stack.
///
/// Also, a synonym for `OP_1` and `OP_TRUE`.
pub const OP_PUSHNUM_1: u8 = 0x51;
/// the array `0x02` onto the stack.
pub const OP_PUSHNUM_2: u8 = 0x52;
/// Push the array `0x03` onto the stack.
pub const OP_PUSHNUM_3: u8 = 0x53;
/// Push the array `0x04` onto the stack.
pub const OP_PUSHNUM_4: u8 = 0x54;
/// Push the array `0x05` onto the stack.
pub const OP_PUSHNUM_5: u8 = 0x55;
/// Push the array `0x06` onto the stack.
pub const OP_PUSHNUM_6: u8 = 0x56;
/// Push the array `0x07` onto the stack.
pub const OP_PUSHNUM_7: u8 = 0x57;
/// Push the array `0x08` onto the stack.
pub const OP_PUSHNUM_8: u8 = 0x58;
/// Push the array `0x09` onto the stack.
pub const OP_PUSHNUM_9: u8 = 0x59;
/// Push the array `0x0a` onto the stack.
pub const OP_PUSHNUM_10: u8 = 0x5a;
/// Push the array `0x0b` onto the stack.
pub const OP_PUSHNUM_11: u8 = 0x5b;
/// Push the array `0x0c` onto the stack.
pub const OP_PUSHNUM_12: u8 = 0x5c;
/// Push the array `0x0d` onto the stack.
pub const OP_PUSHNUM_13: u8 = 0x5d;
/// Push the array `0x0e` onto the stack.
pub const OP_PUSHNUM_14: u8 = 0x5e;
/// Push the array `0x0f` onto the stack.
pub const OP_PUSHNUM_15: u8 = 0x5f;
/// Push the array `0x10` onto the stack.
pub const OP_PUSHNUM_16: u8 = 0x60;
/// Does nothing.
pub const OP_NOP: u8 = 0x61;
/// Synonym for OP_RETURN.
pub const OP_VER: u8 = 0x62;
/// Pop and execute the next statements if a nonzero element was popped.
pub const OP_IF: u8 = 0x63;
/// Pop and execute the next statements if a zero element was popped.
pub const OP_NOTIF: u8 = 0x64;
/// Fail the script unconditionally, does not even need to be executed.
pub const OP_VERIF: u8 = 0x65;
/// Fail the script unconditionally, does not even need to be executed.
pub const OP_VERNOTIF: u8 = 0x66;
/// Execute statements if those after the previous OP_IF were not, and
/// vice-versa. If there is no previous OP_IF, this acts as an OP_RETURN.
pub const OP_ELSE: u8 = 0x67;
/// Pop and execute the next statements if a zero element was popped.
pub const OP_ENDIF: u8 = 0x68;
/// If the top value is zero or the stack is empty, fail; otherwise, pop the
/// stack.
pub const OP_VERIFY: u8 = 0x69;
/// Fail the script immediately. (Must be executed.).
pub const OP_RETURN: u8 = 0x6a;
/// Pop one element from the main stack onto the alt stack.
pub const OP_TOALTSTACK: u8 = 0x6b;
/// Pop one element from the alt stack onto the main stack.
pub const OP_FROMALTSTACK: u8 = 0x6c;
/// Drops the top two stack items.
pub const OP_2DROP: u8 = 0x6d;
/// Duplicates the top two stack items as AB -> ABAB.
pub const OP_2DUP: u8 = 0x6e;
/// Duplicates the two three stack items as ABC -> ABCABC.
pub const OP_3DUP: u8 = 0x6f;
/// Copies the two stack items of items two spaces back to the front, as xxAB ->
/// ABxxAB.
pub const OP_2OVER: u8 = 0x70;
/// Moves the two stack items four spaces back to the front, as xxxxAB ->
/// ABxxxx.
pub const OP_2ROT: u8 = 0x71;
/// Swaps the top two pairs, as ABCD -> CDAB.
pub const OP_2SWAP: u8 = 0x72;
/// Duplicate the top stack element unless it is zero.
pub const OP_IFDUP: u8 = 0x73;
/// Push the current number of stack items onto the stack.
pub const OP_DEPTH: u8 = 0x74;
/// Drops the top stack item.
pub const OP_DROP: u8 = 0x75;
/// Duplicates the top stack item.
pub const OP_DUP: u8 = 0x76;
/// Drops the second-to-top stack item.
pub const OP_NIP: u8 = 0x77;
/// Copies the second-to-top stack item, as xA -> AxA.
pub const OP_OVER: u8 = 0x78;
/// Pop the top stack element as N. Copy the Nth stack element to the top.
pub const OP_PICK: u8 = 0x79;
/// Pop the top stack element as N. Move the Nth stack element to the top.
pub const OP_ROLL: u8 = 0x7a;
/// Rotate the top three stack items, as [top next1 next2] -> [next2 top next1].
pub const OP_ROT: u8 = 0x7b;
/// Swap the top two stack items.
pub const OP_SWAP: u8 = 0x7c;
/// Copy the top stack item to before the second item, as [top next] -> [top
/// next top].
pub const OP_TUCK: u8 = 0x7d;

/// Fail the script unconditionally, does not even need to be executed.
pub const OP_CAT: u8 = 0x7e;
/// Fail the script unconditionally, does not even need to be executed.
pub const OP_SUBSTR: u8 = 0x7f;
/// Fail the script unconditionally, does not even need to be executed.
pub const OP_LEFT: u8 = 0x80;
/// Fail the script unconditionally, does not even need to be executed.
pub const OP_RIGHT: u8 = 0x81;

/// Pushes the length of the top stack item onto the stack.
pub const OP_SIZE: u8 = 0x82;
/// Fail the script unconditionally, does not even need to be executed.
pub const OP_INVERT: u8 = 0x83;
/// Fail the script unconditionally, does not even need to be executed.
pub const OP_AND: u8 = 0x84;
/// Fail the script unconditionally, does not even need to be executed.
pub const OP_OR: u8 = 0x85;
/// Fail the script unconditionally, does not even need to be executed.
pub const OP_XOR: u8 = 0x86;
/// Pushes 1 if the inputs are exactly equal, 0 otherwise.
pub const OP_EQUAL: u8 = 0x87;
/// Returns success if the inputs are exactly equal, failure otherwise.
pub const OP_EQUALVERIFY: u8 = 0x88;
/// Synonym for OP_RETURN.
pub const OP_RESERVED1: u8 = 0x89;
/// Synonym for OP_RETURN.
pub const OP_RESERVED2: u8 = 0x8a;
/// Increment the top stack element in place.
pub const OP_1ADD: u8 = 0x8b;
/// Decrement the top stack element in place.
pub const OP_1SUB: u8 = 0x8c;
/// Fail the script unconditionally, does not even need to be executed.
pub const OP_2MUL: u8 = 0x8d;
/// Fail the script unconditionally, does not even need to be executed.
pub const OP_2DIV: u8 = 0x8e;
/// Multiply the top stack item by -1 in place.
pub const OP_NEGATE: u8 = 0x8f;
/// Absolute value the top stack item in place.
pub const OP_ABS: u8 = 0x90;
/// Map 0 to 1 and everything else to 0, in place.
pub const OP_NOT: u8 = 0x91;
/// Map 0 to 0 and everything else to 1, in place.
pub const OP_0NOTEQUAL: u8 = 0x92;
/// Pop two stack items and push their sum.
pub const OP_ADD: u8 = 0x93;
/// Pop two stack items and push the second minus the top.
pub const OP_SUB: u8 = 0x94;
/// Fail the script unconditionally, does not even need to be executed.
pub const OP_MUL: u8 = 0x95;
/// Fail the script unconditionally, does not even need to be executed.
pub const OP_DIV: u8 = 0x96;
/// Fail the script unconditionally, does not even need to be executed.
pub const OP_MOD: u8 = 0x97;
/// Fail the script unconditionally, does not even need to be executed.
pub const OP_LSHIFT: u8 = 0x98;
/// Fail the script unconditionally, does not even need to be executed.
pub const OP_RSHIFT: u8 = 0x99;
/// Pop the top two stack items and push 1 if both are nonzero, else push 0.
pub const OP_BOOLAND: u8 = 0x9a;
/// Pop the top two stack items and push 1 if either is nonzero, else push 0.
pub const OP_BOOLOR: u8 = 0x9b;
/// Pop the top two stack items and push 1 if both are numerically equal, else
/// push 0.
pub const OP_NUMEQUAL: u8 = 0x9c;
/// Pop the top two stack items and return success if both are numerically
/// equal, else return failure.
pub const OP_NUMEQUALVERIFY: u8 = 0x9d;
/// Pop the top two stack items and push 0 if both are numerically equal, else
/// push 1.
pub const OP_NUMNOTEQUAL: u8 = 0x9e;
/// Pop the top two items; push 1 if the second is less than the top, 0
/// otherwise.
pub const OP_LESSTHAN: u8 = 0x9f;
/// Pop the top two items; push 1 if the second is greater than the top, 0
/// otherwise.
pub const OP_GREATERTHAN: u8 = 0xa0;
/// Pop the top two items; push 1 if the second is <= the top, 0 otherwise.
pub const OP_LESSTHANOREQUAL: u8 = 0xa1;
/// Pop the top two items; push 1 if the second is >= the top, 0 otherwise.
pub const OP_GREATERTHANOREQUAL: u8 = 0xa2;
/// Pop the top two items; push the smaller.
pub const OP_MIN: u8 = 0xa3;
/// Pop the top two items; push the larger.
pub const OP_MAX: u8 = 0xa4;
/// Pop the top three items; if the top is >= the second and < the third, push
/// 1, otherwise push 0.
pub const OP_WITHIN: u8 = 0xa5;
/// Pop the top stack item and push its RIPEMD160 hash.
pub const OP_RIPEMD160: u8 = 0xa6;
/// Pop the top stack item and push its SHA1 hash.
pub const OP_SHA1: u8 = 0xa7;
/// Pop the top stack item and push its SHA256 hash.
pub const OP_SHA256: u8 = 0xa8;
/// Pop the top stack item and push its RIPEMD(SHA256) hash.
pub const OP_HASH160: u8 = 0xa9;
/// Pop the top stack item and push its SHA256(SHA256) hash.
pub const OP_HASH256: u8 = 0xaa;
/// Ignore this and everything preceding when deciding what to sign when
/// signature-checking.
pub const OP_CODESEPARATOR: u8 = 0xab;
/// <https://en.bitcoin.it/wiki/OP_CHECKSIG> pushing 1/0 for success/failure.
pub const OP_CHECKSIG: u8 = 0xac;
/// <https://en.bitcoin.it/wiki/OP_CHECKSIG> returning success/failure.
pub const OP_CHECKSIGVERIFY: u8 = 0xad;
/// Pop N, N pubkeys, M, M signatures, a dummy (due to bug in reference code),
/// and verify that all M signatures are valid. Push 1 for 'all valid', 0
/// otherwise.
pub const OP_CHECKMULTISIG: u8 = 0xae;
/// Like the above but return success/failure.
pub const OP_CHECKMULTISIGVERIFY: u8 = 0xaf;
/// Does nothing.
pub const OP_NOP1: u8 = 0xb0;
/// <https://github.com/bitcoin/bips/blob/master/bip-0065.mediawiki>
pub const OP_CLTV: u8 = 0xb1;
/// <https://github.com/bitcoin/bips/blob/master/bip-0112.mediawiki>
pub const OP_CSV: u8 = 0xb2;
/// Does nothing.
pub const OP_NOP4: u8 = 0xb3;
/// Does nothing.
pub const OP_NOP5: u8 = 0xb4;
/// Does nothing.
pub const OP_NOP6: u8 = 0xb5;
/// Does nothing.
pub const OP_NOP7: u8 = 0xb6;
/// Does nothing.
pub const OP_NOP8: u8 = 0xb7;
/// Does nothing.
pub const OP_NOP9: u8 = 0xb8;
/// Does nothing.
pub const OP_NOP10: u8 = 0xb9;
// Every other opcode acts as OP_RETURN
/// OP_CHECKSIGADD post tapscript.
pub const OP_CHECKSIGADD: u8 = 0xba;
/// Synonym for OP_RETURN.
pub const OP_RETURN_187: u8 = 0xbb;
/// Synonym for OP_RETURN.
pub const OP_RETURN_188: u8 = 0xbc;
/// Synonym for OP_RETURN.
pub const OP_RETURN_189: u8 = 0xbd;
/// Synonym for OP_RETURN.
pub const OP_RETURN_190: u8 = 0xbe;
/// Synonym for OP_RETURN.
pub const OP_RETURN_191: u8 = 0xbf;
/// Synonym for OP_RETURN.
pub const OP_RETURN_192: u8 = 0xc0;
/// Synonym for OP_RETURN.
pub const OP_RETURN_193: u8 = 0xc1;
/// Synonym for OP_RETURN.
pub const OP_RETURN_194: u8 = 0xc2;
/// Synonym for OP_RETURN.
pub const OP_RETURN_195: u8 = 0xc3;
/// Synonym for OP_RETURN.
pub const OP_RETURN_196: u8 = 0xc4;
/// Synonym for OP_RETURN.
pub const OP_RETURN_197: u8 = 0xc5;
/// Synonym for OP_RETURN.
pub const OP_RETURN_198: u8 = 0xc6;
/// Synonym for OP_RETURN.
pub const OP_RETURN_199: u8 = 0xc7;
/// Synonym for OP_RETURN.
pub const OP_RETURN_200: u8 = 0xc8;
/// Synonym for OP_RETURN.
pub const OP_RETURN_201: u8 = 0xc9;
/// Synonym for OP_RETURN.
pub const OP_RETURN_202: u8 = 0xca;
/// Synonym for OP_RETURN.
pub const OP_RETURN_203: u8 = 0xcb;
/// Synonym for OP_RETURN.
pub const OP_RETURN_204: u8 = 0xcc;
/// Synonym for OP_RETURN.
pub const OP_RETURN_205: u8 = 0xcd;
/// Synonym for OP_RETURN.
pub const OP_RETURN_206: u8 = 0xce;
/// Synonym for OP_RETURN.
pub const OP_RETURN_207: u8 = 0xcf;
/// Synonym for OP_RETURN.
pub const OP_RETURN_208: u8 = 0xd0;
/// Synonym for OP_RETURN.
pub const OP_RETURN_209: u8 = 0xd1;
/// Synonym for OP_RETURN.
pub const OP_RETURN_210: u8 = 0xd2;
/// Synonym for OP_RETURN.
pub const OP_RETURN_211: u8 = 0xd3;
/// Synonym for OP_RETURN.
pub const OP_RETURN_212: u8 = 0xd4;
/// Synonym for OP_RETURN.
pub const OP_RETURN_213: u8 = 0xd5;
/// Synonym for OP_RETURN.
pub const OP_RETURN_214: u8 = 0xd6;
/// Synonym for OP_RETURN.
pub const OP_RETURN_215: u8 = 0xd7;
/// Synonym for OP_RETURN.
pub const OP_RETURN_216: u8 = 0xd8;
/// Synonym for OP_RETURN.
pub const OP_RETURN_217: u8 = 0xd9;
/// Synonym for OP_RETURN.
pub const OP_RETURN_218: u8 = 0xda;
/// Synonym for OP_RETURN.
pub const OP_RETURN_219: u8 = 0xdb;
/// Synonym for OP_RETURN.
pub const OP_RETURN_220: u8 = 0xdc;
/// Synonym for OP_RETURN.
pub const OP_RETURN_221: u8 = 0xdd;
/// Synonym for OP_RETURN.
pub const OP_RETURN_222: u8 = 0xde;
/// Synonym for OP_RETURN.
pub const OP_RETURN_223: u8 = 0xdf;
/// Synonym for OP_RETURN.
pub const OP_RETURN_224: u8 = 0xe0;
/// Synonym for OP_RETURN.
pub const OP_RETURN_225: u8 = 0xe1;
/// Synonym for OP_RETURN.
pub const OP_RETURN_226: u8 = 0xe2;
/// Synonym for OP_RETURN.
pub const OP_RETURN_227: u8 = 0xe3;
/// Synonym for OP_RETURN.
pub const OP_RETURN_228: u8 = 0xe4;
/// Synonym for OP_RETURN.
pub const OP_RETURN_229: u8 = 0xe5;
/// Synonym for OP_RETURN.
pub const OP_RETURN_230: u8 = 0xe6;
/// Synonym for OP_RETURN.
pub const OP_RETURN_231: u8 = 0xe7;
/// Synonym for OP_RETURN.
pub const OP_RETURN_232: u8 = 0xe8;
/// Synonym for OP_RETURN.
pub const OP_RETURN_233: u8 = 0xe9;
/// Synonym for OP_RETURN.
pub const OP_RETURN_234: u8 = 0xea;
/// Synonym for OP_RETURN.
pub const OP_RETURN_235: u8 = 0xeb;
/// Synonym for OP_RETURN.
pub const OP_RETURN_236: u8 = 0xec;
/// Synonym for OP_RETURN.
pub const OP_RETURN_237: u8 = 0xed;
/// Synonym for OP_RETURN.
pub const OP_RETURN_238: u8 = 0xee;
/// Synonym for OP_RETURN.
pub const OP_RETURN_239: u8 = 0xef;
/// Synonym for OP_RETURN.
pub const OP_RETURN_240: u8 = 0xf0;
/// Synonym for OP_RETURN.
pub const OP_RETURN_241: u8 = 0xf1;
/// Synonym for OP_RETURN.
pub const OP_RETURN_242: u8 = 0xf2;
/// Synonym for OP_RETURN.
pub const OP_RETURN_243: u8 = 0xf3;
/// Synonym for OP_RETURN.
pub const OP_RETURN_244: u8 = 0xf4;
/// Synonym for OP_RETURN.
pub const OP_RETURN_245: u8 = 0xf5;
/// Synonym for OP_RETURN.
pub const OP_RETURN_246: u8 = 0xf6;
/// Synonym for OP_RETURN.
pub const OP_RETURN_247: u8 = 0xf7;
/// Synonym for OP_RETURN.
pub const OP_RETURN_248: u8 = 0xf8;
/// Synonym for OP_RETURN.
pub const OP_RETURN_249: u8 = 0xf9;
/// Synonym for OP_RETURN.
pub const OP_RETURN_250: u8 = 0xfa;
/// Synonym for OP_RETURN.
pub const OP_RETURN_251: u8 = 0xfb;
/// Synonym for OP_RETURN.
pub const OP_RETURN_252: u8 = 0xfc;
/// Synonym for OP_RETURN.
pub const OP_RETURN_253: u8 = 0xfd;
/// Synonym for OP_RETURN.
pub const OP_RETURN_254: u8 = 0xfe;
/// Synonym for OP_RETURN.
pub const OP_INVALIDOPCODE: u8 = 0xff;

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Display)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BITCOIN, tags = repr, into_u8, try_from_u8)]
#[non_exhaustive]
#[repr(u8)]
pub enum OpCode {
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

    /// Synonym for OP_RETURN.
    #[display("OP_RESERVED")]
    Reserved = OP_RESERVED,

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

    /// Synonym for OP_RETURN.
    #[display("OP_VER")]
    Ver = OP_VER,

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
    /// Fail the script unconditionally, does not even need to be executed.
    #[display("OP_CAT")]
    Cat = OP_CAT,
    /// Fail the script unconditionally, does not even need to be executed.
    #[display("OP_SUBSTR")]
    SubStr = OP_SUBSTR,
    /// Fail the script unconditionally, does not even need to be executed.
    #[display("OP_LEFT")]
    Left = OP_LEFT,
    /// Fail the script unconditionally, does not even need to be executed.
    #[display("OP_RIGHT")]
    Right = OP_RIGHT,
    /// Pushes the length of the top stack item onto the stack.
    #[display("OP_SIZE")]
    Size = OP_SIZE,
    /// Fail the script unconditionally, does not even need to be executed.
    #[display("OP_INVERT")]
    Invert = OP_INVERT,
    /// Fail the script unconditionally, does not even need to be executed.
    #[display("OP_AND")]
    And = OP_AND,
    /// Fail the script unconditionally, does not even need to be executed.
    #[display("OP_OR")]
    Or = OP_OR,
    /// Fail the script unconditionally, does not even need to be executed.
    #[display("OP_XOR")]
    Xor = OP_XOR,

    /// Pushes 1 if the inputs are exactly equal, 0 otherwise.
    #[display("OP_EQUAL")]
    Equal = OP_EQUAL,
    /// Returns success if the inputs are exactly equal, failure otherwise.
    #[display("OP_EQUALVERIFY")]
    EqualVerify = OP_EQUALVERIFY,

    /// Synonym for OP_RETURN.
    #[display("OP_RESERVED1")]
    Reserved1 = OP_RESERVED1,
    /// Synonym for OP_RETURN.
    #[display("OP_RESERVED2")]
    Reserved2 = OP_RESERVED2,

    /// Increment the top stack element in place.
    #[display("OP_1ADD")]
    Add1 = OP_1ADD,
    /// Decrement the top stack element in place.
    #[display("OP_1SUB")]
    Sub1 = OP_1SUB,
    /// Fail the script unconditionally, does not even need to be executed.
    #[display("OP_2MUL")]
    Mul2 = OP_2MUL,
    /// Fail the script unconditionally, does not even need to be executed.
    #[display("OP_2DIV")]
    Div2 = OP_2DIV,
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
    /// Fail the script unconditionally, does not even need to be executed.
    #[display("OP_MUL")]
    Mul = OP_MUL,
    /// Fail the script unconditionally, does not even need to be executed.
    #[display("OP_DIV")]
    Div = OP_DIV,
    /// Fail the script unconditionally, does not even need to be executed.
    #[display("OP_MOD")]
    Mod = OP_MOD,
    /// Fail the script unconditionally, does not even need to be executed.
    #[display("OP_LSHIFT")]
    LShift = OP_LSHIFT,
    /// Fail the script unconditionally, does not even need to be executed.
    #[display("OP_RSHIFT")]
    RShift = OP_RSHIFT,
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
    /// Pop N, N pubkeys, M, M signatures, a dummy (due to bug in reference code),
    /// and verify that all M signatures are valid. Push 1 for 'all valid', 0
    /// otherwise.
    #[display("OP_CHECKMULTISIG")]
    CheckMultiSig = OP_CHECKMULTISIG,
    /// Like the above but return success/failure.
    #[display("OP_CHECKMULTISIGVERIFY")]
    CheckMultisigVerify = OP_CHECKMULTISIGVERIFY,

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

    // Every other opcode acts as OP_RETURN
    /// Synonym for OP_RETURN.
    #[display("OP_INVALIDOPCODE")]
    InvalidOpCode = OP_INVALIDOPCODE,
}
