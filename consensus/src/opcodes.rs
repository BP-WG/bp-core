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

/// Push an empty array onto the stack.
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
