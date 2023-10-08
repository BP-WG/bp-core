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

use std::vec;

use amplify::confinement::Confined;
use amplify::{Bytes32StrRev, Wrapper};

use crate::opcodes::*;
use crate::{
    OpCode, RedeemScript, ScriptBytes, ScriptPubkey, VarIntArray, WScriptHash, LIB_NAME_BITCOIN,
};

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Display, Error)]
#[display(doc_comments)]
pub enum SegwitError {
    /// Script version must be 0 to 16 inclusive.
    InvalidWitnessVersion(u8),
    /// Bitcoin script opcode does not match any known witness version, the
    /// script is malformed.
    MalformedWitnessVersion,
    /// The witness program must be between 2 and 40 bytes in length.
    InvalidWitnessProgramLength(usize),
    /// A v0 witness program must be either of length 20 or 32.
    InvalidSegwitV0ProgramLength(usize),
    /// An uncompressed pubkey was used where it is not allowed.
    UncompressedPubkey,
}

/// Version of the witness program.
///
/// First byte of `scriptPubkey` in transaction output for transactions starting
/// with 0 and 0x51-0x60 (inclusive).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[derive(StrictType, StrictEncode, StrictDecode, StrictDumb)]
#[strict_type(lib = LIB_NAME_BITCOIN, tags = repr, into_u8, try_from_u8)]
#[repr(u8)]
pub enum WitnessVer {
    /// Initial version of witness program. Used for P2WPKH and P2WPK outputs
    #[strict_type(dumb)]
    #[display("segwit0")]
    V0 = OP_PUSHBYTES_0,

    /// Version of witness program used for Taproot P2TR outputs.
    #[display("segwit1")]
    V1 = OP_PUSHNUM_1,

    /// Future (unsupported) version of witness program.
    #[display("segwit2")]
    V2 = OP_PUSHNUM_2,

    /// Future (unsupported) version of witness program.
    #[display("segwit3")]
    V3 = OP_PUSHNUM_3,

    /// Future (unsupported) version of witness program.
    #[display("segwit4")]
    V4 = OP_PUSHNUM_4,

    /// Future (unsupported) version of witness program.
    #[display("segwit5")]
    V5 = OP_PUSHNUM_5,

    /// Future (unsupported) version of witness program.
    #[display("segwit6")]
    V6 = OP_PUSHNUM_6,

    /// Future (unsupported) version of witness program.
    #[display("segwit7")]
    V7 = OP_PUSHNUM_7,

    /// Future (unsupported) version of witness program.
    #[display("segwit8")]
    V8 = OP_PUSHNUM_8,

    /// Future (unsupported) version of witness program.
    #[display("segwit9")]
    V9 = OP_PUSHNUM_9,

    /// Future (unsupported) version of witness program.
    #[display("segwit10")]
    V10 = OP_PUSHNUM_10,

    /// Future (unsupported) version of witness program.
    #[display("segwit11")]
    V11 = OP_PUSHNUM_11,

    /// Future (unsupported) version of witness program.
    #[display("segwit12")]
    V12 = OP_PUSHNUM_12,

    /// Future (unsupported) version of witness program.
    #[display("segwit13")]
    V13 = OP_PUSHNUM_13,

    /// Future (unsupported) version of witness program.
    #[display("segwit14")]
    V14 = OP_PUSHNUM_14,

    /// Future (unsupported) version of witness program.
    #[display("segwit15")]
    V15 = OP_PUSHNUM_15,

    /// Future (unsupported) version of witness program.
    #[display("segwit16")]
    V16 = OP_PUSHNUM_16,
}

impl WitnessVer {
    /// Converts bitcoin script opcode into [`WitnessVer`] variant.
    ///
    /// # Errors
    /// If the opcode does not correspond to any witness version, errors with
    /// [`SegwitError::MalformedWitnessVersion`].
    pub fn from_op_code(op_code: OpCode) -> Result<Self, SegwitError> {
        match op_code as u8 {
            0 => Ok(WitnessVer::V0),
            OP_PUSHNUM_1 => Ok(WitnessVer::V1),
            OP_PUSHNUM_2 => Ok(WitnessVer::V2),
            OP_PUSHNUM_3 => Ok(WitnessVer::V3),
            OP_PUSHNUM_4 => Ok(WitnessVer::V4),
            OP_PUSHNUM_5 => Ok(WitnessVer::V5),
            OP_PUSHNUM_6 => Ok(WitnessVer::V6),
            OP_PUSHNUM_7 => Ok(WitnessVer::V7),
            OP_PUSHNUM_8 => Ok(WitnessVer::V8),
            OP_PUSHNUM_9 => Ok(WitnessVer::V9),
            OP_PUSHNUM_10 => Ok(WitnessVer::V10),
            OP_PUSHNUM_11 => Ok(WitnessVer::V11),
            OP_PUSHNUM_12 => Ok(WitnessVer::V12),
            OP_PUSHNUM_13 => Ok(WitnessVer::V13),
            OP_PUSHNUM_14 => Ok(WitnessVer::V14),
            OP_PUSHNUM_15 => Ok(WitnessVer::V15),
            OP_PUSHNUM_16 => Ok(WitnessVer::V16),
            _ => Err(SegwitError::MalformedWitnessVersion),
        }
    }

    /// Converts witness version ordinal number into [`WitnessVer`] variant.
    ///
    /// # Errors
    /// If the witness version number exceeds 16, errors with
    /// [`SegwitError::MalformedWitnessVersion`].
    pub fn from_version_no(no: u8) -> Result<Self, SegwitError> {
        Ok(match no {
            v if v == Self::V0.version_no() => Self::V0,
            v if v == Self::V1.version_no() => Self::V1,
            v if v == Self::V2.version_no() => Self::V2,
            v if v == Self::V3.version_no() => Self::V3,
            v if v == Self::V4.version_no() => Self::V4,
            v if v == Self::V5.version_no() => Self::V5,
            v if v == Self::V6.version_no() => Self::V6,
            v if v == Self::V7.version_no() => Self::V7,
            v if v == Self::V8.version_no() => Self::V8,
            v if v == Self::V9.version_no() => Self::V9,
            v if v == Self::V10.version_no() => Self::V10,
            v if v == Self::V11.version_no() => Self::V11,
            v if v == Self::V12.version_no() => Self::V12,
            v if v == Self::V13.version_no() => Self::V13,
            v if v == Self::V14.version_no() => Self::V14,
            v if v == Self::V15.version_no() => Self::V15,
            v if v == Self::V16.version_no() => Self::V16,
            _ => return Err(SegwitError::InvalidWitnessVersion(no)),
        })
    }

    /// Converts [`WitnessVer`] instance into corresponding Bitcoin op-code.
    // TODO: Replace `try_from` with `from` since opcodes cover whole range of
    //       u8
    pub fn op_code(self) -> OpCode {
        OpCode::try_from(self as u8).expect("full range of u8 is covered")
    }

    /// Converts [`WitnessVer`] into ordinal version number.
    pub fn version_no(self) -> u8 {
        match self {
            WitnessVer::V0 => 0,
            WitnessVer::V1 => 1,
            WitnessVer::V2 => 2,
            WitnessVer::V3 => 3,
            WitnessVer::V4 => 4,
            WitnessVer::V5 => 5,
            WitnessVer::V6 => 6,
            WitnessVer::V7 => 7,
            WitnessVer::V8 => 8,
            WitnessVer::V9 => 9,
            WitnessVer::V10 => 10,
            WitnessVer::V11 => 11,
            WitnessVer::V12 => 12,
            WitnessVer::V13 => 13,
            WitnessVer::V14 => 14,
            WitnessVer::V15 => 15,
            WitnessVer::V16 => 16,
        }
    }
}

/// Witness program as defined in BIP141.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[derive(StrictType, StrictEncode, StrictDecode, StrictDumb)]
#[strict_type(lib = LIB_NAME_BITCOIN, dumb = Self::dumb())]
pub struct WitnessProgram {
    /// The witness program version.
    version: WitnessVer,
    /// The witness program. (Between 2 and 40 bytes)
    program: Confined<Vec<u8>, 2, 40>,
}

impl WitnessProgram {
    fn dumb() -> Self { Self::new(strict_dumb!(), vec![0; 32]).unwrap() }

    /// Creates a new witness program.
    pub fn new(version: WitnessVer, program: Vec<u8>) -> Result<Self, SegwitError> {
        let len = program.len();
        let program = Confined::try_from(program)
            .map_err(|_| SegwitError::InvalidWitnessProgramLength(len))?;

        // Specific segwit v0 check. These addresses can never spend funds sent
        // to them.
        if version == WitnessVer::V0 && (program.len() != 20 && program.len() != 32) {
            return Err(SegwitError::InvalidSegwitV0ProgramLength(program.len()));
        }

        Ok(WitnessProgram { version, program })
    }

    /// Returns the witness program version.
    pub fn version(&self) -> WitnessVer { self.version }

    /// Returns the witness program.
    pub fn program(&self) -> &[u8] { &self.program }
}

impl ScriptPubkey {
    pub fn p2wpkh(hash: impl Into<[u8; 20]>) -> Self {
        Self::with_witness_program_unchecked(WitnessVer::V0, &hash.into())
    }

    pub fn p2wsh(hash: impl Into<[u8; 32]>) -> Self {
        Self::with_witness_program_unchecked(WitnessVer::V0, &hash.into())
    }

    pub fn is_p2wpkh(&self) -> bool {
        self.len() == 22 && self[0] == WitnessVer::V0.op_code() as u8 && self[1] == OP_PUSHBYTES_20
    }

    pub fn is_p2wsh(&self) -> bool {
        self.len() == 34 && self[0] == WitnessVer::V0.op_code() as u8 && self[1] == OP_PUSHBYTES_32
    }

    /// Generates P2WSH-type of scriptPubkey with a given [`WitnessProgram`].
    pub fn from_witness_program(witness_program: &WitnessProgram) -> Self {
        Self::with_witness_program_unchecked(witness_program.version, witness_program.program())
    }

    /// Generates P2WSH-type of scriptPubkey with a given [`WitnessVer`] and
    /// the program bytes. Does not do any checks on version or program length.
    pub(crate) fn with_witness_program_unchecked(ver: WitnessVer, prog: &[u8]) -> Self {
        let mut script = Self::with_capacity(ScriptBytes::len_for_slice(prog.len()) + 2);
        script.push_opcode(ver.op_code());
        script.push_slice(prog);
        script
    }

    /// Checks whether a script pubkey is a Segregated Witness (segwit) program.
    #[inline]
    pub fn is_witness_program(&self) -> bool {
        // A scriptPubKey (or redeemScript as defined in BIP16/P2SH) that consists of a
        // 1-byte push opcode (for 0 to 16) followed by a data push between 2
        // and 40 bytes gets a new special meaning. The value of the first push
        // is called the "version byte". The following byte vector pushed is
        // called the "witness program".
        let script_len = self.len();
        if !(4..=42).contains(&script_len) {
            return false;
        }
        // Version 0 or PUSHNUM_1-PUSHNUM_16
        let Ok(ver_opcode) = OpCode::try_from(self[0]) else {
            return false;
        };
        let push_opbyte = self[1]; // Second byte push opcode 2-40 bytes
        WitnessVer::from_op_code(ver_opcode).is_ok()
            && push_opbyte >= OP_PUSHBYTES_2
            && push_opbyte <= OP_PUSHBYTES_40
            // Check that the rest of the script has the correct size
            && script_len - 2 == push_opbyte as usize
    }
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
pub struct WitnessScript(
    #[from]
    #[from(Vec<u8>)]
    ScriptBytes,
);

impl WitnessScript {
    pub fn new() -> Self { Self::default() }

    pub fn with_capacity(capacity: usize) -> Self {
        Self(ScriptBytes::from(Confined::with_capacity(capacity)))
    }

    /// Adds a single opcode to the script.
    pub fn push_opcode(&mut self, op_code: OpCode) { self.0.push(op_code as u8); }

    pub fn to_redeem_script(&self) -> RedeemScript {
        let script = ScriptPubkey::p2wsh(WScriptHash::from(self));
        RedeemScript::from_inner(script.into_inner())
    }

    pub fn to_script_pubkey(&self) -> ScriptPubkey { ScriptPubkey::p2wsh(WScriptHash::from(self)) }

    pub fn as_script_bytes(&self) -> &ScriptBytes { &self.0 }
}

#[derive(Wrapper, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, From)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BITCOIN)]
#[derive(CommitEncode)]
#[commit_encode(strategy = strict)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
#[wrapper(BorrowSlice, Index, RangeOps, Debug, Hex, Display, FromStr)]
pub struct Wtxid(
    #[from]
    #[from([u8; 32])]
    Bytes32StrRev,
);

#[derive(Wrapper, Clone, Eq, PartialEq, Hash, Debug, From, Default)]
#[wrapper(Deref, Index, RangeOps)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BITCOIN)]
pub struct Witness(VarIntArray<VarIntArray<u8>>);

impl IntoIterator for Witness {
    type Item = VarIntArray<u8>;
    type IntoIter = vec::IntoIter<VarIntArray<u8>>;

    fn into_iter(self) -> Self::IntoIter { self.0.into_iter() }
}

impl Witness {
    pub fn new() -> Self { default!() }

    pub fn elements(&self) -> impl Iterator<Item = &'_ [u8]> {
        self.0.iter().map(|el| el.as_slice())
    }

    pub fn from_consensus_stack(witness: impl IntoIterator<Item = Vec<u8>>) -> Witness {
        let iter = witness.into_iter().map(|vec| {
            VarIntArray::try_from(vec).expect("witness stack element length exceeds 2^64 bytes")
        });
        let stack =
            VarIntArray::try_from_iter(iter).expect("witness stack size exceeds 2^64 bytes");
        Witness(stack)
    }

    pub(crate) fn as_var_int_array(&self) -> &VarIntArray<VarIntArray<u8>> { &self.0 }
}

#[cfg(feature = "serde")]
mod _serde {
    use serde::{Deserialize, Serialize};
    use serde_crate::ser::SerializeSeq;
    use serde_crate::{Deserializer, Serializer};

    use super::*;
    use crate::ScriptBytes;

    impl Serialize for Witness {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer {
            let mut ser = serializer.serialize_seq(Some(self.len()))?;
            for el in &self.0 {
                ser.serialize_element(&ScriptBytes::from(el.to_inner()))?;
            }
            ser.end()
        }
    }

    impl<'de> Deserialize<'de> for Witness {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: Deserializer<'de> {
            let data = Vec::<ScriptBytes>::deserialize(deserializer)?;
            Ok(Witness::from_consensus_stack(data.into_iter().map(ScriptBytes::into_vec)))
        }
    }
}
