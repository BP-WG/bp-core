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

use crate::opcodes::*;
use crate::{OpCode, ScriptBytes, ScriptPubkey};

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
#[repr(u8)]
pub enum WitnessVer {
    /// Initial version of witness program. Used for P2WPKH and P2WPK outputs
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
    /// # Returns
    /// Version of the Witness program.
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

    /// Converts [`WitnessVer`] instance into corresponding Bitcoin op-code.
    // TODO: Replace `try_from` with `from` since opcodes cover whole range of
    // u8
    pub fn op_code(self) -> OpCode {
        OpCode::try_from(self as u8).expect("full range of u8 is covered")
    }
}

/// Witness program as defined in BIP141.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WitnessProgram {
    /// The witness program version.
    version: WitnessVer,
    /// The witness program. (Between 2 and 40 bytes)
    program: Vec<u8>,
}

impl WitnessProgram {
    /// Creates a new witness program.
    pub fn new(version: WitnessVer, program: Vec<u8>) -> Result<Self, SegwitError> {
        if program.len() < 2 || program.len() > 40 {
            return Err(SegwitError::InvalidWitnessProgramLength(program.len()));
        }

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
    /// Generates P2WSH-type of scriptPubkey with a given [`WitnessProgram`].
    pub fn from_witness_program(witness_program: &WitnessProgram) -> Self {
        Self::with_segwit_unchecked(witness_program.version, witness_program.program())
    }

    /// Generates P2WSH-type of scriptPubkey with a given [`WitnessVer`] and
    /// the program bytes. Does not do any checks on version or program length.
    pub(crate) fn with_segwit_unchecked(ver: WitnessVer, prog: &[u8]) -> Self {
        let mut script = Self::with_capacity(ScriptBytes::len_for_slice(prog.len()) + 2);
        script.push_opcode(ver.op_code());
        script.push_slice(prog);
        script
    }
}
