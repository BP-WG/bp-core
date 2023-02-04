// BP Core Library implementing LNP/BP specifications & standards related to
// bitcoin protocol
//
// Written in 2020-2022 by
//     Dr. Maxim Orlovsky <orlovsky@pandoracore.com>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the Apache 2.0 License
// along with this software.
// If not, see <https://opensource.org/licenses/Apache-2.0>.

use amplify::confinement::Confined;

use crate::opcodes::*;
use crate::{ScriptBytes, LIB_NAME_BP};

#[derive(Copy, Clone, Eq, PartialEq, Debug, Display)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
// TODO: Replace `try_from` with `from` since opcodes cover whole range of u8
#[strict_type(lib = LIB_NAME_BP, tags = repr, into_u8, try_from_u8)]
#[repr(u8)]
pub enum OpCode {
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
}

#[derive(
    Wrapper, WrapperMut, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug,
    From, Default
)]
#[wrapper(Deref, Index, RangeOps, BorrowSlice, LowerHex, UpperHex)]
#[wrapper_mut(DerefMut, IndexMut, RangeMut, BorrowSliceMut)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BP)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct SigScript(ScriptBytes);

#[derive(
    Wrapper, WrapperMut, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug,
    From, Default
)]
#[wrapper(Deref, Index, RangeOps, BorrowSlice, LowerHex, UpperHex)]
#[wrapper_mut(DerefMut, IndexMut, RangeMut, BorrowSliceMut)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BP)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct ScriptPubkey(ScriptBytes);

impl ScriptPubkey {
    pub fn new() -> Self { Self::default() }

    pub fn with_capacity(capacity: usize) -> Self {
        Self(ScriptBytes::from(Confined::with_capacity(capacity)))
    }

    pub fn op_return(data: &[u8]) -> Self {
        let mut script =
            Self::with_capacity(ScriptBytes::len_for_slice(data.len()) + 1);
        script.push_opcode(OpCode::Return);
        script.0.push_slice(data);
        script
    }

    pub fn is_op_return(&self) -> bool { self[0] == OpCode::Return as u8 }

    /// Adds a single opcode to the script.
    pub fn push_opcode(&mut self, op_code: OpCode) {
        self.0.push(op_code as u8).expect("script exceeds 4GB");
    }
}
