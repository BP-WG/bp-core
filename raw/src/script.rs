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

use amplify::confinement;
use amplify::confinement::Confined;

use crate::{VarIntBytes, LIB_NAME_BP};

#[derive(Copy, Clone, Eq, PartialEq, Debug, Display)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BP, tags = repr, into_u8, try_from_u8)]
#[repr(u8)]
pub enum OpCode {
    /// Fail the script immediately.
    #[display("OP_RETURN")]
    #[strict_type(dumb)]
    Return = 0x6a,

    /// Read the next byte as N; push the next N bytes as an array onto the
    /// stack.
    PushData1 = 0x4c,
    /// Read the next 2 bytes as N; push the next N bytes as an array onto the
    /// stack.
    PushData2 = 0x4d,
    /// Read the next 4 bytes as N; push the next N bytes as an array onto the
    /// stack.
    PushData4 = 0x4e,
}

#[derive(Clone, Eq, PartialEq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BP)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct SigScript(VarIntBytes);

#[derive(Clone, Eq, PartialEq, Debug, Default)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BP)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct ScriptPubkey(VarIntBytes);

impl ScriptPubkey {
    pub fn new() -> Self { Self::default() }

    pub fn with_capacity(capacity: usize) -> Self {
        Self(VarIntBytes::from(Confined::with_capacity(capacity)))
    }

    pub fn op_return(data: &[u8]) -> Self {
        let mut script =
            Self::with_capacity(Self::reserved_len_for_slice(data.len()) + 1);
        script.push_opcode(OpCode::Return).expect("fixed size");
        script.push_slice(data);
        script
    }

    /// Adds a single opcode to the script.
    pub fn push_opcode(
        &mut self,
        op_code: OpCode,
    ) -> Result<(), confinement::Error> {
        self.0.push(op_code as u8)
    }

    /// Adds instructions to push some arbitrary data onto the stack.
    ///
    /// ## Panics
    ///
    /// The method panics if `data` length is greater or equal to 0x100000000.
    pub fn push_slice(&mut self, data: &[u8]) {
        // Start with a PUSH opcode
        match data.len() as u64 {
            n if n < OpCode::PushData1 as u64 => {
                self.push(n as u8);
            }
            n if n < 0x100 => {
                self.push(OpCode::PushData1 as u8);
                self.push(n as u8);
            }
            n if n < 0x10000 => {
                self.push(OpCode::PushData2 as u8);
                self.push((n % 0x100) as u8);
                self.push((n / 0x100) as u8);
            }
            n if n < 0x100000000 => {
                self.push(OpCode::PushData4 as u8);
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
    fn push(&mut self, data: u8) {
        self.0.push(data).expect("script exceeds 4GB")
    }

    #[inline]
    fn extend(&mut self, data: &[u8]) {
        self.0
            .extend(data.iter().copied())
            .expect("script exceeds 4GB")
    }

    /// Computes the sum of `len` and the lenght of an appropriate push opcode.
    fn reserved_len_for_slice(len: usize) -> usize {
        len + match len {
            0..=0x4b => 1,
            0x4c..=0xff => 2,
            0x100..=0xffff => 3,
            // we don't care about oversized, the other fn will panic anyway
            _ => 5,
        }
    }
}
