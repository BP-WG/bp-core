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

#[macro_use]
extern crate amplify;
#[macro_use]
extern crate strict_encoding;
#[cfg(feature = "serde")]
#[macro_use]
extern crate serde_crate as serde;

pub extern crate secp256k1;

pub mod opcodes;
mod script;
mod serialize;
mod sha256;
mod taproot;
mod tx;

pub use script::{OpCode, ScriptPubkey, SigScript};
pub use sha256::Sha256;
pub use taproot::*;
pub use tx::{
    LockTime, Outpoint, Sats, SeqNo, Tx, TxIn, TxOut, TxVer, Txid, Vout,
};
pub use types::{ScriptBytes, VarIntArray};

pub const LIB_NAME_BP: &str = "BP";

mod types {
    use std::fmt::{Formatter, LowerHex, UpperHex};

    use amplify::confinement::Confined;
    use amplify::hex::ToHex;

    use super::LIB_NAME_BP;
    use crate::opcodes::*;

    pub type VarIntArray<T> = Confined<Vec<T>, 0, { u64::MAX as usize }>;

    #[derive(
        Wrapper, WrapperMut, Clone, Ord, PartialOrd, Eq, PartialEq, Hash,
        Default, Debug, From
    )]
    #[derive(StrictType, StrictEncode, StrictDecode)]
    #[strict_type(lib = LIB_NAME_BP)]
    #[cfg_attr(
        feature = "serde",
        derive(Serialize, Deserialize),
        serde(crate = "serde_crate", transparent)
    )]
    #[wrapper(Deref, Index, RangeOps, BorrowSlice)]
    #[wrapper_mut(DerefMut, IndexMut, RangeMut, BorrowSliceMut)]
    pub struct ScriptBytes(VarIntArray<u8>);

    impl From<Vec<u8>> for ScriptBytes {
        fn from(value: Vec<u8>) -> Self {
            Self(Confined::try_from(value).expect("u64 >= usize"))
        }
    }

    impl LowerHex for ScriptBytes {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            f.write_str(&self.0.as_inner().to_hex())
        }
    }

    impl UpperHex for ScriptBytes {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            f.write_str(&self.0.as_inner().to_hex().to_uppercase())
        }
    }

    impl ScriptBytes {
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
        fn push(&mut self, data: u8) {
            self.0.push(data).expect("script exceeds 4GB")
        }

        #[inline]
        fn extend(&mut self, data: &[u8]) {
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
    }
}
