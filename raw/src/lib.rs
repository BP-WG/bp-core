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

pub extern crate secp256k1;

mod serialize;
mod sha256;
mod taproot;
mod tx;

pub use sha256::Sha256;
pub use taproot::*;
pub use tx::{
    LockTime, Sats, ScriptPubkey, SeqNo, SigScript, Tx, TxIn, TxOut, TxVer,
    Txid,
};
pub use types::{VarIntArray, VarIntBytes};

mod types {
    use std::fmt::{Formatter, LowerHex, UpperHex};

    use amplify::confinement::Confined;
    use amplify::hex::ToHex;

    pub type VarIntArray<T> = Confined<Vec<T>, 0, { u64::MAX as usize }>;

    #[derive(
        Wrapper, WrapperMut, Clone, Ord, PartialOrd, Eq, PartialEq, Hash,
        Default, Debug, From
    )]
    #[wrapper(Deref, RangeOps, BorrowSlice)]
    #[wrapper_mut(DerefMut, RangeMut, BorrowSliceMut)]
    pub struct VarIntBytes(VarIntArray<u8>);

    impl From<Vec<u8>> for VarIntBytes {
        fn from(value: Vec<u8>) -> Self {
            Self(Confined::try_from(value).expect("u64 >= usize"))
        }
    }

    impl LowerHex for VarIntBytes {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            f.write_str(&self.0.as_inner().to_hex())
        }
    }

    impl UpperHex for VarIntBytes {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            f.write_str(&self.0.as_inner().to_hex().to_uppercase())
        }
    }
}
