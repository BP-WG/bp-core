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

use amplify::Bytes32;

use super::{VarIntArray, VarIntBytes};

#[derive(Wrapper, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, From)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
#[wrapper(RangeOps, BorrowSlice, Hex, Display, FromStr)]
// all-zeros used in coinbase
pub struct Txid(
    #[from]
    #[from([u8; 32])]
    Bytes32,
);

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
// 0xFFFFFFFF used in coinbase
pub struct Vout(u32);

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
pub struct Outpoint {
    pub txid: Txid,
    pub vout: Vout,
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct SeqNo(u32);

#[derive(Clone, Eq, PartialEq, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct SigScript(VarIntBytes);

#[derive(Clone, Eq, PartialEq, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
pub struct TxIn {
    pub prev_output: Outpoint,
    pub sig_script: SigScript,
    pub sequence: SeqNo,
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct Sats(u64);

#[derive(Clone, Eq, PartialEq, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct ScriptPubkey(VarIntBytes);

#[derive(Clone, Eq, PartialEq, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
pub struct TxOut {
    pub value: Sats,
    pub script_pubkey: ScriptPubkey,
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
pub enum TxVer {
    V1,
    V2,
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct LockTime(u32);

#[derive(Clone, Eq, PartialEq, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
pub struct Tx {
    pub version: TxVer,
    pub inputs: VarIntArray<TxIn>,
    pub outputs: VarIntArray<TxOut>,
    pub lock_time: LockTime,
}
