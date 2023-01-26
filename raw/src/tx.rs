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

// all-zeros used in coinbase
pub struct Txid(Bytes32);

// 0xFFFFFFFF used in coinbase
pub struct Vout(u32);

pub struct Outpoint {
    pub txid: Txid,
    pub vout: Vout,
}

pub struct SeqNo(u32);

pub struct SigScript(VarIntBytes);

pub struct TxIn {
    pub prev_output: Outpoint,
    pub sig_script: SigScript,
    pub sequence: SeqNo,
}

pub struct Sats(u64);

pub struct ScriptPubkey(VarIntBytes);

pub struct TxOut {
    pub value: Sats,
    pub script_pubkey: ScriptPubkey,
}

pub enum TxVer {
    V1,
    V2,
}

pub struct LockTime(u32);

pub struct Tx {
    pub version: TxVer,
    pub inputs: VarIntArray<TxIn>,
    pub outputs: VarIntArray<TxOut>,
    pub lock_time: LockTime,
}
