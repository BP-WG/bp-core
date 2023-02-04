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

use bc::{ScriptPubkey, Tx, Txid};

#[derive(Debug, Display)]
#[display(doc_comments)]
pub enum Error {
    /// ... todo
    Connection(Box<dyn std::error::Error>),
    /// ... todo
    UnknownTx,
}

pub trait Resolver {
    fn tx_by_id(&self, txid: Txid) -> Result<Tx, Error>;
    fn tx_by_spk(&self, spk: &ScriptPubkey) -> Result<Vec<u8>, Error>;
}
