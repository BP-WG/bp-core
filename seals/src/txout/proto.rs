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

use bitcoin::{Transaction, Txid};
use commit_verify::multi_commit::MultiCommitment;
use dbc::tapret::TapretProof;
use single_use_seals::{SealProtocol, SealStatus};

use crate::txout::{TxoSeal, VerifyError};

// TODO: #8 Implement proper operations with SealMedium
// TODO: #9 Do asyncronous version
// #[cfg(feature = "async")]
// use single_use_seals::SealMediumAsync;

pub struct Witness(pub InnerWitness, pub OuterWitness);

pub type InnerWitness = Transaction;
pub type OuterWitness = TapretProof;

/// Txo single-use-seal engine.
pub struct TxoProtocol;

impl<Seal> SealProtocol<Seal> for TxoProtocol
where
    Seal: TxoSeal,
{
    type Witness = Witness;
    type Message = MultiCommitment;
    type PublicationId = Txid;
    type Error = VerifyError;

    fn verify(
        &self,
        _seal: &Seal,
        _msg: &Self::Message,
        _witness: &Self::Witness,
    ) -> Result<bool, Self::Error> {
        todo!()
    }

    fn get_seal_status(&self, _seal: &Seal) -> Result<SealStatus, Self::Error> {
        todo!()
    }
}

/*
pub trait TxResolve {
    type Error: std::error::Error;
    fn tx_container(
        &self,
        outpoint: OutPoint,
    ) -> Result<TxContainer, Self::Error>;
    fn tx_and_data(
        &self,
        outpoint: OutPoint,
    ) -> Result<(Transaction, TxSupplement), Self::Error>;
}
*/
