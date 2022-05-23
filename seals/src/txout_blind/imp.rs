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

use amplify::Wrapper;
use bitcoin::{OutPoint, Transaction};
use commit_verify::{EmbedCommitVerify, Message};
use dbc::tapret::TapretProof;
#[cfg(feature = "async")]
use single_use_seals::SealMediumAsync;
use single_use_seals::{SealMedium, SingleUseSeal};

use super::Error;

// TODO: #8 Implement proper operations with SealMedium
// TODO: #9 Do asyncronous version

pub struct Witness(pub InnerWitness, pub OuterWitness);

pub type InnerWitness = Transaction;
pub type OuterWitness = TapretProof;

pub struct TxoutSeal<'a, R>
where
    R: TxResolve,
    Self: 'a,
{
    seal_definition: OutPoint,
    resolver: &'a R,
}

impl<'a, R> TxoutSeal<'a, R>
where
    R: TxResolve,
    Self: 'a,
{
    pub fn new(seal_definition: OutPoint, resolver: &'a R) -> Self {
        Self {
            seal_definition,
            resolver,
        }
    }
}

#[cfg_attr(feature = "async", async_trait)]
impl<'a, R> SingleUseSeal for TxoutSeal<'a, R>
where
    R: TxResolve,
    Self: 'a,
{
    type Witness = Witness;
    type Definition = OutPoint;
    type Message = Message;
    type Error = Error;

    fn close(
        &self,
        over: &Self::Message,
    ) -> Result<Self::Witness, Self::Error> {
        let mut container = self
            .resolver
            .tx_container(self.seal_definition)
            .map_err(|_| Error::ResolverError)?;
        let tx_commitment = TxCommitment::embed_commit(&mut container, &over)?;
        Ok(Witness(tx_commitment, container.to_proof()))
    }

    fn verify(
        &self,
        msg: &Self::Message,
        witness: &Self::Witness,
        _medium: &impl SealMedium<Self>,
    ) -> Result<bool, Self::Error> {
        let (host, supplement) = self
            .resolver
            .tx_and_data(self.seal_definition)
            .map_err(|_| Error::ResolverError)?;
        let found_seals = host
            .input
            .iter()
            .filter(|txin| txin.previous_output == self.seal_definition);
        if found_seals.count() != 1 {
            return Err(Error::ResolverLying);
        }
        let container =
            TxContainer::reconstruct(&witness.1, &supplement, &host)?;
        let commitment = TxCommitment::from_inner(host);
        Ok(commitment.verify(&container, &msg)?)
    }

    #[cfg(feature = "async")]
    async fn verify_async(
        &self,
        _msg: &Self::Message,
        _witness: &Self::Witness,
        _medium: &impl SealMediumAsync<Self>,
    ) -> Result<bool, Self::Error>
    where
        Self: Sized + Sync + Send,
    {
        todo!("#9 Implement verify_async")
    }
}

/*
impl<'a, TXGRAPH> SealMedium<'a, TxoutSeal<'a, TXGRAPH>> for TXGRAPH
where
    TXGRAPH: TxGraph + TxResolve,
{
    type PublicationId = ShortId;
    type Error = Error;

    fn define_seal(
        &'a self,
        seal_definition: &OutPoint,
    ) -> Result<TxoutSeal<TXGRAPH>, Self::Error> {
        let outpoint = seal_definition;
        match self
            .spending_status(outpoint)
            .map_err(|_| Error::MediumAccessError)?
        {
            SpendingStatus::Unknown => Err(Error::InvalidSealDefinition),
            SpendingStatus::Invalid => Err(Error::InvalidSealDefinition),
            SpendingStatus::Unspent => {
                Ok(TxoutSeal::new(outpoint.clone(), self))
            }
            SpendingStatus::Spent(_) => Err(Error::SpentTxout),
        }
    }

    fn get_seal_status(
        &self,
        seal: &TxoutSeal<TXGRAPH>,
    ) -> Result<SealStatus, Self::Error> {
        match self
            .spending_status(&seal.seal_definition)
            .map_err(|_| Error::MediumAccessError)?
        {
            SpendingStatus::Unknown => Ok(SealStatus::Undefined),
            SpendingStatus::Invalid => Ok(SealStatus::Undefined),
            SpendingStatus::Unspent => Ok(SealStatus::Undefined),
            SpendingStatus::Spent(_) => Ok(SealStatus::Closed),
        }
    }
}
 */

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
