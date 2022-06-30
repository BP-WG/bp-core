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

use bitcoin::Txid;
use bitcoin_onchain::ResolveTx;
use commit_verify::lnpbp4;
use dbc::{Anchor, Proof};
use single_use_seals::{SealProtocol, SealStatus, VerifySeal};

use crate::txout::{TxoSeal, VerifyError};

// TODO: #8 Implement proper operations with SealMedium
// TODO: #9 Do asynchronous version
// #[cfg(feature = "async")]
// use single_use_seals::SealMediumAsync;

pub struct Witness {
    pub txid: Txid,
    pub proof: Proof,
}

impl<L> From<Anchor<L>> for Witness
where
    L: lnpbp4::Proof,
{
    fn from(anchor: Anchor<L>) -> Self {
        Witness {
            txid: anchor.txid,
            proof: anchor.dbc_proof,
        }
    }
}

/// Txo single-use-seal engine.
pub struct TxoProtocol<Resolver: ResolveTx> {
    resolver: Resolver,
}

impl<Seal, Resolver> SealProtocol<Seal> for TxoProtocol<Resolver>
where
    Seal: TxoSeal,
    Resolver: ResolveTx,
{
    type Witness = Witness;
    type Message = lnpbp4::CommitmentHash;
    type PublicationId = Txid;
    type Error = VerifyError;

    fn get_seal_status(&self, _seal: &Seal) -> Result<SealStatus, Self::Error> {
        todo!()
    }
}

impl<'seal, Seal, Resolver> VerifySeal<'seal, Seal> for TxoProtocol<Resolver>
where
    Seal: TxoSeal + 'seal,
    Resolver: ResolveTx,
{
    fn verify_seal(
        &self,
        seal: &'seal Seal,
        msg: &Self::Message,
        witness: &Self::Witness,
    ) -> Result<bool, Self::Error> {
        // 1. Get tx
        let tx = self.resolver.resolve_tx(witness.txid)?;

        // 2. The seal must match tx inputs
        let outpoint = seal.outpoint_or(witness.txid);
        if !tx.input.iter().any(|txin| txin.previous_output == outpoint) {
            return Err(VerifyError::WitnessNotClosingSeal(
                witness.txid,
                outpoint,
            ));
        }

        // 3. Verify DBC with the giving closing method
        witness.proof.verify(msg, tx).map_err(VerifyError::from)
    }

    fn verify_seal_all(
        &self,
        seals: impl IntoIterator<Item = &'seal Seal>,
        msg: &Self::Message,
        witness: &Self::Witness,
    ) -> Result<bool, Self::Error> {
        // 1. Get tx
        let tx = self.resolver.resolve_tx(witness.txid)?;

        let mut method = None;
        for seal in seals {
            // 2. All seals must have the same closing method
            if let Some(method) = method {
                if method != seal.method() {
                    return Err(VerifyError::InconsistentCloseMethod);
                }
            } else {
                method = Some(seal.method());
            }

            // 3. Each seal must match tx inputs
            let outpoint = seal.outpoint_or(witness.txid);
            if !tx.input.iter().any(|txin| txin.previous_output == outpoint) {
                return Err(VerifyError::WitnessNotClosingSeal(
                    witness.txid,
                    outpoint,
                ));
            }
        }

        // 4. Verify DBC with the giving closing method
        witness.proof.verify(msg, tx).map_err(VerifyError::from)
    }
}
