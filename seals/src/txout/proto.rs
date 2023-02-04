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

use bc::Txid;
use commit_verify::mpc;
use dbc::{Anchor, Proof};
use single_use_seals::{SealProtocol, SealStatus, VerifySeal};
use strict_encoding::StrictDumb;

use crate::resolver::Resolver;
use crate::txout::{TxoSeal, VerifyError};

pub struct Witness {
    pub txid: Txid,
    pub proof: Proof,
}

impl<L> From<Anchor<L>> for Witness
where
    L: mpc::Proof + StrictDumb,
{
    fn from(anchor: Anchor<L>) -> Self {
        Witness {
            txid: anchor.txid,
            proof: anchor.dbc_proof,
        }
    }
}

/// Txo single-use-seal engine.
pub struct TxoProtocol<R: Resolver> {
    resolver: R,
}

impl<Seal, R> SealProtocol<Seal> for TxoProtocol<R>
where
    Seal: TxoSeal,
    R: Resolver,
{
    type Witness = Witness;
    type Message = mpc::Commitment;
    type PublicationId = Txid;
    type Error = VerifyError;

    fn get_seal_status(&self, _seal: &Seal) -> Result<SealStatus, Self::Error> {
        todo!()
    }
}

impl<'seal, Seal, R> VerifySeal<'seal, Seal> for TxoProtocol<R>
where
    Seal: TxoSeal + 'seal,
    R: Resolver,
{
    fn verify_seal(
        &self,
        seal: &'seal Seal,
        msg: &Self::Message,
        witness: &Self::Witness,
    ) -> Result<bool, Self::Error> {
        // 1. Get tx
        let tx = self.resolver.tx_by_id(witness.txid)?;

        // 2. The seal must match tx inputs
        let outpoint = seal.outpoint_or(witness.txid);
        if !tx.inputs.iter().any(|txin| txin.prev_output == outpoint) {
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
        let tx = self.resolver.tx_by_id(witness.txid)?;

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
            if !tx.inputs.iter().any(|txin| txin.prev_output == outpoint) {
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
