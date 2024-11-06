// Bitcoin protocol single-use-seals library.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2024 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Bitcoin single-use-seals defined by a transaction output and closed by
//! spending that output ("TxOut seals").

use core::fmt::Debug;
use core::marker::PhantomData;

use amplify::Bytes;
use bc::{Outpoint, Tx, Txid};
use commit_verify::mpc::{self, ProtocolId};
use commit_verify::ReservedBytes;
use single_use_seals::{ClientSideWitness, PublishedWitness, SealWitness, SingleUseSeal};
use strict_encoding::StrictDumb;

use crate::SecretSeal;

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = dbc::LIB_NAME_BPCORE)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct Noise(Bytes<68>);

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = dbc::LIB_NAME_BPCORE)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct Anchor<D: dbc::Proof> {
    pub mpc_proof: mpc::MerkleProof,
    pub dbc_proof: D,
    #[cfg_attr(feature = "serde", serde(skip))]
    // TODO: This should become an option
    pub fallback_proof: ReservedBytes<1>,
}

pub struct Proof<D: dbc::Proof> {
    pub mpc_commit: mpc::Commitment,
    pub dbc_proof: D,
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = dbc::LIB_NAME_BPCORE, tags = custom)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", untagged)
)]
pub enum TxoSealExt {
    #[display("~")]
    #[strict_type(tag = 0)]
    Noise(Noise),

    #[display(inner)]
    #[strict_type(tag = 1)]
    Fallback(Outpoint),
}

impl StrictDumb for TxoSealExt {
    fn strict_dumb() -> Self { TxoSealExt::Noise(Noise::from(Bytes::from_byte_array([0u8; 68]))) }
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[display("{primary}/{secondary}")]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = dbc::LIB_NAME_BPCORE)]
#[derive(CommitEncode)]
#[commit_encode(strategy = strict, id = SecretSeal)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct TxoSeal<D: dbc::Proof> {
    pub primary: Outpoint,
    pub secondary: TxoSealExt,
    #[strict_type(skip)]
    #[cfg_attr(feature = "serde", serde(skip))]
    _phantom: PhantomData<D>,
}

impl<D: dbc::Proof> SingleUseSeal for TxoSeal<D> {
    type Message = Proof<D>;
    type PubWitness = Tx;
    type CliWitness = Anchor<D>;

    fn is_included(&self, witness: &SealWitness<Self>) -> bool {
        let mut inputs = witness.published.inputs();
        match self.secondary {
            TxoSealExt::Noise(_) => {
                inputs.any(|input| input.prev_output == self.primary)
                // TODO: && witness.client.fallback_proof.is_none()
            }
            TxoSealExt::Fallback(fallback) => {
                inputs.any(|input| input.prev_output == fallback)
                // TODO: && witness.client.fallback_proof.is_some()
            }
        }
    }
}

// TODO: It's not just a transaction, it should be an SPV proof
impl<D: dbc::Proof> PublishedWitness<TxoSeal<D>> for Tx {
    type PubId = Txid;
    type Error = D::Error;

    fn pub_id(&self) -> Txid { self.txid() }
    fn verify_commitment(&self, proof: Proof<D>) -> Result<(), Self::Error> {
        proof.dbc_proof.verify(&proof.mpc_commit, self)
    }
}

impl<D: dbc::Proof> ClientSideWitness for Anchor<D> {
    type Message = (ProtocolId, mpc::Message);
    type Seal = TxoSeal<D>;
    type Error = mpc::InvalidProof;

    fn convolve_commit(
        &self,
        (protocol_id, message): (ProtocolId, mpc::Message),
    ) -> Result<Proof<D>, Self::Error> {
        // TODO: Verify fallback proof
        // if let Some(_fallback_proof) = self.fallback_proof {
        // }
        let mpc_commit = self.mpc_proof.convolve(protocol_id, message)?;
        Ok(Proof {
            mpc_commit,
            dbc_proof: self.dbc_proof.clone(),
        })
    }
}
