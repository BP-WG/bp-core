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

use core::cmp::Ordering;
use core::fmt::Debug;
use core::marker::PhantomData;

use amplify::{ByteArray, Bytes, Bytes32};
use bc::{Outpoint, Tx, Txid, Vout};
use commit_verify::{mpc, CommitId, DigestExt, ReservedBytes, Sha256, StrictHash};
use single_use_seals::{ClientSideWitness, PublishedWitness, SealWitness, SingleUseSeal};
use strict_encoding::StrictDumb;

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = dbc::LIB_NAME_BPCORE)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct Noise(Bytes<40>);

pub mod mmb {
    use amplify::confinement::SmallOrdMap;
    use commit_verify::{CommitmentId, DigestExt, Sha256};

    use super::*;

    #[derive(Wrapper, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, From)]
    #[wrapper(Deref, BorrowSlice, Hex, Index, RangeOps)]
    #[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
    #[strict_type(lib = dbc::LIB_NAME_BPCORE)]
    #[cfg_attr(
        feature = "serde",
        derive(Serialize, Deserialize),
        serde(crate = "serde_crate", transparent)
    )]
    pub struct Commitment(
        #[from]
        #[from([u8; 32])]
        Bytes32,
    );
    impl CommitmentId for Commitment {
        const TAG: &'static str = "urn:lnp-bp:mmb:bundle#2024-11-18";
    }
    impl From<Sha256> for Commitment {
        fn from(hasher: Sha256) -> Self { hasher.finish().into() }
    }

    #[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
    #[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
    #[strict_type(lib = dbc::LIB_NAME_BPCORE)]
    #[derive(CommitEncode)]
    #[commit_encode(strategy = strict, id = Commitment)]
    #[cfg_attr(
        feature = "serde",
        derive(Serialize, Deserialize),
        serde(crate = "serde_crate", rename_all = "camelCase")
    )]
    pub struct BundleProof {
        pub map: SmallOrdMap<u32, Bytes32>,
    }

    impl BundleProof {
        pub fn verify(&self, seal: Outpoint, msg: Bytes32, tx: &Tx) -> bool {
            let Some(input_index) = tx.inputs().position(|input| input.prev_output == seal) else {
                return false;
            };
            let Ok(input_index) = u32::try_from(input_index) else {
                return false;
            };
            let Some(expected) = self.map.get(&input_index) else {
                return false;
            };
            *expected == msg
        }
    }
}

/// Anchor is a client-side witness for the bitcoin txout seals.
///
/// Anchor is a set of data required for the client-side validation of a bitcoin txout single-use
/// seal, which can't be recovered from the transaction and other public information itself.
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = dbc::LIB_NAME_BPCORE)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct Anchor<D: dbc::Proof> {
    pub mmb_proof: mmb::BundleProof,
    pub mpc_protocol: mpc::ProtocolId,
    pub mpc_proof: mpc::MerkleProof,
    pub dbc_proof: D,
    #[cfg_attr(feature = "serde", serde(skip))]
    // TODO: This should become an option once fallback proofs are ready
    pub fallback_proof: ReservedBytes<1>,
}

impl<D: dbc::Proof> Anchor<D> {
    // TODO: Change when the fallback proofs are ready
    pub fn is_fallback(&self) -> bool { false }
    // TODO: Change when the fallback proofs are ready
    pub fn verify_fallback(&self) -> Result<(), AnchorError> { Ok(()) }
}

/// Proof data for verification of deterministic bitcoin commitment produced from anchor.
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
    fn strict_dumb() -> Self { TxoSealExt::Noise(Noise::from(Bytes::from_byte_array([0u8; 40]))) }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, Display)]
#[display("{primary}/{secondary}")]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = dbc::LIB_NAME_BPCORE)]
#[derive(CommitEncode)]
#[commit_encode(strategy = strict, id = StrictHash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct TxoSeal<D: dbc::Proof> {
    pub primary: Outpoint,
    pub secondary: TxoSealExt,
    #[strict_type(skip)]
    #[cfg_attr(feature = "serde", serde(skip))]
    _phantom: PhantomData<D>,
}

// Manual impl is needed since we need to avoid D: Copy bound
impl<D: dbc::Proof> Copy for TxoSeal<D> {}
impl<D: dbc::Proof> PartialOrd for TxoSeal<D> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}
impl<D: dbc::Proof> Ord for TxoSeal<D> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.primary.cmp(&other.primary).then(self.secondary.cmp(&other.secondary))
    }
}

impl<D: dbc::Proof> TxoSeal<D> {
    /// `nonce` is a deterministic incremental number, preventing from creating the same seal if the
    /// same output is used.
    pub fn vout_no_fallback(vout: Vout, noise_engine: Sha256, nonce: u64) -> Self {
        Self::no_fallback(Outpoint::new(Txid::from([0xFFu8; 32]), vout), noise_engine, nonce)
    }

    /// `nonce` is a deterministic incremental number, preventing from creating the same seal if the
    /// same output is used.
    pub fn no_fallback(outpoint: Outpoint, mut noise_engine: Sha256, nonce: u64) -> Self {
        noise_engine.input_raw(&nonce.to_be_bytes());
        noise_engine.input_raw(outpoint.txid.as_ref());
        noise_engine.input_raw(&outpoint.vout.to_u32().to_be_bytes());
        let mut noise = [0xFFu8; 40];
        noise[..32].copy_from_slice(&noise_engine.finish());
        Self {
            primary: outpoint,
            secondary: TxoSealExt::Noise(Noise(noise.into())),
            _phantom: PhantomData,
        }
    }
}

impl<D: dbc::Proof> SingleUseSeal for TxoSeal<D> {
    type Message = Bytes32;
    type PubWitness = Tx;
    type CliWitness = Anchor<D>;

    fn is_included(&self, message: Self::Message, witness: &SealWitness<Self>) -> bool {
        match self.secondary {
            TxoSealExt::Noise(_) | TxoSealExt::Fallback(_) if !witness.client.is_fallback() => {
                witness.client.mmb_proof.verify(self.primary, message, &witness.published)
            }
            TxoSealExt::Fallback(fallback) => {
                witness.client.mmb_proof.verify(fallback, message, &witness.published)
            }
            // If we are provided a fallback proof but no fallback seal were defined
            TxoSealExt::Noise(_) => false,
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
    type Proof = Proof<D>;
    type Seal = TxoSeal<D>;
    type Error = AnchorError;

    fn convolve_commit(&self, _: Bytes32) -> Result<Proof<D>, Self::Error> {
        self.verify_fallback()?;
        let bundle_id = self.mmb_proof.commit_id();
        let mpc_message = mpc::Message::from_byte_array(bundle_id.to_byte_array());
        let mpc_commit = self.mpc_proof.convolve(self.mpc_protocol, mpc_message)?;
        Ok(Proof {
            mpc_commit,
            dbc_proof: self.dbc_proof.clone(),
        })
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Error, Debug, Display, From)]
#[display(inner)]
pub enum AnchorError {
    #[from]
    Mpc(mpc::InvalidProof),
}
