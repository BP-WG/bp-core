// Bitcoin protocol single-use-seals library.
//
// SPDX-License-Identifier: Apache-2.0
//
// Designed in 2019-2025 by Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
// Written in 2024-2025 by Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association, Switzerland.
// Copyright (C) 2024-2025 LNP/BP Labs, Institute for Distributed and Cognitive Systems (InDCS).
// Copyright (C) 2019-2025 Dr Maxim Orlovsky.
// All rights under the above copyrights are reserved.
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

use core::error::Error;
use core::fmt::Debug;

use amplify::{ByteArray, Bytes, Bytes32};
use bc::{Outpoint, Tx, Txid};
use commit_verify::{
    CommitId, ConvolveVerifyError, DigestExt, EmbedVerifyError, ReservedBytes, Sha256,
};
use dbc::opret::{OpretError, OpretProof};
use dbc::tapret::TapretProof;
use single_use_seals::{ClientSideWitness, PublishedWitness, SealWitness, SingleUseSeal};
use strict_encoding::{StrictDumb, StrictSum};

use crate::WOutpoint;

/// A noise, which acts as a placeholder for seal definitions lacking fallback seal (see
/// [`TxoSealExt::Noise`]).
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, From)]
#[display("{0:x}")]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = dbc::LIB_NAME_BPCORE)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(transparent))]
pub struct Noise(Bytes<40>);

impl Noise {
    /// Construct a new noise object using entropy from a pre-initialized SHA256 engine, some nonce
    /// and main [`WTxoSeal`] definition outpoint.
    pub fn with(outpoint: WOutpoint, mut noise_engine: Sha256, nonce: u64) -> Self {
        noise_engine.input_raw(&nonce.to_be_bytes());
        match outpoint {
            WOutpoint::Wout(wout) => {
                noise_engine.input_raw(&[WOutpoint::ALL_VARIANTS[0].0]);
                noise_engine.input_raw(&wout.to_u32().to_be_bytes());
            }
            WOutpoint::Extern(outpoint) => {
                noise_engine.input_raw(&[WOutpoint::ALL_VARIANTS[1].0]);
                noise_engine.input_raw(outpoint.txid.as_ref());
                noise_engine.input_raw(&outpoint.vout.to_u32().to_be_bytes());
            }
        }
        let mut noise = [0xFFu8; 40];
        noise[..32].copy_from_slice(&noise_engine.finish());
        Self(noise.into())
    }
}

/// Multi-message bundles.
///
/// Multi-message bundles allow putting multiple independent messages into a single commitment under
/// a single MPC protocol. This is achieved by associating each single message with a subset of
/// witness transaction outputs, which is provably disjoint with other subsets for all other
/// messages under the same protocol.
///
/// The proof of disjoint is in [`mmb::BundleProof`], each individual message is kept in
/// [`mmb::Message`], and the final commitment to all messages is represented by [`mmb::Commitment`]
/// structure.
///
/// # See also
///
/// Multiprotocol commitments in [`commit_verify::mpc`]
pub mod mmb {
    use amplify::confinement::SmallOrdMap;
    use commit_verify::{CommitmentId, DigestExt, Sha256};

    use super::*;

    /// A message for a multi-message bundling.
    #[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From, Default)]
    #[wrapper(Deref, BorrowSlice, Display, FromStr, Hex, Index, RangeOps)]
    #[derive(StrictType, StrictEncode, StrictDecode)]
    #[strict_type(lib = dbc::LIB_NAME_BPCORE)]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(transparent))]
    pub struct Message(
        #[from]
        #[from([u8; 32])]
        Bytes32,
    );

    /// The final commitment to all messages under a multi-message bundle.
    ///
    /// The commitment is produced by a linear strict-encoding of the data in a [`BundleProof`].
    /// The data are not merklized since, in order to verify the proof, all messages must be anyway
    /// present in explicit form.
    #[derive(Wrapper, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, From)]
    #[wrapper(Deref, BorrowSlice, Hex, Index, RangeOps)]
    #[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
    #[strict_type(lib = dbc::LIB_NAME_BPCORE)]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(transparent))]
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

    impl From<Commitment> for mpc::Message {
        fn from(msg: Commitment) -> Self { mpc::Message::from_byte_array(msg.to_byte_array()) }
    }

    /// The proof that each message is associated with a separate subset of witness transaction
    /// inputs, and all of these subsets are disjoint.
    #[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
    #[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
    #[strict_type(lib = dbc::LIB_NAME_BPCORE)]
    #[derive(CommitEncode)]
    #[commit_encode(strategy = strict, id = Commitment)]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    pub struct BundleProof {
        /// Map from a transaction input number to a specific message which is associated with it.
        pub map: SmallOrdMap<u32, Message>,
    }

    impl BundleProof {
        /// Verify that the proof matches the witness transaction structure.
        pub fn verify(&self, seal: Outpoint, msg: Message, tx: &Tx) -> bool {
            // Verify that there is a witness transaction input which spends a TxO matching the
            // single-use seal definition.
            let Some(input_index) = tx.inputs().position(|input| input.prev_output == seal) else {
                return false;
            };
            let Ok(input_index) = u32::try_from(input_index) else {
                return false;
            };
            // Check that this output belongs to the same message as expected.
            let Some(expected) = self.map.get(&input_index) else {
                return false;
            };
            *expected == msg
        }
    }
}

/// Module extends [`commit_verify::mpc`] module with multi-message bundle commitments.
pub mod mpc {
    use amplify::confinement::MediumOrdMap;
    use amplify::num::u5;
    use amplify::ByteArray;
    pub use commit_verify::mpc::{
        Commitment, Error, InvalidProof, Leaf, LeafNotKnown, MergeError, MerkleBlock,
        MerkleConcealed, MerkleProof, MerkleTree, Message, Method, Proof, ProtocolId,
        MPC_MINIMAL_DEPTH,
    };
    use commit_verify::{CommitId, TryCommitVerify};

    use crate::mmb;

    /// The source of an [`mpc::Message`], which can be either a single message or a multimessage
    /// bundle (in the form of a proof).
    #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, From)]
    #[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
    #[strict_type(lib = dbc::LIB_NAME_BPCORE, tags = custom, dumb = Self::Single(strict_dumb!()))]
    #[cfg_attr(
        feature = "serde",
        derive(Serialize, Deserialize),
        serde(rename_all = "camelCase", untagged)
    )]
    pub enum MessageSource {
        /// A single message.
        #[from]
        #[strict_type(tag = 1)]
        Single(Message),

        /// A multi-message bundle.
        #[from]
        #[strict_type(tag = 2)]
        Mmb(mmb::BundleProof),
    }

    impl MessageSource {
        /// Construct a [`mpc::Message`] from the provided source.
        pub fn mpc_message(&self) -> Message {
            match self {
                MessageSource::Single(message) => *message,
                MessageSource::Mmb(proof) => {
                    Message::from_byte_array(proof.commit_id().to_byte_array())
                }
            }
        }
    }

    /// The message map which associates each protocol with a source of the message (an instance of
    /// a [`MessageSource`]).
    #[derive(
        Wrapper, WrapperMut, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default, From
    )]
    #[wrapper(Deref)]
    #[wrapper_mut(DerefMut)]
    #[derive(StrictType, StrictEncode, StrictDecode)]
    #[strict_type(lib = dbc::LIB_NAME_BPCORE)]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(transparent))]
    pub struct MessageMap(MediumOrdMap<ProtocolId, MessageSource>);

    /// The information for constructing [`mpc::MerkleTree`].
    #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
    #[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
    #[strict_type(lib = dbc::LIB_NAME_BPCORE)]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all = "camelCase"))]
    pub struct Source {
        /// The minimal depth of the tree.
        pub min_depth: u5,
        /// Entropy see for constructing all the non-protocol leafs of the tree.
        pub entropy: u64,
        /// The protocols and messages to put into the tree.
        pub messages: MessageMap,
    }

    impl Source {
        /// Construct a [`mpc::MerkleTree`] from the source data.
        pub fn into_merkle_tree(self) -> Result<MerkleTree, Error> {
            let messages = self.messages.0.iter().map(|(id, src)| {
                let msg = src.mpc_message();
                (*id, msg)
            });
            let source = commit_verify::mpc::MultiSource {
                method: Method::Sha256t,
                min_depth: self.min_depth,
                messages: MediumOrdMap::from_iter_checked(messages),
                static_entropy: Some(self.entropy),
            };
            MerkleTree::try_commit(&source)
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
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all = "camelCase"))]
pub struct Anchor {
    /// The proof that each witness transaction input is used only in a single bundle.
    pub mmb_proof: mmb::BundleProof,
    /// The protocol under which the client-side witness is valid.
    pub mpc_protocol: mpc::ProtocolId,
    /// The inclusion proof (using multiprotocol commitments) of a commitment under the
    /// [`mpc_protocol`] into the published witness.
    pub mpc_proof: mpc::MerkleProof,
    /// The deterministic bitcoin commitment proof that the witness commitment is valid.
    pub dbc_proof: Option<TapretProof>,
    #[cfg_attr(feature = "serde", serde(skip))]
    /// Reserved for the future proofs regarding fallback seals.
    // TODO: This should become an option once fallback proofs are ready
    pub fallback_proof: ReservedBytes<1>,
}

impl Anchor {
    /// Detect whether an anchor corresponds to a fallback proof or not.
    ///
    /// # Nota bene
    ///
    /// In the current version fallback proofs are not implemented, and this method always returns
    /// `false`.
    // TODO: (v0.13) Change when the fallback proofs are ready
    pub fn is_fallback(&self) -> bool { false }

    /// Verify the fallback proof.
    ///
    /// # Nota bene
    ///
    /// In the current version fallback proofs are not implemented, and this method always returns
    /// `Ok(()) `(since if there is no fallback proof defined, it is a case of a valid situation).
    // TODO: (v0.13) Change when the fallback proofs are ready
    pub fn verify_fallback(&self) -> Result<(), AnchorError> { Ok(()) }
}

/// Proof data for verification of deterministic bitcoin commitment produced from anchor.
///
/// This proof is used to do the final verification of the single-use seal closing in the witness
/// transaction (published witness).
pub struct Proof {
    /// The message to which the witness transaction must commit with deterministic bitcoin
    /// commitment.
    ///
    /// The message is produced from the multiprotocol commitment data of an [`Anchor`].
    pub mpc_commit: mpc::Commitment,
    /// The deterministic bitcoin commitment proof that the witness commitment is valid.
    pub dbc_proof: Option<TapretProof>,
}

/// The value for a fallback seal definition.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[display(inner)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = dbc::LIB_NAME_BPCORE, tags = custom)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(untagged))]
pub enum TxoSealExt {
    /// The fallback seal is not defined. The noise data are used instead to obfuscate the main
    /// seal.
    #[strict_type(tag = 0)]
    Noise(Noise),

    /// The fallback seal is defined as a known UTXO.
    #[strict_type(tag = 1)]
    Fallback(Outpoint),
}

impl StrictDumb for TxoSealExt {
    fn strict_dumb() -> Self { TxoSealExt::Noise(Noise::from(Bytes::from_byte_array([0u8; 40]))) }
}

/// The bitcoin TxO-based single-use seal protocol (see [`SingleUseSeal`]).
///
/// # Nota bene
///
/// Unlike [`crate::WTxoSeal`], this seal always contains information about the defined seal.
/// It is constructed once a "previous" witness transaction, which contains a commitment to a
/// [`crate::WTxoSeal`] definition, is constructed, and its transaction id becomes known.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Display)]
#[display("{primary}/{secondary}")]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = dbc::LIB_NAME_BPCORE)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TxoSeal {
    /// A primary seal definition.
    pub primary: Outpoint,
    /// A fallback seal definition.
    pub secondary: TxoSealExt,
}

impl SingleUseSeal for TxoSeal {
    type Message = mmb::Message;
    type PubWitness = Tx;
    type CliWitness = Anchor;

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

impl PublishedWitness<TxoSeal> for Tx {
    type PubId = Txid;
    type Error = TxoSealError;

    fn pub_id(&self) -> Txid { self.txid() }

    fn verify_commitment(&self, proof: Proof) -> Result<(), Self::Error> {
        let out = self
            .outputs()
            .find(|out| out.script_pubkey.is_op_return() || out.script_pubkey.is_p2tr())
            .ok_or(TxoSealError::NoOutput)?;
        if out.script_pubkey.is_op_return() {
            if proof.dbc_proof.is_none() {
                OpretProof::default().verify(&proof.mpc_commit, self).map_err(TxoSealError::from)
            } else {
                Err(TxoSealError::InvalidProofType)
            }
        } else if let Some(ref dbc_proof) = proof.dbc_proof {
            dbc_proof.verify(&proof.mpc_commit, self).map_err(TxoSealError::from)
        } else {
            Err(TxoSealError::NoTapretProof)
        }
    }
}

impl ClientSideWitness for Anchor {
    type Proof = Proof;
    type Seal = TxoSeal;
    type Error = AnchorError;

    fn convolve_commit(&self, mmb_message: mmb::Message) -> Result<Proof, Self::Error> {
        self.verify_fallback()?;
        if self.mmb_proof.map.values().all(|msg| *msg != mmb_message) {
            return Err(AnchorError::Mmb(mmb_message));
        }
        let bundle_id = self.mmb_proof.commit_id();
        let mpc_message = mpc::Message::from_byte_array(bundle_id.to_byte_array());
        let mpc_commit = self.mpc_proof.convolve(self.mpc_protocol, mpc_message)?;
        Ok(Proof {
            mpc_commit,
            dbc_proof: self.dbc_proof.clone(),
        })
    }

    fn merge(&mut self, other: Self) -> Result<(), impl Error>
    where Self: Sized {
        if self.mpc_protocol != other.mpc_protocol
            || self.mpc_proof != other.mpc_proof
            || self.dbc_proof != other.dbc_proof
            || self.fallback_proof != other.fallback_proof
            || self.mmb_proof != other.mmb_proof
        {
            return Err(AnchorMergeError::AnchorMismatch);
        }
        Ok(())
    }
}

/// Errors verifying Txo-based single use seal closing with a provided witness, under [`TxoSeal`]
/// implementation of [`SingleUseSeals`] protocol.
#[derive(Clone, PartialEq, Eq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum TxoSealError {
    /// witness transaction contains no taproot or OP_RETURN output.
    NoOutput,

    /// the first witness transaction DBC-compatible output does not match the provided proof type.
    InvalidProofType,

    /// the first witness transaction DBC-compatible output is taproot, but no tapret proof is
    /// provided.
    NoTapretProof,

    #[from]
    /// invalid tapret commitment.
    Tapret(ConvolveVerifyError),

    #[from]
    /// invalid opret commitment.
    Opret(EmbedVerifyError<OpretError>),
}

/// Error merging information from multiple anchors for the same witness (see [`Anchor::merge`]).
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum AnchorMergeError {
    /// anchor mismatch in the merge procedure
    AnchorMismatch,

    /// anchor is invalid: too many inputs
    TooManyInputs,
}

/// An error involving [`Anchor`] into a final [`Proof`] for the single-use seal published witness
/// verification.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, Display, Error, From)]
#[display(inner)]
pub enum AnchorError {
    /// Invalid multiprotocol commitment proof (see [`commit_verify::mpc`]).
    #[from]
    Mpc(mpc::InvalidProof),

    /// Invalid multiprotocol bundle (see [`mmb`]).
    #[display("message {0} is not part of the anchor")]
    Mmb(mmb::Message),
}

#[cfg(test)]
mod test {
    #![cfg_attr(coverage_nightly, coverage(off))]

    use amplify::confinement::{Confined, SmallOrdMap};
    use amplify::num::u5;
    use bc::secp256k1::{SecretKey, SECP256K1};
    use bc::{InternalPk, Sats, ScriptPubkey, SeqNo, TapLeafHash, TapScript, TxIn, TxOut, Vout};
    use commit_verify::{CommitVerify, Digest};
    use dbc::tapret::{TapretCommitment, TapretPathProof};
    use single_use_seals::SealError;

    use super::*;
    use crate::mmb::BundleProof;
    use crate::mpc::{MessageMap, MessageSource};
    use crate::TxoSealError;

    fn setup_opret() -> (Vec<mmb::Message>, BundleProof, Vec<TxoSeal>, SealWitness<TxoSeal>) {
        setup(false)
    }

    fn setup_tapret() -> (Vec<mmb::Message>, BundleProof, Vec<TxoSeal>, SealWitness<TxoSeal>) {
        setup(true)
    }

    fn setup(tapret: bool) -> (Vec<mmb::Message>, BundleProof, Vec<TxoSeal>, SealWitness<TxoSeal>) {
        // Construct messages
        let mut msg = [0u8; 32];
        let messages = (0u8..=13)
            .map(|no| {
                msg[0] = no;
                mmb::Message::from_byte_array(msg)
            })
            .collect::<Vec<_>>();

        // Construct bundle proof
        let mut bundle = mmb::BundleProof {
            map: SmallOrdMap::from_iter_checked(
                messages.iter().enumerate().map(|(i, msg)| (i as u32, *msg)),
            ),
        };
        // Make message No 12 equal to 11, so messsage no 12 is not used
        bundle.map.insert(12, messages[11]).unwrap();

        // Construct seals
        let noise_engine = Sha256::new_with_prefix("test");
        let outpoints = messages
            .iter()
            .map(|msg| Outpoint::new(Txid::from_byte_array(msg.to_byte_array()), msg[0] as u32))
            .collect::<Vec<_>>();
        let seals = outpoints
            .iter()
            .enumerate()
            .map(|(no, outpoint)| {
                let wout = if no % 2 == 0 {
                    WOutpoint::Extern(*outpoint)
                } else {
                    WOutpoint::Wout(Vout::from(no as u32))
                };
                TxoSeal {
                    primary: *outpoint,
                    secondary: TxoSealExt::Noise(Noise::with(
                        wout,
                        noise_engine.clone(),
                        outpoint.txid[0] as u64,
                    )),
                }
            })
            .collect::<Vec<_>>();

        let protocol = mpc::ProtocolId::from_byte_array([0xADu8; 32]);
        let msg_sources = MessageSource::Mmb(bundle.clone());
        let source = mpc::Source {
            min_depth: u5::with(3),
            entropy: 0xFE,
            messages: MessageMap::from(Confined::from_checked(bmap! { protocol => msg_sources })),
        };
        let merkle_tree = source.into_merkle_tree().unwrap();
        let merkle_proofs = merkle_tree.clone().into_proofs().collect::<Vec<_>>();
        assert_eq!(merkle_proofs.len(), 1);
        assert_eq!(merkle_proofs[0].0, protocol);

        // Tapret
        let nonce = 0;
        let tapret_commitment = TapretCommitment::with(merkle_tree.commit_id(), nonce);
        let script_commitment = TapScript::commit(&tapret_commitment);
        let secret = SecretKey::from_byte_array(&[0x66; 32]).unwrap();
        let internal_pk = InternalPk::from(secret.x_only_public_key(SECP256K1).0);
        let tapret_proof = TapretProof {
            path_proof: TapretPathProof::root(nonce),
            internal_pk,
        };

        let merkle_proof = merkle_proofs[0].1.clone();
        let anchor = Anchor {
            mmb_proof: bundle.clone(),
            mpc_protocol: protocol,
            mpc_proof: merkle_proof,
            dbc_proof: if tapret { Some(tapret_proof) } else { None },
            fallback_proof: none!(),
        };

        // Construct a witness transaction
        let mpc = merkle_tree.commit_id();
        let tx = Tx {
            version: default!(),
            inputs: Confined::from_iter_checked(messages.iter().map(|msg| TxIn {
                prev_output: outpoints[msg[0] as usize],
                sig_script: none!(),
                sequence: SeqNo::ZERO,
                witness: none!(),
            })),
            outputs: Confined::from_checked(vec![TxOut {
                value: Sats::ZERO,
                script_pubkey: if tapret {
                    ScriptPubkey::p2tr(
                        internal_pk,
                        Some(TapLeafHash::with_leaf_script(&script_commitment.into()).into()),
                    )
                } else {
                    ScriptPubkey::op_return(mpc.as_slice())
                },
            }]),
            lock_time: default!(),
        };
        let witness = SealWitness::new(tx, anchor);

        (messages, bundle, seals, witness)
    }

    #[test]
    fn valid_oprets() {
        let (messages, bundle, seals, witness) = setup_opret();

        for seal in seals {
            let outpoint = seal.primary;
            let pos = outpoint.txid[0] as usize;
            if pos == 12 {
                assert!(!bundle.verify(outpoint, messages[pos], &witness.published));
                assert!(bundle.verify(outpoint, messages[11], &witness.published));

                assert!(!seal.is_included(messages[pos], &witness));
                witness.verify_seal_closing(seal, messages[pos]).unwrap_err();

                assert!(seal.is_included(messages[11], &witness));
                witness.verify_seal_closing(seal, messages[11]).unwrap();
            } else {
                assert!(bundle.verify(outpoint, messages[pos], &witness.published));
                assert!(seal.is_included(messages[pos], &witness));
                witness.verify_seal_closing(seal, messages[pos]).unwrap();
            }
        }
    }
    #[test]
    fn valid_taprets() {
        let (messages, bundle, seals, witness) = setup_tapret();

        for seal in seals {
            let outpoint = seal.primary;
            let pos = outpoint.txid[0] as usize;
            if pos == 12 {
                assert!(!bundle.verify(outpoint, messages[pos], &witness.published));
                assert!(bundle.verify(outpoint, messages[11], &witness.published));

                assert!(!seal.is_included(messages[pos], &witness));
                witness.verify_seal_closing(seal, messages[pos]).unwrap_err();

                assert!(seal.is_included(messages[11], &witness));
                witness.verify_seal_closing(seal, messages[11]).unwrap();
            } else {
                assert!(bundle.verify(outpoint, messages[pos], &witness.published));
                assert!(seal.is_included(messages[pos], &witness));
                witness.verify_seal_closing(seal, messages[pos]).unwrap();
            }
        }
    }

    #[test]
    fn invalid_dbc_type() {
        let (messages, _bundle, seals, mut witness) = setup_tapret();
        let tapret = witness.client.dbc_proof;
        witness.client.dbc_proof = None;
        assert!(matches!(
            witness.verify_seal_closing(seals[2], messages[2]).unwrap_err(),
            SealError::Published(TxoSealError::NoTapretProof)
        ));

        let (messages, _bundle, seals, mut witness) = setup_opret();
        witness.client.dbc_proof = tapret;
        assert!(matches!(
            witness.verify_seal_closing(seals[2], messages[2]).unwrap_err(),
            SealError::Published(TxoSealError::InvalidProofType)
        ));
    }

    #[test]
    fn mmb_absent_input() {
        let (messages, bundle, _seals, witness) = setup_opret();

        let fake_outpoint = Outpoint::new(Txid::from_byte_array([0x13; 32]), 12);
        assert!(!bundle.verify(fake_outpoint, messages[0], &witness.published));
    }

    #[test]
    fn mmb_uncommited_msg() {
        let (messages, mut bundle, seals, witness) = setup_opret();

        // a non-committed message
        bundle.map.remove(&13).unwrap();
        assert!(!bundle.verify(seals[13].primary, messages[13], &witness.published));
    }

    #[test]
    fn fallback_seal() {
        let (messages, _bundle, mut seals, witness) = setup_opret();

        seals[1].secondary = TxoSealExt::Fallback(seals[2].primary);
        witness.verify_seal_closing(seals[1], messages[1]).unwrap();
        assert!(seals[1].is_included(messages[1], &witness));
        // And not a wrong message
        assert!(!seals[1].is_included(messages[2], &witness));
    }

    #[test]
    fn anchor_merge() {
        let (_, _, _, mut witness) = setup_opret();
        witness.client.merge(witness.client.clone()).unwrap();

        let mut other = witness.client.clone();
        other.mpc_protocol = mpc::ProtocolId::from_byte_array([0x13u8; 32]);
        witness.client.merge(other).unwrap_err();
    }
}
