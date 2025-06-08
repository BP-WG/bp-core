// Bitcoin protocol consensus library.
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

use std::borrow::Borrow;

use amplify::{Bytes32, IoError};
use commit_verify::{Digest, DigestExt, Sha256};

use crate::{
    Annex, ConsensusEncode, Sats, ScriptCode, ScriptPubkey, SeqNo, SigScript, Sighash, SighashFlag,
    SighashType, TapLeafHash, TapSighash, Tx as Transaction, TxIn, TxOut, Txid, VarIntArray,
};

/// Used for signature hash for invalid use of SIGHASH_SINGLE.
const UINT256_ONE: [u8; 32] = [
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

#[derive(Copy, Clone, Eq, PartialEq, Debug, Display, Error)]
#[display(
    "number of inputs ({inputs}) doesn't match to the number of provided prevouts ({prevouts}) \
     for signature hasher on tx {txid}."
)]
pub struct PrevoutMismatch {
    txid: Txid,
    inputs: usize,
    prevouts: usize,
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, Display, Error)]
#[display(doc_comments)]
pub enum SighashError {
    /// invalid input index {index} in {txid} which has only {inputs} inputs.
    InvalidInputIndex {
        txid: Txid,
        index: usize,
        inputs: usize,
    },

    /// transaction {txid} input {index} uses SIGHASH_SINGLE, but the total
    /// number of outputs is {outputs} and thus no signature can be produced.
    NoSingleOutputMatch {
        txid: Txid,
        index: usize,
        outputs: usize,
    },
}

impl From<IoError> for SighashError {
    fn from(_: IoError) -> Self { unreachable!("in-memory I/O doesn't error in Rust") }
}

/// Efficiently calculates signature hash message for legacy, segwit and taproot
/// inputs.
#[derive(Debug)]
pub struct SighashCache<Prevout: Borrow<TxOut> = TxOut, Tx: Borrow<Transaction> = Transaction> {
    /// Access to transaction required for transaction introspection.
    tx: Tx,

    prevouts: Vec<Prevout>,

    /// Common cache for taproot and segwit inputs, `None` for legacy inputs.
    common_cache: Option<CommonCache>,

    /// Cache for segwit v0 inputs (the result of another round of sha256 on
    /// `common_cache`).
    segwit_cache: Option<SegwitCache>,

    /// Cache for taproot v1 inputs.
    taproot_cache: Option<TaprootCache>,
}

/// Common values cached between segwit and taproot inputs.
#[derive(Copy, Clone, Debug)]
struct CommonCache {
    prevouts: Bytes32,
    sequences: Bytes32,

    /// In theory `outputs` could be an `Option` since `SIGHASH_NONE` and
    /// `SIGHASH_SINGLE` do not need it, but since `SIGHASH_ALL` is by far
    /// the most used variant we don't bother.
    outputs: Bytes32,
}

/// Values cached for segwit inputs, equivalent to [`CommonCache`] plus another
/// round of `sha256`.
#[derive(Copy, Clone, Debug)]
struct SegwitCache {
    prevouts: Bytes32,
    sequences: Bytes32,
    outputs: Bytes32,
}

/// Values cached for taproot inputs.
#[derive(Copy, Clone, Debug)]
struct TaprootCache {
    amounts: Bytes32,
    script_pubkeys: Bytes32,
}

impl<Prevout: Borrow<TxOut>, Tx: Borrow<Transaction>> SighashCache<Prevout, Tx> {
    /// Constructs a new `SighashCache` from an unsigned transaction.
    ///
    /// The sighash components are computed in a lazy manner when required. For
    /// the generated sighashes to be valid, no fields in the transaction
    /// may change except for script_sig and witness.
    pub fn new(tx: Tx, prevouts: Vec<Prevout>) -> Result<Self, PrevoutMismatch> {
        if tx.borrow().inputs.len() != prevouts.len() {
            return Err(PrevoutMismatch {
                txid: tx.borrow().txid(),
                inputs: tx.borrow().inputs.len(),
                prevouts: prevouts.len(),
            });
        }

        Ok(SighashCache {
            tx,
            prevouts,
            common_cache: None,
            taproot_cache: None,
            segwit_cache: None,
        })
    }

    /// Computes the BIP341 sighash for any type with a fine-grained control
    /// over annex and code separator.
    pub fn tap_sighash_custom(
        &mut self,
        input_index: usize,
        annex: Option<Annex>,
        leaf_hash_code_separator: Option<(TapLeafHash, u32)>,
        sighash_type: Option<SighashType>,
    ) -> Result<TapSighash, SighashError> {
        let mut hasher = TapSighash::engine();

        let SighashType {
            flag: sighash_flag,
            anyone_can_pay,
        } = sighash_type.unwrap_or_default();

        // epoch
        0u8.consensus_encode(&mut hasher)?;

        // * Control:
        // hash_type (1).
        match sighash_type {
            None => 0u8.consensus_encode(&mut hasher)?,
            Some(sighash_type) => sighash_type.to_consensus_u8().consensus_encode(&mut hasher)?,
        };

        {
            let tx = self.tx.borrow();
            // * Transaction Data:
            // nVersion (4): the nVersion of the transaction.
            tx.version.consensus_encode(&mut hasher)?;

            // nLockTime (4): the nLockTime of the transaction.
            tx.lock_time.consensus_encode(&mut hasher)?;
        }

        // If the hash_type & 0x80 does not equal SIGHASH_ANYONECANPAY:
        //     sha_prevouts (32): the SHA256 of the serialization of all input
        // outpoints.     sha_amounts (32): the SHA256 of the serialization of
        // all spent output amounts.     sha_scriptpubkeys (32): the SHA256 of
        // the serialization of all spent output scriptPubKeys.
        // sha_sequences (32): the SHA256 of the serialization of all
        // input nSequence.
        if !anyone_can_pay {
            self.common_cache().prevouts.consensus_encode(&mut hasher)?;
            self.taproot_cache().amounts.consensus_encode(&mut hasher)?;
            self.taproot_cache().script_pubkeys.consensus_encode(&mut hasher)?;
            self.common_cache().sequences.consensus_encode(&mut hasher)?;
        }

        // If hash_type & 3 does not equal SIGHASH_NONE or SIGHASH_SINGLE:
        //     sha_outputs (32): the SHA256 of the serialization of all outputs in
        // CTxOut format.
        if sighash_flag != SighashFlag::None && sighash_flag != SighashFlag::Single {
            self.common_cache().outputs.consensus_encode(&mut hasher)?;
        }

        // * Data about this input:
        // spend_type (1): equal to (ext_flag * 2) + annex_present, where annex_present
        // is 0 if no annex is present, or 1 otherwise
        let mut spend_type = 0u8;
        if annex.is_some() {
            spend_type |= 1u8;
        }
        if leaf_hash_code_separator.is_some() {
            spend_type |= 2u8;
        }
        spend_type.consensus_encode(&mut hasher)?;

        let tx = self.tx.borrow();

        // If hash_type & 0x80 equals SIGHASH_ANYONECANPAY:
        //      outpoint (36): the COutPoint of this input (32-byte hash + 4-byte
        // little-endian).      amount (8): value of the previous output spent
        // by this input.      scriptPubKey (35): scriptPubKey of the previous
        // output spent by this input, serialized as script inside CTxOut. Its
        // size is always 35 bytes.      nSequence (4): nSequence of this input.
        if anyone_can_pay {
            let txin = tx.inputs.get(input_index).ok_or(SighashError::InvalidInputIndex {
                txid: tx.txid(),
                index: input_index,
                inputs: tx.inputs.len(),
            })?;
            let previous_output = self.prevouts[input_index].borrow();
            txin.prev_output.consensus_encode(&mut hasher)?;
            previous_output.value.consensus_encode(&mut hasher)?;
            previous_output.script_pubkey.consensus_encode(&mut hasher)?;
            txin.sequence.consensus_encode(&mut hasher)?;
        } else {
            (input_index as u32).consensus_encode(&mut hasher)?;
        }

        // If an annex is present (the lowest bit of spend_type is set):
        //      sha_annex (32): the SHA256 of (compact_size(size of annex) || annex),
        // where annex      includes the mandatory 0x50 prefix.
        if let Some(annex) = annex {
            let mut enc = Sha256::default();
            annex.consensus_encode(&mut enc)?;
            let hash = enc.finish();
            hash.consensus_encode(&mut hasher)?;
        }

        // * Data about this output:
        // If hash_type & 3 equals SIGHASH_SINGLE:
        //      sha_single_output (32): the SHA256 of the corresponding output in CTxOut
        // format.
        if sighash_flag == SighashFlag::Single {
            let mut enc = Sha256::default();
            tx.outputs
                .get(input_index)
                .ok_or(SighashError::NoSingleOutputMatch {
                    txid: tx.txid(),
                    index: input_index,
                    outputs: tx.outputs.len(),
                })?
                .consensus_encode(&mut enc)?;
            let hash = enc.finish();
            hash.consensus_encode(&mut hasher)?;
        }

        //     if (scriptpath):
        //         ss += TaggedHash("TapLeaf", bytes([leaf_ver]) + ser_string(script))
        //         ss += bytes([0])
        //         ss += struct.pack("<i", codeseparator_pos)
        if let Some((hash, code_separator_pos)) = leaf_hash_code_separator {
            hash.consensus_encode(&mut hasher)?;
            0u8.consensus_encode(&mut hasher)?;
            code_separator_pos.consensus_encode(&mut hasher)?;
        }

        Ok(TapSighash::from_engine(hasher))
    }

    /// Computes the BIP341 sighash for a key spend.
    pub fn tap_sighash_key(
        &mut self,
        input_index: usize,
        sighash_type: Option<SighashType>,
    ) -> Result<TapSighash, SighashError> {
        self.tap_sighash_custom(input_index, None, None, sighash_type)
    }

    /// Computes the BIP341 sighash for a script spend.
    ///
    /// Assumes the default `OP_CODESEPARATOR` position of `0xFFFFFFFF`.
    pub fn tap_sighash_script(
        &mut self,
        input_index: usize,
        leaf_hash: impl Into<TapLeafHash>,
        sighash_type: Option<SighashType>,
    ) -> Result<TapSighash, SighashError> {
        self.tap_sighash_custom(
            input_index,
            None,
            Some((leaf_hash.into(), 0xFFFFFFFF)),
            sighash_type,
        )
    }

    /// Computes the BIP143 sighash for any flag type.
    pub fn segwit_sighash(
        &mut self,
        input_index: usize,
        script_code: &ScriptCode,
        value: Sats,
        sighash_type: SighashType,
    ) -> Result<Sighash, SighashError> {
        let mut hasher = Sighash::engine();

        let zero_hash = [0u8; 32];

        let SighashType {
            flag: sighash_flag,
            anyone_can_pay,
        } = sighash_type;

        self.tx.borrow().version.consensus_encode(&mut hasher)?;

        if !anyone_can_pay {
            self.segwit_cache().prevouts.consensus_encode(&mut hasher)?;
        } else {
            zero_hash.consensus_encode(&mut hasher)?;
        }

        if !anyone_can_pay
            && sighash_flag != SighashFlag::Single
            && sighash_flag != SighashFlag::None
        {
            self.segwit_cache().sequences.consensus_encode(&mut hasher)?;
        } else {
            zero_hash.consensus_encode(&mut hasher)?;
        }

        {
            let tx = self.tx.borrow();
            let txin = tx.inputs.get(input_index).ok_or(SighashError::InvalidInputIndex {
                txid: tx.txid(),
                index: input_index,
                inputs: tx.inputs.len(),
            })?;

            txin.prev_output.consensus_encode(&mut hasher)?;
            script_code.consensus_encode(&mut hasher)?;
            value.consensus_encode(&mut hasher)?;
            txin.sequence.consensus_encode(&mut hasher)?;
        }

        if sighash_flag != SighashFlag::Single && sighash_flag != SighashFlag::None {
            self.segwit_cache().outputs.consensus_encode(&mut hasher)?;
        } else if sighash_flag == SighashFlag::Single
            && input_index < self.tx.borrow().outputs.len()
        {
            let mut single_enc = Sighash::engine();
            self.tx.borrow().outputs[input_index].consensus_encode(&mut single_enc)?;
            Sighash::from_engine(single_enc).consensus_encode(&mut hasher)?;
        } else {
            zero_hash.consensus_encode(&mut hasher)?;
        }

        self.tx.borrow().lock_time.consensus_encode(&mut hasher)?;
        sighash_type.to_consensus_u32().consensus_encode(&mut hasher)?;

        Ok(Sighash::from_engine(hasher))
    }

    /// Computes the legacy sighash for any `sighash_type`.
    pub fn legacy_sighash(
        &self,
        input_index: usize,
        script_pubkey: &ScriptPubkey,
        sighash_type: SighashType,
    ) -> Result<Sighash, SighashError> {
        let tx_src = self.tx.borrow();
        let mut hasher = Sighash::engine();

        if input_index >= tx_src.inputs.len() {
            return Err(SighashError::InvalidInputIndex {
                txid: tx_src.txid(),
                index: input_index,
                inputs: tx_src.inputs.len(),
            });
        }

        let SighashType {
            flag: sighash_flag,
            anyone_can_pay,
        } = sighash_type;

        if sighash_flag == SighashFlag::Single && input_index >= tx_src.outputs.len() {
            return Ok(Sighash::from(UINT256_ONE));
        }

        // Build tx to sign
        let mut tx = Transaction {
            version: tx_src.version,
            lock_time: tx_src.lock_time,
            inputs: none!(),
            outputs: none!(),
        };

        // Add all necessary inputs...
        let sig_script = script_pubkey.as_script_bytes().clone().into();
        if anyone_can_pay {
            tx.inputs = VarIntArray::from_checked(vec![TxIn {
                prev_output: tx_src.inputs[input_index].prev_output,
                sig_script,
                sequence: tx_src.inputs[input_index].sequence,
                witness: none!(),
            }]);
        } else {
            let inputs = tx_src.inputs.iter().enumerate().map(|(n, input)| TxIn {
                prev_output: input.prev_output,
                sig_script: if n == input_index { sig_script.clone() } else { SigScript::new() },
                sequence: if n != input_index
                    && (sighash_flag == SighashFlag::Single || sighash_flag == SighashFlag::None)
                {
                    SeqNo::ZERO
                } else {
                    input.sequence
                },
                witness: none!(),
            });
            tx.inputs = VarIntArray::from_iter_checked(inputs);
        }
        // ...then all outputs
        tx.outputs = match sighash_flag {
            SighashFlag::All => tx_src.outputs.clone(),
            SighashFlag::Single => {
                let outputs = tx_src.outputs.iter()
                    .take(input_index + 1)  // sign all outputs up to and including this one, but erase
                    .enumerate()            // all of them except for this one
                    .map(|(n, out)| if n == input_index {
                        out.clone()
                    } else {
                        // consensus encoding of the "NULL txout" - max amount, empty script_pubkey
                        TxOut { value: Sats::MAX, script_pubkey: none!() }
                    });
                VarIntArray::from_iter_checked(outputs)
            }
            SighashFlag::None => none!(),
        };
        // hash the result
        tx.consensus_encode(&mut hasher)?;
        sighash_type.to_consensus_u32().consensus_encode(&mut hasher)?;

        Ok(Sighash::from_engine(hasher))
    }

    fn common_cache(&mut self) -> &CommonCache {
        let tx = self.tx.borrow();
        self.common_cache.get_or_insert_with(|| {
            let mut enc_prevouts = Sha256::default();
            let mut enc_sequences = Sha256::default();
            for txin in &tx.inputs {
                let _ = txin.prev_output.consensus_encode(&mut enc_prevouts);
                let _ = txin.sequence.consensus_encode(&mut enc_sequences);
            }
            let mut enc_outputs = Sha256::default();
            for txout in &tx.outputs {
                let _ = txout.consensus_encode(&mut enc_outputs);
            }
            CommonCache {
                prevouts: enc_prevouts.finish().into(),
                sequences: enc_sequences.finish().into(),
                outputs: enc_outputs.finish().into(),
            }
        })
    }

    fn segwit_cache(&mut self) -> &SegwitCache {
        let common_cache = *self.common_cache();
        self.segwit_cache.get_or_insert_with(|| SegwitCache {
            prevouts: <[u8; 32]>::from(Sha256::digest(common_cache.prevouts)).into(),
            sequences: <[u8; 32]>::from(Sha256::digest(common_cache.sequences)).into(),
            outputs: <[u8; 32]>::from(Sha256::digest(common_cache.outputs)).into(),
        })
    }

    fn taproot_cache(&mut self) -> &TaprootCache {
        self.taproot_cache.get_or_insert_with(|| {
            let mut enc_amounts = Sha256::default();
            let mut enc_script_pubkeys = Sha256::default();
            for prevout in &self.prevouts {
                let _ = prevout.borrow().value.consensus_encode(&mut enc_amounts);
                let _ = prevout.borrow().script_pubkey.consensus_encode(&mut enc_script_pubkeys);
            }
            TaprootCache {
                amounts: enc_amounts.finish().into(),
                script_pubkeys: enc_script_pubkeys.finish().into(),
            }
        })
    }
}
