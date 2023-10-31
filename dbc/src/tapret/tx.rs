// Deterministic bitcoin commitments library.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2023 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2023 LNP/BP Standards Association. All rights reserved.
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

use bc::Tx;
use commit_verify::{mpc, ConvolveCommit, ConvolveCommitProof};

use super::{Lnpbp12, TapretKeyError, TapretProof};

/// Errors during tapret commitment.
#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub enum TapretError {
    /// Error embedding tapret commitment into x-only key.
    #[from]
    #[display(inner)]
    KeyEmbedding(TapretKeyError),

    /// tapret commitment in a transaction lacking any taproot outputs.
    #[display(doc_comments)]
    NoTaprootOutput,
}

impl ConvolveCommitProof<mpc::Commitment, Tx, Lnpbp12> for TapretProof {
    type Suppl = Self;

    fn restore_original(&self, commitment: &Tx) -> Tx {
        let mut tx = commitment.clone();

        for txout in &mut tx.outputs {
            if txout.script_pubkey.is_p2tr() {
                txout.script_pubkey = self.original_pubkey_script();
            }
        }
        tx
    }

    fn extract_supplement(&self) -> &Self::Suppl { self }
}

impl ConvolveCommit<mpc::Commitment, TapretProof, Lnpbp12> for Tx {
    type Commitment = Tx;
    type CommitError = TapretError;

    fn convolve_commit(
        &self,
        supplement: &TapretProof,
        msg: &mpc::Commitment,
    ) -> Result<(Tx, TapretProof), Self::CommitError> {
        let mut tx = self.clone();

        for txout in &mut tx.outputs {
            if txout.script_pubkey.is_p2tr() {
                let (commitment, proof) = txout
                    .convolve_commit(supplement, msg)
                    .map_err(TapretError::from)?;
                *txout = commitment;
                return Ok((tx, proof));
            }
        }

        Err(TapretError::NoTaprootOutput)
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use amplify::hex::FromHex;
    use amplify::Bytes32;
    use bc::InternalPk;
    use commit_verify::mpc::Commitment;
    use commit_verify::ConvolveVerifyError;
    use secp256k1::{ffi, XOnlyPublicKey};

    use super::*;
    use crate::tapret::TapretPathProof;

    #[test]
    fn no_commitment() {
        let tx = Tx::from_str(
            "020000000001027763e2a0ad25d45b63a19c33491b67c5037e72709121290bac5481a5d5d0c9330100000000ffffffff7763e2a0ad25d45b63a19c33491b67c5037e72709121290bac5481a5d5d0c9330400000000ffffffff02026e010000000000225120455dfcc062ef80609b007377f127e4abdb5cb0052158af1fab7aa628c34563f1d508000000000000225120a2788d4208ec6b4b600aef4c13075cf1d47bda0299ed1e6eedce4e7a90fb2a2c0141150df5377a34deded048dc01bff3d4f5f31d8a89fe2fbf1d0295993c1f899b3cefd1a63900ea6346b78edd476524c08ae094ff417bfa525b585ee66ebc26bb9e010141d959f21b498d90c2ff9f5b0bf3aee9158527501162eab2e3d56371714877a97df80caab15e366855aa56443b7d081c234a4ce4d6414815a874624cbe46b643370100000000"
        ).unwrap();

        let internal_pk: XOnlyPublicKey = unsafe {
            ffi::XOnlyPublicKey::from_array_unchecked(<[u8; 64]>::from_hex(
                "cb5271aa59fc637e29d034ec75363ca241fda5d3939684603b469b185be7e50f18ec6fd539e7dc1fd5fb4cf046d2cef5028a5ca0cdb09a252683e6a6eb2ad61d",
            ).unwrap()).into()
        };
        let proof = TapretProof {
            path_proof: TapretPathProof {
                partner_node: None,
                nonce: 0,
            },
            internal_pk: InternalPk::from(internal_pk),
        };

        let msg = Commitment::from(Bytes32::zero());
        assert_eq!(
            ConvolveCommitProof::<_, Tx, _>::verify(&proof, &msg, &tx),
            Err(ConvolveVerifyError::CommitmentMismatch)
        );
    }
}
