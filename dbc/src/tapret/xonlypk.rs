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

use bc::{InternalPk, OutputPk, TapBranchHash, TapLeafHash, TapNodeHash, TapScript};
use commit_verify::{mpc, CommitVerify, ConvolveCommit, ConvolveCommitProof};

use super::{Lnpbp12, TapretNodePartner, TapretPathProof, TapretProof};
use crate::tapret::tapscript::TapretCommitment;

/// Errors during tapret commitment embedding into x-only public key.
#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(doc_comments)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub enum TapretKeyError {
    /// tapret node partner {0} contains alternative commitment
    AlternativeCommitment(TapretNodePartner),

    /// tapret node partner {0} has an invalid order with the commitment node
    /// {1}
    IncorrectOrdering(TapretNodePartner, TapLeafHash),
}

impl ConvolveCommitProof<mpc::Commitment, InternalPk, Lnpbp12> for TapretProof {
    type Suppl = TapretPathProof;

    fn restore_original(&self, _: &OutputPk) -> InternalPk { self.internal_pk }

    fn extract_supplement(&self) -> &Self::Suppl { &self.path_proof }
}

impl ConvolveCommit<mpc::Commitment, TapretProof, Lnpbp12> for InternalPk {
    type Commitment = OutputPk;
    type CommitError = TapretKeyError;

    fn convolve_commit(
        &self,
        supplement: &TapretPathProof,
        msg: &mpc::Commitment,
    ) -> Result<(OutputPk, TapretProof), Self::CommitError> {
        let tapret_commitment = TapretCommitment::with(*msg, supplement.nonce);
        let script_commitment = TapScript::commit(&tapret_commitment);

        let merkle_root: TapNodeHash = if let Some(ref partner) = supplement.partner_node {
            if !partner.check_no_commitment() {
                return Err(TapretKeyError::AlternativeCommitment(partner.clone()));
            }

            let commitment_leaf = TapLeafHash::with_tap_script(&script_commitment);
            let commitment_hash = TapNodeHash::from(commitment_leaf);

            if !partner.check_ordering(commitment_hash) {
                return Err(TapretKeyError::IncorrectOrdering(partner.clone(), commitment_leaf));
            }

            TapBranchHash::with_nodes(commitment_hash, partner.tap_node_hash()).into()
        } else {
            TapLeafHash::with_tap_script(&script_commitment).into()
        };

        let output_key = self.to_output_key(Some(merkle_root));

        let proof = TapretProof {
            path_proof: supplement.clone(),
            internal_pk: *self,
        };

        Ok((output_key, proof))
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use bc::LeafScript;
    use commit_verify::mpc::Commitment;

    use super::*;
    use crate::tapret::TapretNodePartner;

    #[test]
    fn key_path() {
        let internal_pk = InternalPk::from_str(
            "c5f93479093e2b8f724a79844cc10928dd44e9a390b539843fb83fbf842723f3",
        )
        .unwrap();
        let msg = mpc::Commitment::from([8u8; 32]);
        let path_proof = TapretPathProof::root(0);

        // Do via API
        let (outer_key, proof) = internal_pk.convolve_commit(&path_proof, &msg).unwrap();

        // Do manually
        let tapret_commitment = TapretCommitment::with(msg, path_proof.nonce);
        let script_commitment = TapScript::commit(&tapret_commitment);
        let script_leaf = TapLeafHash::with_tap_script(&script_commitment);
        let real_key = internal_pk.to_output_key(Some(script_leaf));

        assert_eq!(outer_key, real_key);

        assert_eq!(proof, TapretProof {
            path_proof,
            internal_pk
        });

        assert!(
            ConvolveCommitProof::<Commitment, InternalPk, Lnpbp12>::verify(
                &proof, &msg, &outer_key
            )
            .unwrap()
        );
    }

    #[test]
    fn single_script() {
        let internal_pk = InternalPk::from_str(
            "c5f93479093e2b8f724a79844cc10928dd44e9a390b539843fb83fbf842723f3",
        )
        .unwrap();
        let msg = mpc::Commitment::from([8u8; 32]);
        let path_proof = TapretPathProof::with(
            TapretNodePartner::RightLeaf(LeafScript::from_tap_script(default!())),
            13,
        )
        .unwrap();

        let (outer_key, proof) = internal_pk.convolve_commit(&path_proof, &msg).unwrap();

        assert_eq!(proof, TapretProof {
            path_proof,
            internal_pk
        });

        assert!(
            ConvolveCommitProof::<Commitment, InternalPk, Lnpbp12>::verify(
                &proof, &msg, &outer_key
            )
            .unwrap()
        );
    }

    #[test]
    #[should_panic(expected = "IncorrectOrdering")]
    fn invalid_partner_ordering() {
        let internal_pk = InternalPk::from_str(
            "c5f93479093e2b8f724a79844cc10928dd44e9a390b539843fb83fbf842723f3",
        )
        .unwrap();
        let msg = mpc::Commitment::from([8u8; 32]);
        let path_proof = TapretPathProof::with(
            TapretNodePartner::RightLeaf(LeafScript::from_tap_script(default!())),
            11,
        )
        .unwrap();

        let (outer_key, proof) = internal_pk.convolve_commit(&path_proof, &msg).unwrap();

        assert_eq!(proof, TapretProof {
            path_proof,
            internal_pk
        });

        assert!(
            ConvolveCommitProof::<Commitment, InternalPk, Lnpbp12>::verify(
                &proof, &msg, &outer_key
            )
            .unwrap()
        );
    }
}
