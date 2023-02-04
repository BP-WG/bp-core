// Deterministic bitcoin commitments library, implementing LNPBP standards
// Part of bitcoin protocol core library (BP Core Lib)
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

use bc::{InternalPk, TapBranchHash, TapLeafHash, TapNodeHash, TapScript};
use commit_verify::{mpc, CommitVerify, ConvolveCommit, ConvolveCommitProof};
use secp256k1::XOnlyPublicKey;

use super::{Lnpbp12, TapretNodePartner, TapretPathProof, TapretProof};
use crate::tapret::tapscript::TapretCommitment;

/// Errors during tapret commitment embedding into x-only public key.
#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum TapretKeyError {
    /// tapret node partner {0} contains alternative commitment
    AlternativeCommitment(TapretNodePartner),

    /// tapret node partner {0} has an invalid order with the commitment node
    /// {1}
    IncorrectOrdering(TapretNodePartner, TapLeafHash),
}

impl ConvolveCommitProof<mpc::Commitment, InternalPk, Lnpbp12> for TapretProof {
    type Suppl = TapretPathProof;

    fn restore_original(&self, _: &XOnlyPublicKey) -> InternalPk {
        self.internal_pk
    }

    fn extract_supplement(&self) -> &Self::Suppl { &self.path_proof }
}

impl ConvolveCommit<mpc::Commitment, TapretProof, Lnpbp12> for InternalPk {
    type Commitment = XOnlyPublicKey;
    type CommitError = TapretKeyError;

    fn convolve_commit(
        &self,
        supplement: &TapretPathProof,
        msg: &mpc::Commitment,
    ) -> Result<(XOnlyPublicKey, TapretProof), Self::CommitError> {
        let tapret_commitment = TapretCommitment::with(*msg, supplement.nonce);
        let script_commitment = TapScript::commit(&tapret_commitment);

        let merkle_root: TapNodeHash = if let Some(ref partner) =
            supplement.partner_node
        {
            if !partner.check_no_commitment() {
                return Err(TapretKeyError::AlternativeCommitment(
                    partner.clone(),
                ));
            }

            let commitment_leaf =
                TapLeafHash::with_tap_script(&script_commitment);
            let commitment_hash = TapNodeHash::from(commitment_leaf);

            if !partner.check_ordering(commitment_hash) {
                return Err(TapretKeyError::IncorrectOrdering(
                    partner.clone(),
                    commitment_leaf,
                ));
            }

            TapBranchHash::with_nodes(commitment_hash, partner.tap_node_hash())
                .into()
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
        let path_proof = TapretPathProof::root();

        // Do via API
        let (outer_key, proof) =
            internal_pk.convolve_commit(&path_proof, &msg).unwrap();

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
                &proof, &msg, outer_key
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
            TapretNodePartner::RightLeaf(LeafScript::from_tap_script(
                default!(),
            )),
            22,
        )
        .unwrap();

        let (outer_key, proof) =
            internal_pk.convolve_commit(&path_proof, &msg).unwrap();

        assert_eq!(proof, TapretProof {
            path_proof,
            internal_pk
        });

        assert!(
            ConvolveCommitProof::<Commitment, InternalPk, Lnpbp12>::verify(
                &proof, &msg, outer_key
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
            TapretNodePartner::RightLeaf(LeafScript::from_tap_script(
                default!(),
            )),
            11,
        )
        .unwrap();

        let (outer_key, proof) =
            internal_pk.convolve_commit(&path_proof, &msg).unwrap();

        assert_eq!(proof, TapretProof {
            path_proof,
            internal_pk
        });

        assert!(
            ConvolveCommitProof::<Commitment, InternalPk, Lnpbp12>::verify(
                &proof, &msg, outer_key
            )
            .unwrap()
        );
    }
}
