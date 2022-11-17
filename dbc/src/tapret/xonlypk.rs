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

use bitcoin::hashes::Hash;
use bitcoin::schnorr::{TapTweak, TweakedPublicKey, UntweakedPublicKey};
use bitcoin::util::taproot::TapBranchHash;
use bitcoin_scripts::taproot::{Node, TreeNode};
use bitcoin_scripts::TapScript;
use commit_verify::convolve_commit::{ConvolveCommit, ConvolveCommitProof};
use commit_verify::{lnpbp4, CommitVerify};
use secp256k1::SECP256K1;

use super::{Lnpbp6, TapretPathProof, TapretProof, TapretTreeError};

impl ConvolveCommitProof<lnpbp4::CommitmentHash, UntweakedPublicKey, Lnpbp6>
    for TapretProof
{
    type Suppl = TapretPathProof;

    fn restore_original(&self, _: &TweakedPublicKey) -> UntweakedPublicKey {
        self.internal_key
    }

    fn extract_supplement(&self) -> &Self::Suppl { &self.path_proof }
}

impl ConvolveCommit<lnpbp4::CommitmentHash, TapretProof, Lnpbp6>
    for UntweakedPublicKey
{
    type Commitment = TweakedPublicKey;
    type CommitError = TapretTreeError;

    fn convolve_commit(
        &self,
        supplement: &TapretPathProof,
        msg: &lnpbp4::CommitmentHash,
    ) -> Result<(TweakedPublicKey, TapretProof), Self::CommitError> {
        let script_commitment = TapScript::commit(&(*msg, supplement.nonce));

        let root = if let Some(ref partner) = supplement.partner_node {
            if !partner.check_no_commitment() {
                return Err(TapretTreeError::AlternativeCommitment(
                    partner.clone(),
                ));
            }

            let commitment_node =
                TreeNode::with_tap_script(script_commitment, 1);

            if !partner.check_ordering(commitment_node.node_hash()) {
                return Err(TapretTreeError::IncorrectOrdering(
                    partner.clone(),
                    commitment_node,
                ));
            }

            TreeNode::with_branch(commitment_node, partner.to_tree_node(), 0)
        } else {
            TreeNode::with_tap_script(script_commitment, 0)
        };

        // rust-bitcoin API has this inefficiency: while `TapLeafHash` can be
        // a valid merkle root (for script trees with a single leaf), it is not
        // accepted by the tap_tweak API.
        //
        // Details: <https://github.com/rust-bitcoin/rust-bitcoin/issues/1393>
        let merkle_root =
            TapBranchHash::from_inner(root.node_hash().into_inner());
        // TODO: Use secp instance from Lnpbp6
        let (output_key, _parity_not_used) =
            self.tap_tweak(SECP256K1, Some(merkle_root));

        let proof = TapretProof {
            path_proof: supplement.clone(),
            internal_key: *self,
        };

        Ok((output_key, proof))
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use amplify::Wrapper;
    use bitcoin::hashes::Hash;
    use bitcoin_scripts::LeafScript;
    use commit_verify::lnpbp4::CommitmentHash;
    use secp256k1::XOnlyPublicKey;

    use super::*;
    use crate::tapret::TapretNodePartner;

    #[test]
    fn key_path() {
        let internal_key = XOnlyPublicKey::from_str(
            "c5f93479093e2b8f724a79844cc10928dd44e9a390b539843fb83fbf842723f3",
        )
        .unwrap();
        let msg = CommitmentHash::from_inner(Hash::hash(b""));
        let path_proof = TapretPathProof::new();

        let (outer_key, proof) =
            internal_key.convolve_commit(&path_proof, &msg).unwrap();

        let script_commitment = TapScript::commit(&(msg, 0));
        let root = TreeNode::with_tap_script(script_commitment, 0);
        let merkle_root =
            TapBranchHash::from_inner(root.node_hash().into_inner());
        let (real_key, _) =
            internal_key.tap_tweak(SECP256K1, Some(merkle_root));

        assert_eq!(outer_key, real_key);

        assert_eq!(proof, TapretProof {
            path_proof,
            internal_key
        });

        assert!(ConvolveCommitProof::<
            CommitmentHash,
            UntweakedPublicKey,
            Lnpbp6,
        >::verify(&proof, &msg, outer_key)
        .unwrap());
    }

    #[test]
    fn single_script() {
        let internal_key = XOnlyPublicKey::from_str(
            "c5f93479093e2b8f724a79844cc10928dd44e9a390b539843fb83fbf842723f3",
        )
        .unwrap();
        let msg = CommitmentHash::from_inner(Hash::hash(b""));
        let path_proof = TapretPathProof::with(
            TapretNodePartner::RightLeaf(LeafScript::tapscript(default!())),
            88,
        )
        .unwrap();

        let (outer_key, proof) =
            internal_key.convolve_commit(&path_proof, &msg).unwrap();

        assert_eq!(proof, TapretProof {
            path_proof,
            internal_key
        });

        assert!(ConvolveCommitProof::<
            CommitmentHash,
            UntweakedPublicKey,
            Lnpbp6,
        >::verify(&proof, &msg, outer_key)
        .unwrap());
    }

    #[test]
    #[should_panic(expected = "IncorrectOrdering")]
    fn invalid_partner_ordering() {
        let internal_key = XOnlyPublicKey::from_str(
            "c5f93479093e2b8f724a79844cc10928dd44e9a390b539843fb83fbf842723f3",
        )
        .unwrap();
        let msg = CommitmentHash::from_inner(Hash::hash(b""));
        let path_proof = TapretPathProof::with(
            TapretNodePartner::RightLeaf(LeafScript::tapscript(default!())),
            1,
        )
        .unwrap();

        let (outer_key, proof) =
            internal_key.convolve_commit(&path_proof, &msg).unwrap();

        assert_eq!(proof, TapretProof {
            path_proof,
            internal_key
        });

        assert!(ConvolveCommitProof::<
            CommitmentHash,
            UntweakedPublicKey,
            Lnpbp6,
        >::verify(&proof, &msg, outer_key)
        .unwrap());
    }
}
