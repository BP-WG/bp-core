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
use commit_verify::convolve_commit::{
    ConvolveCommitProof, ConvolveCommitVerify,
};
use commit_verify::{lnpbp4, CommitVerify};
use secp256k1::SECP256K1;

use super::{
    Lnpbp6, TapretNodePartner, TapretPathProof, TapretProof, TapretTreeError,
};

impl ConvolveCommitProof<lnpbp4::CommitmentHash, UntweakedPublicKey, Lnpbp6>
    for TapretProof
{
    type Suppl = TapretPathProof;

    fn restore_original(&self, _: &TweakedPublicKey) -> UntweakedPublicKey {
        self.internal_key
    }

    fn extract_supplement(&self) -> &Self::Suppl { &self.path_proof }
}

impl ConvolveCommitVerify<lnpbp4::CommitmentHash, TapretProof, Lnpbp6>
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
            if !partner.check() {
                return Err(TapretTreeError::AlternativeCommitment(
                    partner.clone(),
                ));
            }

            let commitment_node =
                TreeNode::with_tap_script(script_commitment, 1);
            let partner_node = match partner {
                TapretNodePartner::LeftNode(left_node) => {
                    TreeNode::Hidden(*left_node, 1)
                }
                TapretNodePartner::RightLeaf(leaf_script) => {
                    TreeNode::Leaf(leaf_script.clone(), 0)
                }
                TapretNodePartner::RightBranch(partner_branch) => {
                    TreeNode::Hidden(partner_branch.node_hash(), 1)
                }
            };
            TreeNode::with_branch(commitment_node, partner_node, 0)
        } else {
            TreeNode::with_tap_script(script_commitment, 0)
        };

        // TODO: Check with <https://github.com/rust-bitcoin/rust-bitcoin/issues/1393>
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
