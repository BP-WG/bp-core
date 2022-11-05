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

use amplify::Wrapper;
use bitcoin::schnorr::{TweakedPublicKey, UntweakedPublicKey};
use bitcoin::util::taproot::{TaprootBuilder, TaprootBuilderError};
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

        // TODO: Refactor without builder but with new bitcoin_scripts::taproot
        //       APIs
        let mut builder = TaprootBuilder::new();

        for (depth, partner) in supplement.partner_node.iter().enumerate() {
            let depth = depth as u8 + 1;

            if !partner.check() {
                return Err(TapretTreeError::InvalidPartnerProof(
                    depth,
                    partner.clone(),
                ));
            }

            match partner {
                TapretNodePartner::LeftNode(left_node) => {
                    builder = builder.add_hidden_node(depth, *left_node)?;
                    builder = builder
                        .add_leaf(depth, script_commitment.to_inner())?;
                }
                TapretNodePartner::RightLeaf(leaf_script) => {
                    builder = builder
                        .add_leaf(depth, script_commitment.to_inner())?;
                    builder = builder.add_leaf_with_ver(
                        1,
                        leaf_script.script.to_inner(),
                        leaf_script.version,
                    )?;
                }
                TapretNodePartner::RightBranch(partner_branch) => {
                    builder = builder
                        .add_leaf(depth, script_commitment.to_inner())?;
                    builder = builder
                        .add_hidden_node(depth, partner_branch.node_hash())?;
                }
            }
        }

        // TODO: Use secp instance from Lnpbp6
        let spend_info = builder
            .finalize(SECP256K1, *self)
            .map_err(|_| TaprootBuilderError::IncompleteTree)?;

        let output_key = spend_info.output_key();

        let proof = TapretProof {
            path_proof: supplement.clone(),
            internal_key: *self,
        };

        Ok((output_key, proof))
    }
}
