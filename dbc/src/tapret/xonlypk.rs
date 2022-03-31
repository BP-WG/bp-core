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
use bitcoin::hashes::Hash;
use bitcoin::psbt::TapTree;
use bitcoin::schnorr::{TapTweak, TweakedPublicKey, UntweakedPublicKey};
use bitcoin::util::taproot::{TapBranchHash, TaprootBuilder};
use bitcoin_scripts::taproot::{Node, TaprootScriptTree};
use bitcoin_scripts::TapScript;
use commit_verify::embed_commit::ConvolveCommitVerify;
use commit_verify::multi_commit::MultiCommitment;
use commit_verify::CommitVerify;
use secp256k1::SECP256K1;

use crate::tapret::{Lnpbp6, TapNodeProof, TapTreeError};

impl ConvolveCommitVerify<MultiCommitment, TapNodeProof, Lnpbp6>
    for UntweakedPublicKey
{
    type Commitment = TweakedPublicKey;
    type CommitError = TapTreeError;

    fn convolve_commit(
        &self,
        supplement: &TapNodeProof,
        msg: &MultiCommitment,
    ) -> Result<Self::Commitment, Self::CommitError> {
        let script_commitment = TapScript::commit(msg);

        let mut builder = TaprootBuilder::new();

        match supplement {
            TapNodeProof::None => {
                builder =
                    builder.add_leaf(0, script_commitment.into_inner())?;
            }
            TapNodeProof::Leaf(leaf_script) => {
                builder =
                    builder.add_leaf(1, script_commitment.into_inner())?;
                builder = builder.add_leaf_with_ver(
                    1,
                    leaf_script.script.into_inner(),
                    leaf_script.version,
                )?;
            }
            TapNodeProof::Branch(branch, _) => {
                builder =
                    builder.add_leaf(1, script_commitment.into_inner())?;
                builder.add_hidden(1, branch.into_node_hash())
            }
        };

        let commit_node =
            TaprootScriptTree::from(TapTree::from_inner(builder)?)
                .into_root_node();
        let merkle_root =
            TapBranchHash::from_inner(commit_node.node_hash().into_inner());

        let (output_key, _parity) =
            self.tap_tweak(SECP256K1, Some(merkle_root));

        Ok(output_key)
    }
}
