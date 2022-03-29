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

//! Taproot OP_RETURN-based deterministic commitments.
//!
//! Option<merkle_path> + message -> merkle_path*

use bitcoin::util::taproot::{TaprootMerkleBranch, TaprootSpendInfo};
use commit_verify::EmbedCommitVerify;
use secp256k1::XOnlyPublicKey;

pub struct TapretProtocol;

pub enum TaprootCommitError {
    TooDeepTree,
}

impl EmbedCommitVerify<AnchorId> for TaprootMerkleBranch {
    type Proof = TaprootMerkleBranch;
    type Protocol = TapretProtocol;
    type CommitError = TaprootCommitError;

    fn embed_commit(
        &mut self,
        msg: &AnchorId,
    ) -> Result<Self::Proof, Self::CommitError> {
        let proof = self.clone();
        self.0.push(msg.as_ref());
        Ok(proof)
    }
}

impl EmbedCommitVerify<AnchorId> for TaprootSpendInfo {
    type Proof = (TaprootMerkleBranch, XOnlyPublicKey);
    type Protocol = TapretProtocol;
    type CommitError = TaprootCommitError;

    fn embed_commit(
        &mut self,
        msg: &AnchorId,
    ) -> Result<Self::Proof, Self::CommitError> {
        self.push_script()
    }
}
