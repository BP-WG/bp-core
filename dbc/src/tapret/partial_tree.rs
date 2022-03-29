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

use bitcoin::blockdata::opcodes::all;
use bitcoin::blockdata::script;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::schnorr::UntweakedPublicKey;
use bitcoin::util::taproot::{
    LeafVersion, TapLeafHash, TaprootError, TaprootMerkleBranch,
};
use commit_verify::multi_commit::MultiCommitment;
use commit_verify::{CommitEncode, EmbedCommitProof, EmbedCommitVerify};

use crate::tapret::taptree::Lnpbp6;

#[derive(
    Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error,
    From
)]
#[display(doc_comments)]
pub enum Error {
    /// tapret commitment proof contains zero-length merkle path.
    EmptyProof,

    /// unable to update tap tree with the commitment. Details: {0}
    #[from]
    TapTree(TaprootError),
}

/// Extra-transaction proof for tapret commitment
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[derive(StrictEncode, StrictDecode)]
pub struct TaprootMerkleProof {
    /// Internal taproot key
    pub internal_key: UntweakedPublicKey,

    /// Merkle path in the script key to the last leaf containing `OP_RETURN`
    /// commitment
    pub merkle_path: TaprootMerkleBranch,
}

/// Container for embedding tapret commitments, containing data assembled from
/// either:
/// - PSBT (used in commitment creation),
/// - mined transaction and [`TaprootMerkleProof`] using
///   [`EmbedCommitProof::restore_original_container`] method (used in
///   commitment verification).
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[derive(StrictEncode, StrictDecode)]
pub struct TaprootMerkleContainer {
    /// Internal taproot key
    pub internal_key: UntweakedPublicKey,

    /// Merkle path in the script key to the last leaf containing `OP_RETURN`
    /// commitment
    pub merkle_path: TaprootMerkleBranch,
}

/*
impl TaprootMerkleContainer {
    fn original_merkle_root(&self) -> Result<TapBranchHash, Error> {
        self.merkle_path
            .as_inner()
            .iter()
            .rfold(None, |acc, hash1| {
                let hash1 = TapBranchHash::from_slice(hash1)
                    .expect("TapBranchHash length differs from sha256 hash");
                let mut eng = TapBranchHash::engine();
                match acc {
                    None => return Some(hash1),
                    Some(hash2) if hash1 < hash2 => {
                        eng.input(&hash1);
                        eng.input(&hash2);
                    }
                    Some(hash2) => {
                        eng.input(&hash2);
                        eng.input(&hash1);
                    }
                }
                Some(TapBranchHash::from_engine(eng))
            })
            .ok_or(Error::EmptyProof)
    }
}
 */

impl EmbedCommitProof<MultiCommitment, TaprootMerkleContainer, Lnpbp6>
    for TaprootMerkleProof
{
    fn restore_original_container(
        &self,
        _postcommit_container: &TaprootMerkleContainer,
    ) -> TaprootMerkleContainer {
        let mut path = self.merkle_path.as_inner().to_vec();
        path.pop().ok_or(Error::EmptyProof).unwrap(); // TODO: Return error type
        return TaprootMerkleContainer {
            internal_key: self.internal_key,
            merkle_path: TaprootMerkleBranch::from_inner(path)
                .expect("merkle path with reduced length"),
        };
    }
}

impl EmbedCommitVerify<MultiCommitment, Lnpbp6> for TaprootMerkleContainer {
    type Proof = TaprootMerkleProof;
    type CommitError = Error;

    fn embed_commit(
        &mut self,
        msg: &MultiCommitment,
    ) -> Result<Self::Proof, Self::CommitError> {
        let proof = TaprootMerkleProof {
            internal_key: self.internal_key,
            merkle_path: self.merkle_path.clone(),
        };

        let commitment_script = script::Builder::new()
            .push_opcode(all::OP_RETURN)
            .push_slice(&msg.commit_serialize())
            .into_script();

        let commitment = TapLeafHash::from_script(
            &commitment_script,
            LeafVersion::TapScript,
        );
        let mut path = self.merkle_path.as_inner().to_vec();
        path.push(sha256::Hash::from_inner(commitment.into_inner()));
        self.merkle_path = TaprootMerkleBranch::from_inner(path)?;

        Ok(proof)
    }
}
