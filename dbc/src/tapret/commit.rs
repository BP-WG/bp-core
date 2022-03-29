use bitcoin::hashes::sha256::Midstate;
use bitcoin::schnorr::UntweakedPublicKey;
use bitcoin::util::psbt::TapTree;
use bitcoin::util::taproot::TaprootMerkleBranch;
use commit_verify::multi_commit::MultiCommitment;
use commit_verify::{EmbedCommitProof, EmbedCommitProtocol, EmbedCommitVerify};
use secp256k1::{schnorr, XOnlyPublicKey};

/// Marker non-instantiable enum defining LNPBP-6 taproot OP_RETURN (`tapret`)
/// protocol.
pub enum Lnpbp6 {}

impl EmbedCommitProtocol for Lnpbp6 {
    const HASH_TAG_MIDSTATE: Midstate = Midstate([0u8; 32]);
}

/// Extra-transaction proof for tapret commitment
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
// TODO: Add strict encoding
pub struct Proof {
    /// The signature over the output public key produced with the output
    /// private key.
    ///
    /// This information is required for the validation, since the
    /// `scriptPubkey` in the DBC transaction contains x-only public key,
    /// corresponding to two different elliptic curve points. It may be possible
    /// (while still a very challenging from a cryptographic perspective) to
    /// construct two *different* messages and proofs of the commitment, each
    /// of which will correspond to one of these two elliptic curve points.
    /// Thus, we need to commit to the parity of the resulting output key by
    /// signing output public key with the corresponding private output key.
    ///
    /// On the client-side signatures may be aggregated for validation, but
    /// still they have to be kept as a part of the client-side-data.
    pub output_key_sig: schnorr::Signature,

    /// Internal taproot key
    pub internal_key: UntweakedPublicKey,

    /// Merkle path in the script key to the last leaf containing `OP_RETURN`
    /// commitment
    pub merkle_path: TaprootMerkleBranch,
}

impl EmbedCommitProof<MultiCommitment, TapTreeContainer, Lnpbp6> for Proof {
    fn restore_original_container(
        &self,
        commit_container: &TapTreeContainer,
        message: MultiCommitment,
    ) -> TapTreeContainer {
    }
}

impl EmbedCommitProof<MultiCommitment, ControlBlock, Lnpbp6> for Proof {
    fn restore_original_container(
        &self,
        commit_container: &TapTreeContainer,
        message: MultiCommitment,
    ) -> ControlBlock {
    }
}

/// Errors during taproot OP_RETURN-based commitment process
#[derive(
    Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error
)]
#[display(doc_comments)]
pub enum Error {}

/// Container for tapret commitments. Represents a newtype around [`TapTree`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TapTreeContainer(TapTree);

impl EmbedCommitVerify<MultiCommitment, Lnpbp6> for TapTreeContainer {
    type Proof = Proof;
    type CommitError = Error;

    fn embed_commit(
        &mut self,
        msg: &MultiCommitment,
    ) -> Result<Self::Proof, Self::CommitError> {
        let mut builder = self.0.clone().into_inner();
        builder.is_complete() * self = Self(TapTree::from_inner(builder)?);
        Ok(proof)
    }
}
