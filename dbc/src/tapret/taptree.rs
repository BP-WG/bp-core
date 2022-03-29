use bitcoin::blockdata::opcodes::all;
use bitcoin::blockdata::script;
use bitcoin::hashes::sha256::Midstate;
use bitcoin::schnorr::UntweakedPublicKey;
use bitcoin::util::psbt::TapTree;
use bitcoin::util::taproot::{
    LeafVersion, TaprootBuilder, TaprootBuilderError, TaprootMerkleBranch,
};
use commit_verify::multi_commit::MultiCommitment;
use commit_verify::{
    CommitEncode, EmbedCommitProof, EmbedCommitProtocol, EmbedCommitVerify,
};
use secp256k1::{schnorr, KeyPair, SECP256K1};

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

/*
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
 */

impl EmbedCommitProof<MultiCommitment, TapTreeContainer, Lnpbp6>
    for TaprootMerkleBranch
{
    fn restore_original_container(
        &self,
        _commit_container: &TapTreeContainer,
    ) -> TapTreeContainer {
        todo!()
    }
}

/// Errors during tapret commitment embedding into [`TapTree`] container.
#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum TapTreeError {
    /// the provided commitment data can't be strict encoded. Details: {0}
    #[from]
    StrictEncoding(strict_encoding::Error),

    /// unable to update tap tree with the commitment. Details: {0}
    #[from]
    TapTree(TaprootBuilderError),
}

/// Container for tapret commitments. Represents a newtype around [`TapTree`].
#[derive(Wrapper, Clone, PartialEq, Eq, Debug, From)]
pub struct TapTreeContainer(TapTree);

impl EmbedCommitVerify<MultiCommitment, Lnpbp6> for TapTreeContainer {
    type Proof = TaprootMerkleBranch;
    type CommitError = TapTreeError;

    fn embed_commit(
        &mut self,
        msg: &MultiCommitment,
    ) -> Result<Self::Proof, Self::CommitError> {
        let script_commitment = script::Builder::new()
            .push_opcode(all::OP_RETURN)
            .push_slice(&msg.commit_serialize())
            .into_script();

        let mut builder = TaprootBuilder::new();
        let mut max_depth = 0u8;
        for (depth, script) in &self.0 {
            builder = builder.add_leaf(depth as usize, script.clone())?;
            max_depth = max_depth.max(depth);
        }

        let commit_depth = max_depth as usize + 1;
        let builder = builder
            .add_leaf(commit_depth, script_commitment.clone())?
            .add_leaf(commit_depth, script_commitment.clone())?;

        // We use a dump internal key since its data are not used anywhere
        // TODO: Allow extraction of script merkle branches in rust-bitcoin from
        //       TaprootTreeBuilder without using internal key
        let internal_key =
            KeyPair::from_secret_key(SECP256K1, secp256k1::ONE_KEY)
                .public_key();
        let spend_info = builder
            .finalize(SECP256K1, internal_key)
            .expect("tapret TapTree commitment algorithm failure");

        // Both of the DFS-last two leafs has the same merkle path, so we can
        // use any of them.
        let control_block = spend_info
            .control_block(&(script_commitment, LeafVersion::TapScript))
            .expect("tapret TapTree commitment algorithm failure");
        debug_assert_eq!(
            control_block.merkle_branch.as_inner().len(),
            commit_depth
        );

        Ok(control_block.merkle_branch)
    }
}
