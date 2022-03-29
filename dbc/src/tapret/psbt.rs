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

//! Implementation of tapret commitments for PSBT-related data structures.

use bitcoin::blockdata::opcodes::all;
use bitcoin::blockdata::script;
use bitcoin::psbt::TapTree;
use bitcoin::util::taproot::{
    LeafVersion, TaprootBuilder, TaprootBuilderError, TaprootMerkleBranch,
};
use bitcoin::{Script, TxOut};
use psbt::commit::tapret::ProprietaryKeyTapret;
use psbt::{ProprietaryKey, TapretOutput};
use secp256k1::Secp256k1;
use strict_encoding::StrictEncode;

/// Error finalizing deterministic bitcoin commitments in the PSBT
#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum CommitmentError {
    /// tapret commitment is already created for this output; it could be that
    /// the PSBT was commitment-finalized under some other protocol.
    CommitmentAlreadyFinalized,

    /// an attempt to add tapret commitment to a non-taproot output or output
    /// which does not contain all required information about script tree and
    /// internal key.
    NonTaprootOutput,

    /// output is not marked to host the commitments; please set
    /// [`PSBT_OUT_TAPRET_HOST`] flag on it first.
    OutputCantHostCommitment,

    /// the provided commitment data can't be strict encoded. Details: {0}
    #[from]
    StrictEncoding(strict_encoding::Error),

    /// unable to update tap tree with the commitment. Details: {0}
    #[from]
    TapTree(TaprootBuilderError),
}

/// PSBT commitment finalizer does output-type specific modifications – and
/// saves information for the wallet in form of tweak data such that the wallet
/// will be able to store the information for future address retrievals and
/// spending.
pub trait CommitFinalizer {
    /// - Taproot: take the value of `TAPRET_COMMITMENT` and add two equal
    ///   `OP_RETURN` branches at the `depth = max(depth) + 1`; save merkle path to
    ///   this branch as `TAPRET_PROOF`; update value of transaction `scriptPubkey`.
    fn finalize_tapret(
        &mut self,
        secp: &Secp256k1<secp256k1::VerifyOnly>,
    ) -> Result<Option<TaprootMerkleBranch>, CommitmentError>;
}

impl CommitFinalizer for (TxOut, psbt::Output) {
    fn finalize_tapret(
        &mut self,
        secp: &Secp256k1<secp256k1::VerifyOnly>,
    ) -> Result<Option<TaprootMerkleBranch>, CommitmentError> {
        let (txout, output) = self;

        if output.has_tapret_proof() {
            return Err(CommitmentError::CommitmentAlreadyFinalized);
        }

        let commitment = match output.tapret_commitment() {
            None => return Ok(None),
            Some(commitment) => commitment,
        };
        let script_commitment = script::Builder::new()
            .push_opcode(all::OP_RETURN)
            .push_slice(&commitment[..])
            .into_script();

        let taptree = output
            .tap_tree
            .as_ref()
            .ok_or(CommitmentError::NonTaprootOutput)?;
        let mut builder = TaprootBuilder::new();
        let mut max_depth = 0u8;
        for (depth, script) in taptree {
            builder = builder.add_leaf(depth as usize, script.clone())?;
            max_depth = max_depth.max(depth);
        }

        let internal_key = output
            .tap_internal_key
            .ok_or(CommitmentError::NonTaprootOutput)?;
        let builder = builder
            .add_leaf(max_depth as usize + 1, script_commitment.clone())?
            .add_leaf(max_depth as usize + 1, script_commitment.clone())?;

        output.tap_tree = Some(
            TapTree::from_inner(builder.clone())
                .expect("non-finalized TapTree after tapret commitment"),
        );

        let spend_info = builder
            .finalize(secp, internal_key)
            .expect("tapret TapTree commitment algorithm failure");
        txout.script_pubkey =
            Script::new_v1_p2tr_tweaked(spend_info.output_key());

        // Both of the DFS-last two leafs has the same merkle path, so we can
        // use any of them.
        let control_block = spend_info
            .control_block(&(script_commitment, LeafVersion::TapScript))
            .expect("tapret TapTree commitment algorithm failure");
        debug_assert_eq!(
            control_block.merkle_branch.as_inner().len(),
            max_depth as usize + 1
        );
        let proof = control_block.merkle_branch;

        output
            .proprietary
            .insert(ProprietaryKey::tapret_proof(), proof.strict_serialize()?);

        Ok(Some(proof))
    }
}

#[cfg(test)]
mod test {
    //use super::*;

    #[test]
    fn noscript() {}
}
