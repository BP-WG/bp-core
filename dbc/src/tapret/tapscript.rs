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

use bp::{TapCode, TapScript, LIB_NAME_BP};
use commit_verify::{
    mpc, strategies, CommitEncode, CommitStrategy, CommitVerify,
};

use super::Lnpbp12;

/// Hardcoded tapret script prefix consisting of 29 `OP_RESERVED` pushes,
/// followed by `OP_RETURN` and `OP_PUSHBYTES_33`.
pub const TAPRET_SCRIPT_COMMITMENT_PREFIX: [u8; 31] = [
    0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50,
    0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50,
    0x50, 0x50, 0x50, 0x50, 0x50, 0x6a, 0x21,
];

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BP)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
pub struct TapretCommitment {
    /// LNPBP-4 multi-protocol commitment.
    pub mpc: mpc::Commitment,
    /// Nonce is used to put the commitment into the correct side of the tree.
    pub nonce: u8,
}

impl TapretCommitment {
    pub fn with(mpc: mpc::Commitment, nonce: u8) -> Self { Self { mpc, nonce } }
}

impl CommitStrategy for TapretCommitment {
    type Strategy = strategies::ConcealStrict;
}

impl CommitVerify<TapretCommitment, Lnpbp12> for TapScript {
    /// Tapret script consists of 29 `OP_RESERVED` pushes, followed by
    /// `OP_RETURN`, `OP_PUSHBYTES_33` and serialized commitment data (MPC
    /// commitment + nonce as a single slice).
    fn commit(commitment: &TapretCommitment) -> Self {
        let mut tapret = TapScript::with_capacity(64);
        for _ in 0..29 {
            tapret.push_opcode(TapCode::Reserved);
        }
        let mut data = [0u8; 33];
        commitment.commit_encode(&mut data);
        tapret.push_slice(&data);
        tapret
    }
}

#[cfg(test)]
mod test {
    use strict_encoding::StrictDumb;

    use super::*;

    pub fn commitment() -> TapretCommitment {
        TapretCommitment {
            mpc: mpc::Commitment::strict_dumb(),
            nonce: 8,
        }
    }

    #[test]
    pub fn prefix() {
        let script = TapScript::commit(&commitment());
        assert_eq!(TAPRET_SCRIPT_COMMITMENT_PREFIX, script[0..31]);
    }

    #[test]
    pub fn commiment_serialization() {
        let commitment = commitment();
        let script = TapScript::commit(&commitment);
        assert_eq!(script[32], commitment.nonce);
        assert_eq!(script[..32], commitment.mpc.as_slice());
    }
}
