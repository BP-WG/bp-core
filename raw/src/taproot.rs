// BP Core Library implementing LNP/BP specifications & standards related to
// bitcoin protocol
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

use std::borrow::Borrow;
use std::cmp;
use std::fmt::{self, Formatter, LowerHex, UpperHex};

use amplify::confinement::{Confined, TinyVec};
use amplify::{Bytes32, Wrapper};
use secp256k1::XOnlyPublicKey;

use crate::opcodes::*;
use crate::serialize::Serialize;
use crate::{ScriptBytes, ScriptPubkey, Sha256, LIB_NAME_BP};

/// The SHA-256 midstate value for the TapLeaf hash.
pub const MIDSTATE_TAPLEAF: [u8; 32] = [
    156, 224, 228, 230, 124, 17, 108, 57, 56, 179, 202, 242, 195, 15, 80, 137,
    211, 243, 147, 108, 71, 99, 110, 96, 125, 179, 62, 234, 221, 198, 240, 201,
];
// 9ce0e4e67c116c3938b3caf2c30f5089d3f3936c47636e607db33eeaddc6f0c9

/// The SHA-256 midstate value for the TapBranch hash.
pub const MIDSTATE_TAPBRANCH: [u8; 32] = [
    35, 168, 101, 169, 184, 164, 13, 167, 151, 124, 30, 4, 196, 158, 36, 111,
    181, 190, 19, 118, 157, 36, 201, 183, 181, 131, 181, 212, 168, 210, 38,
    210,
];
// 23a865a9b8a40da7977c1e04c49e246fb5be13769d24c9b7b583b5d4a8d226d2

/// The SHA-256 midstate value for the TapTweak hash.
pub const MIDSTATE_TAPTWEAK: [u8; 32] = [
    209, 41, 162, 243, 112, 28, 101, 93, 101, 131, 182, 195, 185, 65, 151, 39,
    149, 244, 226, 50, 148, 253, 84, 244, 162, 174, 141, 133, 71, 202, 89, 11,
];
// d129a2f3701c655d6583b6c3b941972795f4e23294fd54f4a2ae8d8547ca590b

/// The SHA-256 midstate value for the [`TapSighashHash`].
pub const MIDSTATE_TAPSIGHASH: [u8; 32] = [
    245, 4, 164, 37, 215, 248, 120, 59, 19, 99, 134, 138, 227, 229, 86, 88,
    110, 238, 148, 93, 188, 120, 136, 221, 2, 166, 226, 195, 24, 115, 254, 159,
];
// f504a425d7f8783b1363868ae3e556586eee945dbc7888dd02a6e2c31873fe9f

#[derive(
    Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From
)]
#[wrapper(RangeOps, BorrowSlice, Hex, Display, FromStr)]
pub struct TapLeafHash(
    #[from]
    #[from([u8; 32])]
    Bytes32,
);

impl TapLeafHash {
    pub fn with_tap_script(tap_script: TapScript) -> Self {
        let mut engine = Sha256::from_tag(MIDSTATE_TAPLEAF);
        LeafScript::from(tap_script)
            .serialize_into(&mut engine)
            .expect("fixed size");
        Self(engine.finish().into())
    }
}

#[derive(
    Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From
)]
#[wrapper(RangeOps, BorrowSlice, Hex, Display, FromStr)]
pub struct TapBranchHash(
    #[from]
    #[from([u8; 32])]
    Bytes32,
);

impl TapBranchHash {
    pub fn with_nodes(node1: TapNodeHash, node2: TapNodeHash) -> Self {
        let mut engine = Sha256::from_tag(MIDSTATE_TAPBRANCH);
        engine.input(cmp::min(&node1, &node2).borrow());
        engine.input(cmp::max(&node1, &node2).borrow());
        Self(engine.finish().into())
    }
}

#[derive(
    Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From
)]
#[wrapper(RangeOps, BorrowSlice, Hex, Display, FromStr)]
pub struct TapNodeHash(
    #[from]
    #[from([u8; 32])]
    #[from(TapLeafHash)]
    #[from(TapBranchHash)]
    Bytes32,
);

#[derive(Wrapper, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrapper(Deref)]
pub struct TapMerklePath(TinyVec<TapBranchHash>);

/// Taproot annex prefix.
pub const TAPROOT_ANNEX_PREFIX: u8 = 0x50;

/// Tapscript leaf version.
// https://github.com/bitcoin/bitcoin/blob/e826b22da252e0599c61d21c98ff89f366b3120f/src/script/interpreter.h#L226
pub const TAPROOT_LEAF_TAPSCRIPT: u8 = 0xc0;

/// Tapleaf mask for getting the leaf version from first byte of control block.
// https://github.com/bitcoin/bitcoin/blob/e826b22da252e0599c61d21c98ff89f366b3120f/src/script/interpreter.h#L225
pub const TAPROOT_LEAF_MASK: u8 = 0xfe;

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Display, Error)]
#[display(doc_comments)]
/// invalid taproot leaf version {0}.
pub struct InvalidLeafVer(u8);

/// The leaf version for tapleafs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LeafVer {
    /// BIP-342 tapscript.
    TapScript,

    /// Future leaf version.
    Future(FutureLeafVer),
}

impl LeafVer {
    /// Creates a [`LeafVer`] from consensus byte representation.
    ///
    /// # Errors
    ///
    /// - If the last bit of the `version` is odd.
    /// - If the `version` is 0x50 ([`TAPROOT_ANNEX_PREFIX`]).
    pub fn from_consensus(version: u8) -> Result<Self, InvalidLeafVer> {
        match version {
            TAPROOT_LEAF_TAPSCRIPT => Ok(LeafVer::TapScript),
            TAPROOT_ANNEX_PREFIX => Err(InvalidLeafVer(TAPROOT_ANNEX_PREFIX)),
            future => {
                FutureLeafVer::from_consensus(future).map(LeafVer::Future)
            }
        }
    }

    /// Returns the consensus representation of this [`LeafVer`].
    pub fn to_consensus(self) -> u8 {
        match self {
            LeafVer::TapScript => TAPROOT_LEAF_TAPSCRIPT,
            LeafVer::Future(version) => version.to_consensus(),
        }
    }
}

impl LowerHex for LeafVer {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        LowerHex::fmt(&self.to_consensus(), f)
    }
}

impl UpperHex for LeafVer {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        UpperHex::fmt(&self.to_consensus(), f)
    }
}

/// Inner type representing future (non-tapscript) leaf versions. See
/// [`LeafVer::Future`].
///
/// NB: NO PUBLIC CONSTRUCTOR!
/// The only way to construct this is by converting `u8` to [`LeafVer`] and then
/// extracting it.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct FutureLeafVer(u8);

impl FutureLeafVer {
    pub(self) fn from_consensus(
        version: u8,
    ) -> Result<FutureLeafVer, InvalidLeafVer> {
        match version {
            TAPROOT_LEAF_TAPSCRIPT => unreachable!(
                "FutureLeafVersion::from_consensus should be never called for \
                 0xC0 value"
            ),
            TAPROOT_ANNEX_PREFIX => Err(InvalidLeafVer(TAPROOT_ANNEX_PREFIX)),
            odd if odd & 0xFE != odd => Err(InvalidLeafVer(odd)),
            even => Ok(FutureLeafVer(even)),
        }
    }

    /// Returns the consensus representation of this [`FutureLeafVer`].
    #[inline]
    pub fn to_consensus(self) -> u8 { self.0 }
}

impl LowerHex for FutureLeafVer {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        LowerHex::fmt(&self.0, f)
    }
}

impl UpperHex for FutureLeafVer {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        UpperHex::fmt(&self.0, f)
    }
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct LeafScript {
    pub version: LeafVer,
    pub script: ScriptBytes,
}

impl From<TapScript> for LeafScript {
    fn from(tap_script: TapScript) -> Self {
        LeafScript {
            version: LeafVer::TapScript,
            script: tap_script.into_inner(),
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, Display)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BP, tags = repr, into_u8, try_from_u8)]
#[repr(u8)]
pub enum TapCode {
    /// Push the next 32 bytes as an array onto the stack.
    #[display("OP_PUSH_BYTES32")]
    PushBytes32 = OP_PUSHBYTES_32,

    /// Synonym for OP_RETURN.
    Reserved = OP_RESERVED,

    /// Fail the script immediately.
    #[display("OP_RETURN")]
    #[strict_type(dumb)]
    Return = OP_RETURN,

    /// Read the next byte as N; push the next N bytes as an array onto the
    /// stack.
    #[display("OP_PUSH_DATA1")]
    PushData1 = OP_PUSHDATA1,
    /// Read the next 2 bytes as N; push the next N bytes as an array onto the
    /// stack.
    #[display("OP_PUSH_DATA2")]
    PushData2 = OP_PUSHDATA2,
    /// Read the next 4 bytes as N; push the next N bytes as an array onto the
    /// stack.
    #[display("OP_PUSH_DATA3")]
    PushData4 = OP_PUSHDATA4,
}

#[derive(
    Wrapper, WrapperMut, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug,
    From, Default
)]
#[wrapper(RangeOps, BorrowSlice, LowerHex, UpperHex)]
#[wrapper_mut(RangeMut, BorrowSliceMut)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BP)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct TapScript(ScriptBytes);
// TODO: impl Display/FromStr for TapScript providing correct opcodes

impl TapScript {
    pub fn new() -> Self { Self::default() }

    pub fn with_capacity(capacity: usize) -> Self {
        Self(ScriptBytes::from(Confined::with_capacity(capacity)))
    }

    /// Adds a single opcode to the script.
    pub fn push_opcode(&mut self, op_code: TapCode) {
        self.0.push(op_code as u8).expect("script exceeds 4GB");
    }
}

impl ScriptPubkey {
    pub fn p2tr(
        internal_key: XOnlyPublicKey,
        merkle_root: Option<TapNodeHash>,
    ) -> Self {
        todo!()
    }

    pub fn p2tr_tweaked(output_key: XOnlyPublicKey) -> Self { todo!() }
}
