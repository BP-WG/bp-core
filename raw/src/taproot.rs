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

#![allow(unused_braces)] // required due to strict dumb derivation and compiler bug

use std::borrow::Borrow;
use std::fmt::{self, Formatter, LowerHex, UpperHex};
use std::{cmp, io};

use amplify::confinement::{Confined, TinyVec};
use amplify::{Bytes32, Wrapper};
use secp256k1::{Scalar, XOnlyPublicKey};
use strict_encoding::{
    DecodeError, ReadTuple, StrictDecode, StrictEncode, StrictProduct,
    StrictTuple, StrictType, TypeName, TypedRead, TypedWrite, WriteTuple,
};

use crate::opcodes::*;
use crate::serialize::{ConsensusWrite, Serialize};
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
    Wrapper, WrapperMut, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash,
    Debug, From
)]
#[wrapper(Deref, LowerHex, Display, FromStr)]
#[wrapper_mut(DerefMut)]
#[derive(StrictType, StrictDumb)]
#[strict_type(lib = LIB_NAME_BP, dumb = { Self(XOnlyPublicKey::from_slice(&[1u8; 32]).unwrap()) })]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct InternalPk(XOnlyPublicKey);

impl InternalPk {
    pub fn to_output_key(
        &self,
        merkle_root: Option<impl IntoTapHash>,
    ) -> XOnlyPublicKey {
        let mut engine = Sha256::from_tag(MIDSTATE_TAPTWEAK);
        // always hash the key
        engine.input(&self.0.serialize());
        if let Some(merkle_root) = merkle_root {
            engine.input(merkle_root.into_tap_hash().as_slice());
        }
        let tweak = Scalar::from_be_bytes(engine.finish())
            .expect("hash value greater than curve order");
        let (output_key, tweaked_parity) = self
            .0
            .add_tweak(secp256k1::SECP256K1, &tweak)
            .expect("hash collision");
        debug_assert!(self.tweak_add_check(
            secp256k1::SECP256K1,
            &output_key,
            tweaked_parity,
            tweak
        ));
        output_key
    }
}

impl StrictEncode for InternalPk {
    fn strict_encode<W: TypedWrite>(&self, writer: W) -> io::Result<W> {
        let bytes = Bytes32::from(self.0.serialize());
        writer.write_newtype::<Self>(&bytes)
    }
}

impl StrictDecode for InternalPk {
    fn strict_decode(reader: &mut impl TypedRead) -> Result<Self, DecodeError> {
        reader.read_tuple(|r| {
            let bytes: Bytes32 = r.read_field()?;
            XOnlyPublicKey::from_slice(bytes.as_slice())
                .map(Self)
                .map_err(|_| {
                    DecodeError::DataIntegrityError(format!(
                        "invalid x-only public key value '{bytes:x}'"
                    ))
                })
        })
    }
}

pub trait IntoTapHash {
    fn into_tap_hash(self) -> TapNodeHash;
}

#[derive(
    Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From
)]
#[wrapper(Index, RangeOps, BorrowSlice, Hex, Display, FromStr)]
pub struct TapLeafHash(
    #[from]
    #[from([u8; 32])]
    Bytes32,
);

impl TapLeafHash {
    pub fn with_leaf_script(leaf_script: &LeafScript) -> Self {
        let mut engine = Sha256::from_tag(MIDSTATE_TAPLEAF);
        leaf_script.serialize_into(&mut engine).ok();
        Self(engine.finish().into())
    }

    pub fn with_tap_script(tap_script: &TapScript) -> Self {
        let mut engine = Sha256::from_tag(MIDSTATE_TAPLEAF);
        engine.write_u8(TAPROOT_LEAF_TAPSCRIPT).ok();
        tap_script.serialize_into(&mut engine).ok();
        Self(engine.finish().into())
    }
}

impl IntoTapHash for TapLeafHash {
    fn into_tap_hash(self) -> TapNodeHash { TapNodeHash(self.0) }
}

#[derive(
    Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From
)]
#[wrapper(Index, RangeOps, BorrowSlice, Hex, Display, FromStr)]
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

impl IntoTapHash for TapBranchHash {
    fn into_tap_hash(self) -> TapNodeHash { TapNodeHash(self.0) }
}

#[derive(
    Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From
)]
#[wrapper(Deref, Index, RangeOps, BorrowSlice, Hex, Display, FromStr)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BP)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
pub struct TapNodeHash(
    #[from]
    #[from([u8; 32])]
    #[from(TapLeafHash)]
    #[from(TapBranchHash)]
    Bytes32,
);

impl IntoTapHash for TapNodeHash {
    fn into_tap_hash(self) -> TapNodeHash { self }
}

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
pub enum LeafVer {
    /// BIP-342 tapscript.
    #[default]
    TapScript,

    /// Future leaf version.
    Future(FutureLeafVer),
}

impl StrictType for LeafVer {
    const STRICT_LIB_NAME: &'static str = LIB_NAME_BP;
    fn strict_name() -> Option<TypeName> { Some(tn!("LeafVer")) }
}
impl StrictProduct for LeafVer {}
impl StrictTuple for LeafVer {
    const FIELD_COUNT: u8 = 1;
}
impl StrictEncode for LeafVer {
    fn strict_encode<W: TypedWrite>(&self, writer: W) -> std::io::Result<W> {
        writer.write_tuple::<Self>(|w| {
            Ok(w.write_field(&self.to_consensus())?.complete())
        })
    }
}
impl StrictDecode for LeafVer {
    fn strict_decode(reader: &mut impl TypedRead) -> Result<Self, DecodeError> {
        reader.read_tuple(|r| {
            let version = r.read_field()?;
            Self::from_consensus(version)
                .map_err(|err| DecodeError::DataIntegrityError(err.to_string()))
        })
    }
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
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BP, dumb = { Self(0x51) })]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
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

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Default, Display)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BP)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[display("{version:04x} {script:x}")]
pub struct LeafScript {
    pub version: LeafVer,
    pub script: ScriptBytes,
}

// TODO: Impl Hex and FromStr for LeafScript

impl From<TapScript> for LeafScript {
    fn from(tap_script: TapScript) -> Self {
        LeafScript {
            version: LeafVer::TapScript,
            script: tap_script.into_inner(),
        }
    }
}

impl LeafScript {
    pub fn from_tap_script(tap_script: TapScript) -> Self {
        Self::from(tap_script)
    }
    pub fn tap_leaf_hash(&self) -> TapLeafHash {
        TapLeafHash::with_leaf_script(self)
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
#[wrapper(Deref, Index, RangeOps, BorrowSlice, LowerHex, UpperHex)]
#[wrapper_mut(DerefMut, IndexMut, RangeMut, BorrowSliceMut)]
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
        internal_key: InternalPk,
        merkle_root: Option<TapNodeHash>,
    ) -> Self {
        todo!()
    }

    pub fn p2tr_tweaked(output_key: XOnlyPublicKey) -> Self { todo!() }

    pub fn is_p2tr(&self) -> bool { todo!() }
}
