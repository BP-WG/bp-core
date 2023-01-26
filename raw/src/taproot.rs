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

use amplify::Bytes32;

use crate::VarIntBytes;

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

#[derive(
    Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From
)]
#[wrapper(RangeOps, BorrowSlice, Hex, Display, FromStr)]
pub struct TapBranchHash(
    #[from]
    #[from([u8; 32])]
    Bytes32,
);

#[derive(
    Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From
)]
#[wrapper(RangeOps, BorrowSlice, Hex, Display, FromStr)]
pub struct TapNodeHash(
    #[from]
    #[from([u8; 32])]
    Bytes32,
);

#[derive(
    Wrapper, WrapperMut, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug,
    From
)]
#[wrapper(RangeOps, BorrowSlice, LowerHex, UpperHex)]
#[wrapper_mut(RangeMut, BorrowSliceMut)]
pub struct TapScript(
    #[from]
    #[from(Vec<u8>)]
    VarIntBytes,
);
// TODO: impl Display/FromStr for TapScript providing opcodes
