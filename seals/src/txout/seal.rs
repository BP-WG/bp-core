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

use std::str::FromStr;

use bp::{Outpoint, Txid, Vout};

use super::MethodParseError;

/// Methods common for all transaction-output based seal types.
pub trait TxoSeal {
    /// Returns method which must be used for seal closing.
    fn method(&self) -> CloseMethod;

    /// Returns [`Txid`] part of the seal definition, if known.
    fn txid(&self) -> Option<Txid>;

    /// Returns transaction output number containing the defined seal.
    fn vout(&self) -> Vout;

    /// Returns [`OutPoint`] defining the seal, if txid is known.
    fn outpoint(&self) -> Option<Outpoint>;

    /// Returns [`Txid`] part of the seal definition, if known, or the provided
    /// `default_txid`.
    fn txid_or(&self, default_txid: Txid) -> Txid;

    /// Returns [`OutPoint`] defining the seal, if txid is known, or constructs
    /// one using the provided `default_txid`.
    fn outpoint_or(&self, default_txid: Txid) -> Outpoint;
}

/// Method of single-use-seal closing.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = bp::LIB_NAME_BP, tags = repr, into_u8, try_from_u8)]
#[repr(u8)]
#[non_exhaustive]
pub enum CloseMethod {
    /// Seal is closed over the message in form of OP_RETURN commitment present
    /// in the first OP_RETURN-containing transaction output.
    #[display("opret1st")]
    #[strict_type(dumb)]
    OpretFirst = 0x00,

    /// Seal is closed over the message in form of Taproot-based OP_RETURN
    /// commitment present in the first Taproot transaction output.
    #[display("tapret1st")]
    TapretFirst = 0x01,
}

impl FromStr for CloseMethod {
    type Err = MethodParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_lowercase() {
            s if s == CloseMethod::OpretFirst.to_string() => {
                CloseMethod::OpretFirst
            }
            s if s == CloseMethod::TapretFirst.to_string() => {
                CloseMethod::TapretFirst
            }
            _ => return Err(MethodParseError(s.to_owned())),
        })
    }
}
