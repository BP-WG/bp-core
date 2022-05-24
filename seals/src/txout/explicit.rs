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

use std::convert::{TryFrom, TryInto};

use bitcoin::{OutPoint, Txid};

use crate::txout::{CloseMethod, TxoSeal, WitnessVoutError};

/// Revealed seal definition which may point to a witness transactions and does
/// not contain blinding data.
///
/// These data are not used within RGB contract data, thus we do not have a
/// commitment and conceal procedures (since without knowing a blinding factor
/// we can't perform them).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "snake_case")
)]
#[derive(StrictEncode, StrictDecode)]
pub struct ExplicitSeal {
    /// Commitment to the specific seal close method [`CloseMethod`] which must
    /// be used to close this seal.
    pub method: CloseMethod,

    /// Txid of the seal definition.
    ///
    /// It may be missed in situations when ID of a transaction is not known,
    /// but the transaction still can be identified by some other means (for
    /// instance it is a transaction spending specific outpoint, like other
    /// seal definition).
    pub txid: Option<Txid>,

    /// Tx output number, which should be always known.
    pub vout: u32,
}

impl TryFrom<&ExplicitSeal> for OutPoint {
    type Error = WitnessVoutError;

    #[inline]
    fn try_from(reveal: &ExplicitSeal) -> Result<Self, Self::Error> {
        reveal
            .txid
            .map(|txid| OutPoint::new(txid, reveal.vout as u32))
            .ok_or(WitnessVoutError)
    }
}

impl TryFrom<ExplicitSeal> for OutPoint {
    type Error = WitnessVoutError;

    #[inline]
    fn try_from(reveal: ExplicitSeal) -> Result<Self, Self::Error> {
        OutPoint::try_from(&reveal)
    }
}

impl From<&OutPoint> for ExplicitSeal {
    #[inline]
    fn from(outpoint: &OutPoint) -> Self {
        Self {
            method: CloseMethod::TapretFirst,
            txid: Some(outpoint.txid),
            vout: outpoint.vout as u32,
        }
    }
}

impl From<OutPoint> for ExplicitSeal {
    #[inline]
    fn from(outpoint: OutPoint) -> Self { ExplicitSeal::from(&outpoint) }
}

impl TxoSeal for ExplicitSeal {
    #[inline]
    fn method(&self) -> CloseMethod { self.method }

    #[inline]
    fn txid(&self) -> Option<Txid> { self.txid }

    #[inline]
    fn vout(&self) -> usize { self.vout as usize }

    #[inline]
    fn outpoint(&self) -> Option<OutPoint> { self.try_into().ok() }

    #[inline]
    fn txid_or(&self, default_txid: Txid) -> Txid {
        self.txid.unwrap_or(default_txid)
    }

    #[inline]
    fn outpoint_or(&self, default_txid: Txid) -> OutPoint {
        OutPoint::new(self.txid.unwrap_or(default_txid), self.vout as u32)
    }
}
