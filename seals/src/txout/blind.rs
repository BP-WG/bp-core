// Bitcoin protocol single-use-seals library.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2024 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! TxOut seals which are blinded with additional entropy.

use std::fmt::{self, Debug, Display, Formatter};
use std::hash::Hash;
use std::str::FromStr;

use amplify::hex;
use bc::{Outpoint, Txid, Vout};
use commit_verify::{CommitId, Conceal};
use dbc::MethodParseError;
use rand::{thread_rng, RngCore};
use strict_encoding::{StrictDecode, StrictDumb, StrictEncode};

use super::{CloseMethod, WitnessVoutError};
use crate::txout::{SealTxid, TxPtr, TxoSeal};
use crate::{SealCloseMethod, SecretSeal};

/// Seal type which can be blinded and chained with other seals.
pub type ChainBlindSeal<M> = BlindSeal<TxPtr, M>;
/// Seal type which can be blinded, but can't be chained with other seals.
pub type SingleBlindSeal<M> = BlindSeal<Txid, M>;

/// Revealed seal definition which may point to a witness transactions and
/// contains blinding data.
///
/// Revealed seal means that the seal definition containing explicit information
/// about the bitcoin transaction output.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = dbc::LIB_NAME_BPCORE)]
#[derive(CommitEncode)]
#[commit_encode(strategy = strict, id = SecretSeal)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct BlindSeal<Id: SealTxid, M: SealCloseMethod = CloseMethod> {
    /// Commitment to the specific seal close method [`CloseMethod`] which must
    /// be used to close this seal.
    pub method: M,

    /// Txid of the seal definition.
    ///
    /// It may be missed in situations when ID of a transaction is not known,
    /// but the transaction still can be identified by some other means (for
    /// instance it is a transaction spending specific outpoint, like other
    /// seal definition).
    pub txid: Id,

    /// Tx output number, which should be always known.
    pub vout: Vout,

    /// Blinding factor providing confidentiality of the seal definition.
    /// Prevents rainbow table bruteforce attack based on the existing
    /// blockchain txid set.
    pub blinding: u64,
}

impl<Id: SealTxid> Conceal for BlindSeal<Id> {
    type Concealed = SecretSeal;

    #[inline]
    fn conceal(&self) -> Self::Concealed { self.commit_id() }
}

impl<M: SealCloseMethod> TryFrom<&BlindSeal<TxPtr, M>> for Outpoint {
    type Error = WitnessVoutError;

    #[inline]
    fn try_from(reveal: &BlindSeal<TxPtr, M>) -> Result<Self, Self::Error> {
        reveal.txid.map_to_outpoint(reveal.vout).ok_or(WitnessVoutError)
    }
}

impl<M: SealCloseMethod> TryFrom<BlindSeal<TxPtr, M>> for Outpoint {
    type Error = WitnessVoutError;

    #[inline]
    fn try_from(reveal: BlindSeal<TxPtr, M>) -> Result<Self, Self::Error> {
        Outpoint::try_from(&reveal)
    }
}

impl<M: SealCloseMethod> From<&BlindSeal<Txid, M>> for Outpoint {
    #[inline]
    fn from(reveal: &BlindSeal<Txid, M>) -> Self { Outpoint::new(reveal.txid, reveal.vout) }
}

impl<M: SealCloseMethod> From<BlindSeal<Txid, M>> for Outpoint {
    #[inline]
    fn from(reveal: BlindSeal<Txid, M>) -> Self { Outpoint::from(&reveal) }
}

impl<Id: SealTxid, M: SealCloseMethod> TxoSeal<M> for BlindSeal<Id, M> {
    #[inline]
    fn method(&self) -> M { self.method }

    #[inline]
    fn txid(&self) -> Option<Txid> { self.txid.txid() }

    #[inline]
    fn vout(&self) -> Vout { self.vout }

    #[inline]
    fn outpoint(&self) -> Option<Outpoint> { self.txid.map_to_outpoint(self.vout) }

    #[inline]
    fn txid_or(&self, default_txid: Txid) -> Txid { self.txid.txid_or(default_txid) }

    #[inline]
    fn outpoint_or(&self, default_txid: Txid) -> Outpoint {
        Outpoint::new(self.txid.txid_or(default_txid), self.vout)
    }
}

impl<Id: SealTxid> BlindSeal<Id, CloseMethod> {
    /// Creates new seal using TapretFirst closing method for the provided
    /// outpoint. Uses `thread_rng` to initialize blinding factor.
    pub fn tapret_first_rand_from(outpoint: Outpoint) -> Self {
        BlindSeal::tapret_first_rand(outpoint.txid, outpoint.vout)
    }

    /// Creates new seal using OpretFirst closing method for the provided
    /// outpoint. Uses `thread_rng` to initialize blinding factor.
    pub fn opret_first_rand_from(outpoint: Outpoint) -> Self {
        BlindSeal::opret_first_rand(outpoint.txid, outpoint.vout)
    }

    /// Creates new seal using TapretFirst closing method for the provided
    /// outpoint. Uses `thread_rng` to initialize blinding factor.
    pub fn tapret_first_rand(txid: impl Into<Id>, vout: impl Into<Vout>) -> Self {
        BlindSeal::with_rng(CloseMethod::TapretFirst, txid, vout, &mut thread_rng())
    }

    /// Creates new seal using OpretFirst closing method for the provided
    /// outpoint. Uses `thread_rng` to initialize blinding factor.
    pub fn opret_first_rand(txid: impl Into<Id>, vout: impl Into<Vout>) -> Self {
        BlindSeal::with_rng(CloseMethod::OpretFirst, txid, vout, &mut thread_rng())
    }
}

impl<Id: SealTxid, M: SealCloseMethod> BlindSeal<Id, M> {
    /// Creates new seal for the provided outpoint and seal closing method. Uses
    /// `thread_rng` to initialize blinding factor.
    pub fn new_random(method: M, txid: impl Into<Id>, vout: impl Into<Vout>) -> Self {
        BlindSeal::with_rng(method, txid, vout, &mut thread_rng())
    }

    /// Creates new seal for the provided outpoint and seal closing method. Uses
    /// provided random number generator to create a new blinding factor.
    pub fn with_rng(
        method: M,
        txid: impl Into<Id>,
        vout: impl Into<Vout>,
        rng: &mut impl RngCore,
    ) -> Self {
        BlindSeal {
            method,
            txid: txid.into(),
            vout: vout.into(),
            blinding: rng.next_u64(),
        }
    }

    /// Reconstructs previously defined seal pointing to a witness transaction
    /// of another seal with a given method, witness transaction output number
    /// and previously generated blinding factor value..
    pub fn with_blinding(
        method: M,
        txid: impl Into<Id>,
        vout: impl Into<Vout>,
        blinding: u64,
    ) -> Self {
        BlindSeal {
            method,
            txid: txid.into(),
            vout: vout.into(),
            blinding,
        }
    }
}

impl<M: SealCloseMethod> BlindSeal<TxPtr, M> {
    /// Creates new seal pointing to a witness transaction of another seal.
    /// Takes seal closing method and witness transaction output number as
    /// arguments. Uses `thread_rng` to initialize blinding factor.
    #[inline]
    pub fn new_random_vout(method: M, vout: impl Into<Vout>) -> Self {
        Self {
            method,
            blinding: thread_rng().next_u64(),
            txid: TxPtr::WitnessTx,
            vout: vout.into(),
        }
    }

    /// Reconstructs previously defined seal pointing to a witness transaction
    /// of another seal with a given method, witness transaction output number
    /// and previously generated blinding factor value..
    pub fn with_blinded_vout(method: M, vout: impl Into<Vout>, blinding: u64) -> Self {
        BlindSeal {
            method,
            txid: TxPtr::WitnessTx,
            vout: vout.into(),
            blinding,
        }
    }
}

impl<M: SealCloseMethod> BlindSeal<Txid, M> {
    /// Converts `BlindSeal<Txid>` into `BlindSeal<TxPtr>`.
    pub fn transmutate(self) -> BlindSeal<TxPtr, M> {
        BlindSeal::with_blinding(self.method, self.txid, self.vout, self.blinding)
    }

    /// Converts seal into a transaction outpoint.
    #[inline]
    pub fn to_outpoint(&self) -> Outpoint { Outpoint::new(self.txid, self.vout) }
}

impl<M: SealCloseMethod> BlindSeal<TxPtr, M> {
    /// Converts `BlindSeal<TxPtr>` into `BlindSeal<Txid>`.
    pub fn resolve(self, txid: Txid) -> BlindSeal<Txid, M> {
        BlindSeal::with_blinding(self.method, self.txid().unwrap_or(txid), self.vout, self.blinding)
    }
}

/// Errors happening during parsing string representation of different forms of
/// single-use-seals
#[derive(Clone, PartialEq, Eq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum ParseError {
    /// single-use-seal must start with method name (e.g. 'tapret1st' etc)
    MethodRequired,

    /// full transaction id is required for the seal specification
    TxidRequired,

    /// blinding factor must be specified after `#`
    BlindingRequired,

    /// wrong seal close method id
    #[display(inner)]
    #[from]
    WrongMethod(MethodParseError),

    /// unable to parse blinding value; it must be a hexadecimal string
    /// starting with `0x`
    WrongBlinding,

    /// unable to parse transaction id value; it must be 64-character
    /// hexadecimal string, however {0}
    WrongTxid(hex::Error),

    /// unable to parse transaction vout value; it must be a decimal unsigned
    /// integer
    WrongVout,

    /// wrong structure of seal string representation
    WrongStructure,

    /// blinding secret must be represented by a 64-bit hexadecimal value
    /// starting with `0x` and not with a decimal
    NonHexBlinding,
}

impl<Id: SealTxid, M: SealCloseMethod> FromStr for BlindSeal<Id, M>
where M: FromStr<Err = MethodParseError>
{
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut split = s.split(&[':', '#'][..]);
        match (split.next(), split.next(), split.next(), split.next(), split.next()) {
            (Some("~"), ..) | (Some(""), ..) => Err(ParseError::MethodRequired),
            (Some(_), Some(""), ..) => Err(ParseError::TxidRequired),
            (Some(_), Some(_), None, ..) if s.contains(':') => Err(ParseError::BlindingRequired),
            (Some(_), Some(_), Some(_), Some(blinding), None) if !blinding.starts_with("0x") => {
                Err(ParseError::NonHexBlinding)
            }
            (Some(method), Some(txid), Some(vout), Some(blinding), None) => Ok(BlindSeal {
                method: method.parse()?,
                blinding: u64::from_str_radix(blinding.trim_start_matches("0x"), 16)
                    .map_err(|_| ParseError::WrongBlinding)?,
                txid: Id::from_str(txid).map_err(ParseError::WrongTxid)?,
                vout: vout.parse().map_err(|_| ParseError::WrongVout)?,
            }),
            _ => Err(ParseError::WrongStructure),
        }
    }
}

impl<Id: SealTxid, M: SealCloseMethod> Display for BlindSeal<Id, M>
where
    Self: TxoSeal<M>,
    M: Display,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}#{:#010x}", self.method, self.txid, self.vout, self.blinding)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn blind_seal_str() {
        let mut outpoint_reveal = BlindSeal {
            method: CloseMethod::TapretFirst,
            blinding: 0x31bbed7e7b2d,
            txid: TxPtr::Txid(
                Txid::from_str("646ca5c1062619e2a2d60771c9dfd820551fb773e4dc8c4ed67965a8d1fae839")
                    .unwrap(),
            ),
            vout: Vout::from(21),
        };

        let s = outpoint_reveal.to_string();
        assert_eq!(
            &s,
            "tapret1st:646ca5c1062619e2a2d60771c9dfd820551fb773e4dc8c4ed67965a8d1fae839:21#\
             0x31bbed7e7b2d"
        );
        // round-trip
        assert_eq!(ChainBlindSeal::from_str(&s).unwrap(), outpoint_reveal);

        outpoint_reveal.txid = TxPtr::WitnessTx;
        let s = outpoint_reveal.to_string();
        assert_eq!(&s, "tapret1st:~:21#0x31bbed7e7b2d");
        // round-trip
        assert_eq!(ChainBlindSeal::from_str(&s).unwrap(), outpoint_reveal);

        // wrong method
        assert_eq!(
            ChainBlindSeal::<CloseMethod>::from_str(
                "tapret:646ca5c1062619e2a2d60771c9dfd820551fb773e4dc8c4ed67965a8d1fae839:0x765#\
                 0x78ca95"
            ),
            Err(ParseError::WrongMethod(MethodParseError(s!("tapret"))))
        );

        // wrong vout value
        assert_eq!(
            ChainBlindSeal::<CloseMethod>::from_str(
                "tapret1st:646ca5c1062619e2a2d60771c9dfd820551fb773e4dc8c4ed67965a8d1fae839:0x765#\
                 0x78ca95"
            ),
            Err(ParseError::WrongVout)
        );
        assert_eq!(
            ChainBlindSeal::<CloseMethod>::from_str(
                "tapret1st:646ca5c1062619e2a2d60771c9dfd820551fb773e4dc8c4ed67965a8d1fae839:i9#\
                 0x78ca95"
            ),
            Err(ParseError::WrongVout)
        );
        assert_eq!(
            ChainBlindSeal::<CloseMethod>::from_str(
                "tapret1st:646ca5c1062619e2a2d60771c9dfd820551fb773e4dc8c4ed67965a8d1fae839:-5#\
                 0x78ca95"
            ),
            Err(ParseError::WrongVout)
        );

        // wrong blinding secret value
        assert_eq!(
            ChainBlindSeal::<CloseMethod>::from_str(
                "tapret1st:646ca5c1062619e2a2d60771c9dfd820551fb773e4dc8c4ed67965a8d1fae839:5#\
                 0x78cs"
            ),
            Err(ParseError::WrongBlinding)
        );
        assert_eq!(
            ChainBlindSeal::<CloseMethod>::from_str(
                "tapret1st:646ca5c1062619e2a2d60771c9dfd820551fb773e4dc8c4ed67965a8d1fae839:5#\
                 78ca95"
            ),
            Err(ParseError::NonHexBlinding)
        );
        assert_eq!(
            ChainBlindSeal::<CloseMethod>::from_str(
                "tapret1st:646ca5c1062619e2a2d60771c9dfd820551fb773e4dc8c4ed67965a8d1fae839:5#857"
            ),
            Err(ParseError::NonHexBlinding)
        );
        assert_eq!(
            ChainBlindSeal::<CloseMethod>::from_str(
                "tapret1st:646ca5c1062619e2a2d60771c9dfd820551fb773e4dc8c4ed67965a8d1fae839:5#-5"
            ),
            Err(ParseError::NonHexBlinding)
        );

        // wrong txid value
        assert_eq!(
            ChainBlindSeal::<CloseMethod>::from_str(
                "tapret1st:646ca5c1062619e2a2d607719dfd820551fb773e4dc8c4ed67965a8d1fae839:5#\
                 0x78ca69"
            ),
            Err(ParseError::WrongTxid(hex::Error::OddLengthString(63)))
        );
        assert_eq!(
            ChainBlindSeal::<CloseMethod>::from_str("tapret1st:rvgbdg:5#0x78ca69"),
            Err(ParseError::WrongTxid(hex::Error::InvalidChar(b'r')))
        );
        assert_eq!(
            ChainBlindSeal::<CloseMethod>::from_str(
                "tapret1st:10@646ca5c1062619e2a2d60771c9dfd820551fb773e4dc8c4ed67965a8d1fae839:5#\
                 0x78ca69"
            ),
            Err(ParseError::WrongTxid(hex::Error::OddLengthString(67)))
        );

        // wrong structure
        assert_eq!(
            ChainBlindSeal::<CloseMethod>::from_str(
                "tapret1st:646ca5c1062619e2a2d60771c9dfd820551fb773e4dc8c4ed67965a8d1fae839:1"
            ),
            Err(ParseError::WrongStructure)
        );
        assert_eq!(
            ChainBlindSeal::<CloseMethod>::from_str(
                "tapret1st:646ca5c1062619e2a2d60771c9dfd820551fb773e4dc8c4ed67965a8d1fae839#0x78ca"
            ),
            Err(ParseError::WrongStructure)
        );
        assert_eq!(
            ChainBlindSeal::<CloseMethod>::from_str(
                "tapret1st:646ca5c1062619e2a2d60771c9dfd820551fb773e4dc8c4ed67965a8d1fae839"
            ),
            Err(ParseError::BlindingRequired)
        );
        assert_eq!(
            ChainBlindSeal::<CloseMethod>::from_str(
                "tapret1st:646ca5c1062619e2a2d60771c9dfd820551fb773e4dc8c4ed67965a8d1fae839##\
                 0x78ca"
            ),
            Err(ParseError::WrongVout)
        );
        assert_eq!(
            ChainBlindSeal::<CloseMethod>::from_str(
                "tapret1st:646ca5c1062619e2a2d60771c9dfd820551fb773e4dc8c4ed67965a8d1fae839:#\
                 0x78ca95"
            ),
            Err(ParseError::WrongVout)
        );
        assert_eq!(
            ChainBlindSeal::<CloseMethod>::from_str("tapret1st:_:5#0x78ca"),
            Err(ParseError::WrongTxid(hex::Error::OddLengthString(1)))
        );
        assert_eq!(
            ChainBlindSeal::<CloseMethod>::from_str(":5#0x78ca"),
            Err(ParseError::MethodRequired)
        );
        assert_eq!(
            ChainBlindSeal::<CloseMethod>::from_str("~:5#0x78ca"),
            Err(ParseError::MethodRequired)
        );
    }
}
