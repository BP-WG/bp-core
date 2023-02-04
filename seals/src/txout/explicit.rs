// Bitcoin protocol single-use-seals library.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2023 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2023 LNP/BP Standards Association. All rights reserved.
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

//! TxOut single-use-seals.

use std::convert::{TryFrom, TryInto};
use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use bc::{Outpoint, Txid, Vout};

use crate::txout::{CloseMethod, MethodParseError, TxoSeal, WitnessVoutError};

/// Revealed seal definition which may point to a witness transactions and does
/// not contain blinding data.
///
/// These data are not used within RGB contract data, thus we do not have a
/// commitment and conceal procedures (since without knowing a blinding factor
/// we can't perform them).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = bc::LIB_NAME_BP)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
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
    pub vout: Vout,
}

impl TryFrom<&ExplicitSeal> for Outpoint {
    type Error = WitnessVoutError;

    #[inline]
    fn try_from(reveal: &ExplicitSeal) -> Result<Self, Self::Error> {
        reveal
            .txid
            .map(|txid| Outpoint::new(txid, reveal.vout))
            .ok_or(WitnessVoutError)
    }
}

impl TryFrom<ExplicitSeal> for Outpoint {
    type Error = WitnessVoutError;

    #[inline]
    fn try_from(reveal: ExplicitSeal) -> Result<Self, Self::Error> { Outpoint::try_from(&reveal) }
}

impl From<&Outpoint> for ExplicitSeal {
    #[inline]
    fn from(outpoint: &Outpoint) -> Self {
        Self {
            method: CloseMethod::TapretFirst,
            txid: Some(outpoint.txid),
            vout: outpoint.vout,
        }
    }
}

impl From<Outpoint> for ExplicitSeal {
    #[inline]
    fn from(outpoint: Outpoint) -> Self { ExplicitSeal::from(&outpoint) }
}

impl TxoSeal for ExplicitSeal {
    #[inline]
    fn method(&self) -> CloseMethod { self.method }

    #[inline]
    fn txid(&self) -> Option<Txid> { self.txid }

    #[inline]
    fn vout(&self) -> Vout { self.vout }

    #[inline]
    fn outpoint(&self) -> Option<Outpoint> { self.try_into().ok() }

    #[inline]
    fn txid_or(&self, default_txid: Txid) -> Txid { self.txid.unwrap_or(default_txid) }

    #[inline]
    fn outpoint_or(&self, default_txid: Txid) -> Outpoint {
        Outpoint::new(self.txid.unwrap_or(default_txid), self.vout)
    }
}

impl ExplicitSeal {
    /// Constructs seal for the provided outpoint and seal closing method.
    #[inline]
    pub fn new(method: CloseMethod, outpoint: Outpoint) -> ExplicitSeal {
        Self {
            method,
            txid: Some(outpoint.txid),
            vout: outpoint.vout,
        }
    }

    /// Constructs seal.
    #[inline]
    pub fn with(method: CloseMethod, txid: Option<Txid>, vout: impl Into<Vout>) -> ExplicitSeal {
        ExplicitSeal {
            method,
            txid,
            vout: vout.into(),
        }
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

    /// wrong seal close method id
    #[display(inner)]
    #[from]
    WrongMethod(MethodParseError),

    /// unable to parse transaction id value; it must be 64-character
    /// hexadecimal string
    WrongTxid,

    /// unable to parse transaction vout value; it must be a decimal unsigned
    /// integer
    WrongVout,

    /// wrong structure of seal string representation
    WrongStructure,
}

impl FromStr for ExplicitSeal {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut split = s.split(&[':', '#'][..]);
        match (split.next(), split.next(), split.next(), split.next()) {
            (Some("~"), ..) | (Some(""), ..) => Err(ParseError::MethodRequired),
            (Some(_), Some(""), ..) => Err(ParseError::TxidRequired),
            (Some(method), Some("~"), Some(vout), None) => Ok(ExplicitSeal {
                method: method.parse()?,
                txid: None,
                vout: vout.parse().map_err(|_| ParseError::WrongVout)?,
            }),
            (Some(method), Some(txid), Some(vout), None) => Ok(ExplicitSeal {
                method: method.parse()?,
                txid: Some(txid.parse().map_err(|_| ParseError::WrongTxid)?),
                vout: vout.parse().map_err(|_| ParseError::WrongVout)?,
            }),
            _ => Err(ParseError::WrongStructure),
        }
    }
}

impl Display for ExplicitSeal {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}",
            self.method,
            self.txid
                .as_ref()
                .map(Txid::to_string)
                .unwrap_or_else(|| s!("~")),
            self.vout,
        )
    }
}
