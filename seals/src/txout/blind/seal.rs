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

use std::convert::TryFrom;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

use bitcoin::hashes::{sha256, sha256t, Hash, HashEngine};
use bitcoin::secp256k1::rand::{thread_rng, RngCore};
use bitcoin::{OutPoint, Txid};
use commit_verify::{commit_encode, CommitConceal, CommitVerify, TaggedHash};
use dbc::tapret::Lnpbp6;
use lnpbp_bech32::{FromBech32Str, ToBech32String};

use super::WitnessVoutError;
use crate::txout::{CloseMethod, MethodParseError};

/// Data required to generate or reveal the information about blinded
/// transaction outpoint
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[derive(StrictEncode, StrictDecode)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
pub struct RevealedSeal {
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

    /// Blinding factor providing confidentiality of the seal definition.
    /// Prevents rainbow table bruteforce attack based on the existing
    /// blockchain txid set.
    pub blinding: u64,
}

impl TryFrom<RevealedSeal> for OutPoint {
    type Error = WitnessVoutError;

    #[inline]
    fn try_from(reveal: RevealedSeal) -> Result<Self, Self::Error> {
        reveal
            .txid
            .map(|txid| OutPoint::new(txid, reveal.vout as u32))
            .ok_or(WitnessVoutError)
    }
}

impl From<OutPoint> for RevealedSeal {
    fn from(outpoint: OutPoint) -> Self {
        Self {
            method: CloseMethod::TapretFirst,
            blinding: thread_rng().next_u64(),
            txid: Some(outpoint.txid),
            vout: outpoint.vout as u32,
        }
    }
}

impl From<OutPoint> for ConcealedSeal {
    fn from(outpoint: OutPoint) -> Self {
        RevealedSeal::from(outpoint).commit_conceal()
    }
}

impl CommitConceal for RevealedSeal {
    type ConcealedCommitment = ConcealedSeal;

    #[inline]
    fn commit_conceal(&self) -> Self::ConcealedCommitment {
        self.to_concealed_seal()
    }
}

impl RevealedSeal {
    #[inline]
    pub fn to_concealed_seal(&self) -> ConcealedSeal {
        ConcealedSeal::commit(self)
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

    #[display(inner)]
    #[from]
    WrongMethod(MethodParseError),

    /// unable to parse blinding value; it must be a hexadecimal string
    /// starting with `0x`
    WrongBlinding,

    /// unable to parse transaction id value; it must be 64-character
    /// hexacecimal string
    WrongTxid,

    /// unable to parse transaction vout value; it must be a decimal unsigned
    /// integer
    WrongVout,

    /// wrong structure of seal string representation
    WrongStructure,

    /// blinding secret must be represented by a 64-bit hexadecimal value
    /// starting with `0x` and not with a decimal
    NonHexBlinding,

    /// wrong Bech32 representation of the blinded UTXO seal – {0}
    #[from]
    Bech32(lnpbp_bech32::Error),
}

impl FromStr for RevealedSeal {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut split = s.split(&[':', '#'][..]);
        match (
            split.next(),
            split.next(),
            split.next(),
            split.next(),
            split.next(),
        ) {
            (Some("~"), ..) | (Some(""), ..) => Err(ParseError::MethodRequired),
            (Some(_), Some(""), ..) => Err(ParseError::TxidRequired),
            (Some(_), Some(_), None, ..) if s.contains(':') => {
                Err(ParseError::BlindingRequired)
            }
            (Some(_), Some(_), Some(_), Some(blinding), None)
                if !blinding.starts_with("0x") =>
            {
                Err(ParseError::NonHexBlinding)
            }
            (Some(method), Some("~"), Some(vout), Some(blinding), None) => {
                Ok(RevealedSeal {
                    method: method.parse()?,
                    blinding: u64::from_str_radix(
                        blinding.trim_start_matches("0x"),
                        16,
                    )
                    .map_err(|_| ParseError::WrongBlinding)?,
                    txid: None,
                    vout: vout.parse().map_err(|_| ParseError::WrongVout)?,
                })
            }
            (Some(method), Some(txid), Some(vout), Some(blinding), None) => {
                Ok(RevealedSeal {
                    method: method.parse()?,
                    blinding: u64::from_str_radix(
                        blinding.trim_start_matches("0x"),
                        16,
                    )
                    .map_err(|_| ParseError::WrongBlinding)?,
                    txid: Some(
                        txid.parse().map_err(|_| ParseError::WrongTxid)?,
                    ),
                    vout: vout.parse().map_err(|_| ParseError::WrongVout)?,
                })
            }
            _ => Err(ParseError::WrongStructure),
        }
    }
}

impl Display for RevealedSeal {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}:{}#{:#010x}",
            self.method,
            self.txid.as_ref().map(Txid::to_string).unwrap_or(s!("~")),
            self.vout,
            self.blinding
        )
    }
}

static MIDSTATE_CONCEALED_SEAL: [u8; 32] = [
    250, 13, 163, 5, 178, 220, 248, 173, 139, 222, 67, 198, 134, 127, 63, 153,
    147, 236, 172, 33, 17, 167, 176, 30, 70, 99, 185, 129, 217, 110, 183, 27,
];

/// Tag used for [`ConcealedSeal`] hash type
pub struct ConcealedSealTag;

impl sha256t::Tag for ConcealedSealTag {
    #[inline]
    fn engine() -> sha256::HashEngine {
        let midstate = sha256::Midstate::from_inner(MIDSTATE_CONCEALED_SEAL);
        sha256::HashEngine::from_midstate(midstate, 64)
    }
}

impl lnpbp_bech32::Strategy for ConcealedSealTag {
    const HRP: &'static str = "txob";
    type Strategy = lnpbp_bech32::strategies::UsingStrictEncoding;
}

/// Blind version of transaction outpoint-based single-use-seal
#[derive(
    Wrapper, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default,
    Display, From
)]
#[wrapper(Debug, LowerHex, Index, IndexRange, IndexFrom, IndexTo, IndexFull)]
#[display(ConcealedSeal::to_bech32_string)]
pub struct ConcealedSeal(sha256t::Hash<ConcealedSealTag>);

#[cfg(feature = "serde")]
impl serde::Serialize for ConcealedSeal {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_bech32_string())
        } else {
            serializer.serialize_bytes(&self[..])
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for ConcealedSeal {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;
        impl serde::de::Visitor<'_> for Visitor {
            type Value = ConcealedSeal;

            fn expecting(
                &self,
                formatter: &mut std::fmt::Formatter,
            ) -> std::fmt::Result {
                formatter.write_str("Bech32 string with `txob` HRP")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                ConcealedSeal::from_str(v).map_err(serde::de::Error::custom)
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_str(&v)
            }

            fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                ConcealedSeal::from_slice(&v).map_err(|_| {
                    serde::de::Error::invalid_length(v.len(), &"32 bytes")
                })
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_str(Visitor)
        } else {
            deserializer.deserialize_byte_buf(Visitor)
        }
    }
}

impl FromStr for ConcealedSeal {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(ConcealedSeal::from_bech32_str(s)?)
    }
}

impl strict_encoding::Strategy for ConcealedSeal {
    type Strategy = strict_encoding::strategies::Wrapped;
}

impl commit_encode::Strategy for ConcealedSeal {
    type Strategy = commit_encode::strategies::UsingStrict;
}

impl CommitVerify<RevealedSeal, Lnpbp6> for ConcealedSeal {
    fn commit(reveal: &RevealedSeal) -> Self {
        let mut engine = sha256t::Hash::<ConcealedSealTag>::engine();
        engine.input(&[reveal.method as u8]);
        engine.input(&reveal.txid.unwrap_or_default()[..]);
        engine.input(&reveal.vout.to_le_bytes()[..]);
        engine.input(&reveal.blinding.to_le_bytes()[..]);
        let inner = sha256t::Hash::<ConcealedSealTag>::from_engine(engine);
        ConcealedSeal::from_hash(inner)
    }
}

impl lnpbp_bech32::Strategy for ConcealedSeal {
    const HRP: &'static str = "txob";
    type Strategy = lnpbp_bech32::strategies::UsingStrictEncoding;
}

#[cfg(test)]
mod test {
    use amplify::Wrapper;
    use bitcoin::hashes::hex::FromHex;
    use commit_verify::tagged_hash;

    use super::*;

    #[test]
    fn outpoint_hash_midstate() {
        let midstate = tagged_hash::Midstate::with(b"bp:txout:concealed");
        assert_eq!(midstate.into_inner().into_inner(), MIDSTATE_CONCEALED_SEAL);
    }

    #[test]
    fn outpoint_hash_is_sha256d() {
        let reveal = RevealedSeal {
            method: CloseMethod::TapretFirst,
            blinding: 54683213134637,
            txid: Some(Txid::from_hex("646ca5c1062619e2a2d60771c9dfd820551fb773e4dc8c4ed67965a8d1fae839").unwrap()),
            vout: 2,
        };
        let outpoint_hash = reveal.to_concealed_seal();
        let mut engine = sha256t::Hash::<ConcealedSealTag>::engine();
        engine.input(&[reveal.method as u8]);
        engine.input(&reveal.txid.unwrap()[..]);
        engine.input(&reveal.vout.to_le_bytes()[..]);
        engine.input(&reveal.blinding.to_le_bytes()[..]);
        assert_eq!(
            **outpoint_hash,
            *sha256t::Hash::<ConcealedSealTag>::from_engine(engine)
        )
    }

    #[test]
    fn outpoint_hash_bech32() {
        let outpoint_hash = RevealedSeal {
            method: CloseMethod::TapretFirst,
            blinding: 54683213134637,
            txid: Some(Txid::from_hex("646ca5c1062619e2a2d60771c9dfd820551fb773e4dc8c4ed67965a8d1fae839").unwrap()),
            vout: 2,
        }.to_concealed_seal();
        let bech32 =
            "txob1a9peq6yx9x6ajt584qp5ge4jk9v7tmtgs3x2gntk2nf425cvpdgszt65je";
        assert_eq!(bech32, outpoint_hash.to_string());
        assert_eq!(outpoint_hash.to_string(), outpoint_hash.to_bech32_string());
        let reconstructed = ConcealedSeal::from_str(bech32).unwrap();
        assert_eq!(reconstructed, outpoint_hash);
    }

    #[test]
    fn outpoint_reveal_str() {
        let mut outpoint_reveal = RevealedSeal {
            method: CloseMethod::TapretFirst,
            blinding: 54683213134637,
            txid: Some(Txid::from_hex("646ca5c1062619e2a2d60771c9dfd820551fb773e4dc8c4ed67965a8d1fae839").unwrap()),
            vout: 21,
        };

        let s = outpoint_reveal.to_string();
        assert_eq!(
            &s,
            "tapret1st:646ca5c1062619e2a2d60771c9dfd820551fb773e4dc8c4ed67965a8d1fae839:\
             21#0x31bbed7e7b2d"
        );
        // round-trip
        assert_eq!(RevealedSeal::from_str(&s).unwrap(), outpoint_reveal);

        outpoint_reveal.txid = None;
        let s = outpoint_reveal.to_string();
        assert_eq!(&s, "tapret1st:~:21#0x31bbed7e7b2d");
        // round-trip
        assert_eq!(RevealedSeal::from_str(&s).unwrap(), outpoint_reveal);

        // wrong method
        assert_eq!(RevealedSeal::from_str(
            "tapret:646ca5c1062619e2a2d60771c9dfd820551fb773e4dc8c4ed67965a8d1fae839:0x765#0x78ca95"
        ), Err(ParseError::WrongMethod(MethodParseError(s!("tapret")))));

        // wrong vout value
        assert_eq!(RevealedSeal::from_str(
            "tapret1st:646ca5c1062619e2a2d60771c9dfd820551fb773e4dc8c4ed67965a8d1fae839:0x765#0x78ca95"
        ), Err(ParseError::WrongVout));
        assert_eq!(RevealedSeal::from_str(
            "tapret1st:646ca5c1062619e2a2d60771c9dfd820551fb773e4dc8c4ed67965a8d1fae839:i9#0x78ca95"
        ), Err(ParseError::WrongVout));
        assert_eq!(RevealedSeal::from_str(
            "tapret1st:646ca5c1062619e2a2d60771c9dfd820551fb773e4dc8c4ed67965a8d1fae839:-5#0x78ca95"
        ), Err(ParseError::WrongVout));

        // wrong blinding secret value
        assert_eq!(RevealedSeal::from_str(
            "tapret1st:646ca5c1062619e2a2d60771c9dfd820551fb773e4dc8c4ed67965a8d1fae839:5#0x78cs"
        ), Err(ParseError::WrongBlinding));
        assert_eq!(RevealedSeal::from_str(
            "tapret1st:646ca5c1062619e2a2d60771c9dfd820551fb773e4dc8c4ed67965a8d1fae839:5#78ca95"
        ), Err(ParseError::NonHexBlinding));
        assert_eq!(RevealedSeal::from_str(
            "tapret1st:646ca5c1062619e2a2d60771c9dfd820551fb773e4dc8c4ed67965a8d1fae839:5#857"
        ), Err(ParseError::NonHexBlinding));
        assert_eq!(RevealedSeal::from_str(
            "tapret1st:646ca5c1062619e2a2d60771c9dfd820551fb773e4dc8c4ed67965a8d1fae839:5#-5"
        ), Err(ParseError::NonHexBlinding));

        // wrong txid value
        assert_eq!(RevealedSeal::from_str(
            "tapret1st:646ca5c1062619e2a2d607719dfd820551fb773e4dc8c4ed67965a8d1fae839:5#0x78ca69"
        ), Err(ParseError::WrongTxid));
        assert_eq!(
            RevealedSeal::from_str("tapret1st:rvgbdg:5#0x78ca69"),
            Err(ParseError::WrongTxid)
        );
        assert_eq!(RevealedSeal::from_str(
            "tapret1st:10@646ca5c1062619e2a2d60771c9dfd820551fb773e4dc8c4ed67965a8d1fae839:5#0x78ca69"
        ), Err(ParseError::WrongTxid));

        // wrong structure
        assert_eq!(RevealedSeal::from_str(
            "tapret1st:646ca5c1062619e2a2d60771c9dfd820551fb773e4dc8c4ed67965a8d1fae839:1"
        ), Err(ParseError::WrongStructure));
        assert_eq!(RevealedSeal::from_str(
            "tapret1st:646ca5c1062619e2a2d60771c9dfd820551fb773e4dc8c4ed67965a8d1fae839#0x78ca"
        ), Err(ParseError::WrongStructure));
        assert_eq!(RevealedSeal::from_str(
            "tapret1st:646ca5c1062619e2a2d60771c9dfd820551fb773e4dc8c4ed67965a8d1fae839"
        ), Err(ParseError::BlindingRequired));
        assert_eq!(RevealedSeal::from_str(
            "tapret1st:646ca5c1062619e2a2d60771c9dfd820551fb773e4dc8c4ed67965a8d1fae839##0x78ca"
        ), Err(ParseError::WrongVout));
        assert_eq!(RevealedSeal::from_str(
            "tapret1st:646ca5c1062619e2a2d60771c9dfd820551fb773e4dc8c4ed67965a8d1fae839:#0x78ca95"
        ), Err(ParseError::WrongVout));
        assert_eq!(
            RevealedSeal::from_str("tapret1st:_:5#0x78ca"),
            Err(ParseError::WrongTxid)
        );
        assert_eq!(
            RevealedSeal::from_str(":5#0x78ca"),
            Err(ParseError::MethodRequired)
        );
        assert_eq!(
            RevealedSeal::from_str("~:5#0x78ca"),
            Err(ParseError::MethodRequired)
        );
    }
}
