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

use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use amplify::{Bytes32, Wrapper};
use baid58::{Baid58ParseError, Chunking, FromBaid58, ToBaid58, CHUNKING_32CHECKSUM};
use commit_verify::{CommitmentId, DigestExt, Sha256};

/// Confidential version of transaction outpoint-based single-use-seal
#[derive(Wrapper, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, From)]
#[wrapper(Deref, BorrowSlice, Hex, Index, RangeOps)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = dbc::LIB_NAME_BPCORE)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct SecretSeal(
    #[from]
    #[from([u8; 32])]
    Bytes32,
);

impl CommitmentId for SecretSeal {
    const TAG: &'static str = "urn:lnpbp:seals:secret#2024-02-03";
}

impl From<Sha256> for SecretSeal {
    fn from(hasher: Sha256) -> Self { hasher.finish().into() }
}

impl ToBaid58<32> for SecretSeal {
    const HRI: &'static str = "utxob";
    const CHUNKING: Option<Chunking> = CHUNKING_32CHECKSUM;
    fn to_baid58_payload(&self) -> [u8; 32] { self.0.into_inner() }
    fn to_baid58_string(&self) -> String { self.to_string() }
}
impl FromBaid58<32> for SecretSeal {}
impl FromStr for SecretSeal {
    type Err = Baid58ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        SecretSeal::from_baid58_maybe_chunked_str(s, ':', ' ')
    }
}
impl Display for SecretSeal {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            write!(f, "{::^}", self.to_baid58())
        } else {
            write!(f, "{::^.3}", self.to_baid58())
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn secret_seal_baid58() {
        let baid58 = "utxob:2eFrirU-RjqLnqR74-AKRfdnc9M-DpvSRjmZG-mFPrw7nvu-Te1wy83";
        let seal: SecretSeal = baid58.parse().unwrap();
        assert_eq!(baid58, seal.to_string());
        assert_eq!(baid58.replace('-', ""), format!("{seal:#}"));
        assert_eq!(seal.to_string(), seal.to_baid58_string());
        let reconstructed = SecretSeal::from_str(&baid58.replace('-', "")).unwrap();
        assert_eq!(reconstructed, seal);
    }
}
