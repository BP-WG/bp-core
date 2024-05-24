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

use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use amplify::{ByteArray, Bytes32, Wrapper};
use baid64::{Baid64ParseError, DisplayBaid64, FromBaid64Str};
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
    const TAG: &'static str = "urn:lnp-bp:seals:secret#2024-02-03";
}

impl From<Sha256> for SecretSeal {
    fn from(hasher: Sha256) -> Self { hasher.finish().into() }
}

impl DisplayBaid64 for SecretSeal {
    const HRI: &'static str = "utxob";
    const CHUNKING: bool = true;
    const PREFIX: bool = true;
    const EMBED_CHECKSUM: bool = true;
    const MNEMONIC: bool = false;
    fn to_baid64_payload(&self) -> [u8; 32] { self.to_byte_array() }
}
impl FromBaid64Str for SecretSeal {}
impl FromStr for SecretSeal {
    type Err = Baid64ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> { Self::from_baid64_str(s) }
}
impl Display for SecretSeal {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result { self.fmt_baid64(f) }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn secret_seal_baid58() {
        let baid64 = "utxob:xDfmDF9g-yNOjriV-6Anbe6H-MLJ!!g6-lo7Dd4f-dhWBW8S-XYGBm";
        let seal: SecretSeal = baid64.parse().unwrap();
        assert_eq!(baid64, seal.to_string());
        assert_eq!(seal.to_string(), seal.to_baid64_string());
        let reconstructed = SecretSeal::from_str(&baid64.replace('-', "")).unwrap();
        assert_eq!(reconstructed, seal);
    }
}
