// Deterministic bitcoin commitments library, implementing LNPBP standards
// Part of bitcoin protocol core library (BP Core Lib)
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

use crate::{Error, Proof};

pub trait Container: Sized {
    type Supplement;
    type Host;

    /// Reconstructs commitment container from the extra-transaction proof
    /// and protocol-specific data.
    fn reconstruct(
        proof: &Proof,
        supplement: &Self::Supplement,
        host: &Self::Host,
    ) -> Result<Self, Error>;

    fn deconstruct(self) -> (Proof, Self::Supplement);

    fn to_proof(&self) -> Proof;
    fn into_proof(self) -> Proof;
}
