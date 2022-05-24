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

//! Bitcoin single-use-seals defined by a transaction output and closed by
//! spending that output ("TxOut seals").

pub mod blind;
mod error;
pub mod explicit;
mod proto;
mod seal;

pub use error::{MethodParseError, VerifyError, WitnessVoutError};
pub use explicit::ExplicitSeal;
pub use proto::TxoProtocol;
pub use seal::{CloseMethod, TxoSeal};
