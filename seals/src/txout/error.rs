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

use bc::{Outpoint, Txid};

use crate::resolver;

/// Seal verification errors.
#[derive(Debug, Display, From, Error)]
#[display(doc_comments)]
pub enum VerifyError {
    /// seals provided for a batch verification have inconsistent close method.
    InconsistentCloseMethod,

    /// witness transaction can't be found in the publication medium
    /// (blockchain or channel) by the given id {0}.
    WitnessTxUnknown(Txid),

    /// the provided witness transaction {0} does not closes seal {1}.
    WitnessNotClosingSeal(Txid, Outpoint),

    /// tapret commitment is invalid.
    ///
    /// Details: {0}
    #[from]
    InvalidTapretCommitment(dbc::tapret::TapretError),

    /// unable to access commitment publication medium.
    #[from]
    #[display(inner)]
    TxResolverError(resolver::Error),
}

/// Error happening if the seal data holds only witness transaction output
/// number and thus can't be used alone for constructing full bitcoin
/// transaction output data which must include the witness transaction id
/// (unknown to the seal).
#[derive(
    Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display, Error
)]
#[display("witness txid is unknown; unable to reconstruct full outpoint data")]
pub struct WitnessVoutError;

/// wrong transaction output-based single-use-seal closing method id '{0}'.
#[derive(Clone, PartialEq, Eq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub struct MethodParseError(pub String);
