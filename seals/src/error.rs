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

#[derive(Clone, PartialEq, Debug, Display, From, Error)]
#[display(doc_comments)]
pub enum Error {
    /// Invalid seal definition
    InvalidSealDefinition,

    /// Transaction output is already spent
    SpentTxout,

    /// Unable to access commitment publication medium
    MediumAccessError,

    /// Error in commitment: {0}
    #[from]
    CommitmentError(dbc::Error),

    /// Error from transaction resolver
    ResolverError,

    /// Resolver probably lies and can't be trusted
    ResolverLying,
}
