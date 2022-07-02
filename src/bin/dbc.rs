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

#[macro_use]
extern crate clap;
#[macro_use]
extern crate amplify;

use std::path::PathBuf;
use std::{fs, io};

use amplify::IoError;
use bitcoin::psbt::serialize::{Deserialize, Serialize};
use bitcoin::psbt::PsbtParseError;
use clap::Parser;
use colored::Colorize;
use commit_verify::EmbedCommitVerify;
use dbc::anchor::PsbtEmbeddedMessage;
use dbc::tapret::PsbtCommitError;
use psbt::Psbt;

/// Command-line arguments
#[derive(Parser)]
#[derive(Clone, Eq, PartialEq, Debug)]
#[clap(
    author,
    version,
    name = "dbc",
    about = "Command-line tool for deterministic bitcoin commitments"
)]
pub struct Args {
    /// Command to execute
    #[clap(subcommand)]
    pub command: Command,
}

/// Wallet command to execute
#[allow(clippy::large_enum_variant)]
#[derive(Subcommand)]
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum Command {
    /// Adds commitment to the PSBT file in positions marked with
    /// `LNPBP_CAN_HOST_COMMITMENT` proprietary key.
    ///
    /// If operation succeeds, removes the flag from the output where the
    /// commitment was added, replacing it with `LNPBP_COMMITMENT` proprietary
    /// key.
    Commit {
        /// Input file containing PSBT of the transfer witness transaction.
        psbt_in: PathBuf,

        /// Output file to save the PSBT updated with state transition(s)
        /// information. If not given, the source PSBT file is overwritten.
        psbt_out: Option<PathBuf>,
    },
}

impl Args {
    pub fn exec(self) -> Result<(), Error> {
        match self.command {
            Command::Commit { psbt_in, psbt_out } => {
                let psbt_bytes = fs::read(&psbt_in)?;
                let mut psbt = Psbt::deserialize(&psbt_bytes)?;

                let anchor = psbt.embed_commit(&PsbtEmbeddedMessage)?;
                eprintln!("Anchor: {:?}", anchor);

                let psbt_bytes = psbt.serialize();
                fs::write(psbt_out.unwrap_or(psbt_in), psbt_bytes)?;
            }
        }

        Ok(())
    }
}

#[derive(Debug, Display, Error, From)]
#[display(inner)]
pub enum Error {
    #[from(io::Error)]
    Io(IoError),

    #[from]
    BitcoinEncoding(bitcoin::consensus::encode::Error),

    #[from]
    StrictEncoding(strict_encoding::Error),

    #[from]
    PsbtBase58(PsbtParseError),

    #[from]
    #[display(inner)]
    Commitment(PsbtCommitError),
}

fn main() {
    let args = Args::parse();
    if let Err(err) = args.exec() {
        eprintln!("{}: {}\n", "Error".bright_red(), err);
    }
}
