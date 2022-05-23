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

use std::path::{Path, PathBuf};
use std::{fs, io};

use amplify::{IoError, Slice32};
use bitcoin::psbt::PsbtParseError;
use clap::Parser;
use colored::Colorize;
use psbt::{ProprietaryKeyDescriptor, Psbt};
use strict_encoding::{StrictDecode, StrictEncode};

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
        /// Number of `LNPBP_CAN_HOST_COMMITMENT`-flagged output to add
        /// commitment data to.
        #[clap(short, long, default_value = "0")]
        output_no: u16,

        /// Commitment value.
        ///
        /// Saved into `LNPBP_COMMITMENT` proprietary key.
        commitment: Slice32,

        /// Additional proprietary keys which will be added to the constructed
        /// PSBT.
        ///
        /// These keys may contain information specific to the used commitment
        /// scheme.
        #[clap(short = 'k', long = "proprietary-key")]
        proprietary_keys: Vec<ProprietaryKeyDescriptor>,

        /// File containing PSBT.
        psbt_file: PathBuf,
    },
}

impl Args {
    pub fn exec(&self) -> Result<(), Error> {
        match &self.command {
            Command::Commit {
                output_no,
                commitment,
                proprietary_keys,
                psbt_file,
            } => self.commit(
                psbt_file,
                *output_no,
                *commitment,
                proprietary_keys,
            ),
        }
    }

    fn commit(
        &self,
        psbt_path: &Path,
        output_no: u16,
        commitment: Slice32,
        proprietary_keys: &[ProprietaryKeyDescriptor],
    ) -> Result<(), Error> {
        let file = fs::File::open(psbt_path)?;
        let mut psbt = Psbt::strict_decode(&file)?;

        let output: &mut psbt::Output =
            if let Some(output) = psbt.outputs.get_mut(output_no as usize) {
                output
            } else {
                return Err(Error::NoOutput {
                    requested: output_no,
                    total: psbt.outputs.len(),
                });
            };

        let file = fs::File::create(psbt_path)?;
        psbt.strict_encode(file)?;

        Ok(())
    }
}

#[derive(Debug, Display, Error, From)]
#[display(inner)]
pub enum Error {
    #[from(io::Error)]
    Io(IoError),

    #[from]
    StrictEncoding(strict_encoding::Error),

    #[from]
    PsbtBase58(PsbtParseError),

    /// output no {requested} exceeds total number of outputs in the
    /// transaction ({total}).
    #[display(doc_comments)]
    NoOutput { requested: u16, total: usize },
}

fn main() {
    let args = Args::parse();
    if let Err(err) = args.exec() {
        eprintln!("{}: {}\n", "Error".bright_red(), err);
    }
}
