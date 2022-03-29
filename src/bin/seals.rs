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

use std::fs;
use std::path::{Path, PathBuf};

use amplify::{IoError, Slice32};
use colored::Colorize;

/// Command-line arguments
#[derive(Parser)]
#[derive(Clone, Eq, PartialEq, Debug)]
#[clap(
    author,
    version,
    name = "seals",
    about = "Command-line tool for working with bitcoin-based single-use-seals"
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
pub enum Command {}

impl Args {
    pub fn exec(&self) -> Result<(), Error> {
        match &self.command {}
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
    Miniscript(miniscript::Error),

    #[from]
    Derive(DeriveError),

    #[from]
    ResolveUtxo(UtxoResolverError),

    #[from]
    Electrum(electrum::Error),

    #[from]
    Yaml(serde_yaml::Error),
}

fn main() {
    let args = Args::parse();
    if let Err(err) = args.exec() {
        eprintln!("{}: {}\n", "Error".bright_red(), err);
    }
}
