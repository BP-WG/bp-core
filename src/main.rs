// BP Core Library implementing LNP/BP specifications & standards related to
// bitcoin protocol
//
// Written in 2020-2021 by
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

use amplify::IoError;
use bitcoin::util::bip32::ExtendedPubKey;
use clap::Parser;
use std::io;
use wallet::slip132;

/// Command-line arguments
#[derive(Parser)]
#[derive(Clone, Eq, PartialEq, Debug)]
#[clap(
    author,
    version,
    name = "bp",
    about = "Command-line tool for working with bitcoin protocol"
)]
pub struct Args {
    /// Command to execute
    #[clap(subcommand)]
    pub command: Command,
}

/// Wallet command to execute
#[derive(Subcommand)]
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum Command {
    /// Commands for extended public key information and manipulation
    #[clap(subcommand)]
    Xpub(XpubCommand),
}

#[allow(clippy::large_enum_variant)]
#[derive(Subcommand)]
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum XpubCommand {
    /// Parses extended public key and prints details information about it
    Inspect { xpub: ExtendedPubKey },
}

#[derive(Debug, Display, Error, From)]
#[display(inner)]
pub enum Error {
    #[from(io::Error)]
    Io(IoError),

    #[from]
    StrictEncoding(strict_encoding::Error),

    /// error in extended key encoding: {0}
    #[from]
    XkeyEncoding(slip132::Error),
}

impl Args {
    pub fn exec(&self) -> Result<(), Error> {
        match self.command {
            Command::Xpub(XpubCommand::Inspect { xpub }) => {
                self.xpub_inspect(xpub)
            }
        }
    }

    fn xpub_inspect(&self, xpub: ExtendedPubKey) -> Result<(), Error> {
        println!("{}", xpub);
        Ok(())
    }
}

fn main() -> Result<(), Error> {
    let args = Args::parse();
    args.exec()
}
