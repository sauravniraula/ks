mod app;
mod cli;
mod crypto;
mod session;
mod storage;

use anyhow::Result;
use clap::Parser;

fn main() -> Result<()> {
    let args = cli::Cli::parse();

    match args.command {
        Some(command) => cli::run(command),
        None => app::run(),
    }
}
