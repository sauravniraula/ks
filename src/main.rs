mod api_keys;
mod app;
mod cli;
mod crypto;
mod mcp;
mod session;
mod storage;

use anyhow::{anyhow, Result};
use clap::Parser;

fn main() -> Result<()> {
    let args = cli::Cli::parse();

    match args.command {
        Some(command) => cli::run(command, args.selected_group),
        None if args.selected_group.is_some() => Err(anyhow!(
            "-g/--group is only supported with login, list, and search"
        )),
        None => app::run(),
    }
}
