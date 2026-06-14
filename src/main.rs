//! B579-Arwah — entry point.

mod cli;
mod ffi;
mod tui;

use anyhow::Result;
use cli::Cli;
use clap::Parser;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

fn main() -> Result<()> {
    init_tracing();
    let cli = Cli::parse();
    cli.run()
}

fn init_tracing() {
    tracing_subscriber::registry()
        .with(fmt::layer().with_writer(std::io::stderr))
        .with(EnvFilter::from_default_env())
        .init();
}
