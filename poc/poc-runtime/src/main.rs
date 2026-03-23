#![forbid(unsafe_code)]

//! `poc-runtime` binary bootstrap for the preferred multi-process PoC launcher.

use clap::Parser;

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    poc_runtime::init_tracing();
    if let Err(error) = poc_runtime::run(poc_runtime::Cli::parse()).await {
        eprintln!("Error: {error}");
        std::process::exit(1);
    }
}
