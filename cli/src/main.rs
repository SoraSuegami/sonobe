#[cfg(not(target_arch = "wasm32"))]
use ::clap::Parser;
#[cfg(not(target_arch = "wasm32"))]
use ark_serialize::Write;
#[cfg(not(target_arch = "wasm32"))]
use settings::Cli;
#[cfg(not(target_arch = "wasm32"))]
use std::path::Path;
#[cfg(not(target_arch = "wasm32"))]
use std::{fs, io};

#[cfg(not(target_arch = "wasm32"))]
mod gen_params;
#[cfg(not(target_arch = "wasm32"))]
mod settings;

#[cfg(not(target_arch = "wasm32"))]
fn create_or_open_then_write<T: AsRef<[u8]>>(path: &Path, content: &T) -> Result<(), io::Error> {
    let mut file = fs::OpenOptions::new().create(true).write(true).open(path)?;
    file.write_all(content.as_ref())
}

#[cfg(not(target_arch = "wasm32"))]
fn main() {
    let cli = Cli::parse();

    // generate a subscriber with the desired log level
    env_logger::builder()
        .format_timestamp_secs()
        .filter_level(cli.verbosity.log_level_filter())
        .init();

    match cli.command {
        settings::Subcommand::GenVerifier => gen_solidity(cli),
        settings::Subcommand::GenParams => gen_params::gen_params(cli),
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn gen_solidity(cli: Cli) {
    // Fetch the exact protocol for which we need to generate the Decider verifier contract.
    let protocol = cli.protocol;
    // Fetch the protocol data passed by the user from the file.
    let protocol_vk = std::fs::read(cli.protocol_vk.expect("protocol_vk is required")).unwrap();

    // Generate the Solidity Verifier contract for the selected protocol with the given data.
    create_or_open_then_write(
        &cli.out,
        &protocol.render(&protocol_vk, cli.pragma).unwrap(),
    )
    .unwrap();
}

#[cfg(target_arch = "wasm32")]
fn main() {}
