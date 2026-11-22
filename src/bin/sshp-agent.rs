use anyhow::Result;
use clap::Parser;
use sshp::{
    Paths,
    agent::{AgentCommand, standalone_cmd},
};

#[derive(Parser)]
#[command(version, about = "Run or control the sshp OpenSSH signing agent")]
struct Cli {
    #[command(subcommand)]
    command: AgentCommand,
}

fn main() -> Result<()> {
    let command = Cli::parse().command;
    standalone_cmd(&Paths::discover()?, command)
}
