use anyhow::Result;
use clap::{Parser, Subcommand};
use sshp::{Paths, agent, config, integration, settings, sync, vault};
use std::path::PathBuf;

#[derive(Parser)]
#[command(version, about = "Manage an encrypted OpenSSH vault")]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create an age-backed vault and initialize its Git repository
    Init {
        #[arg(long)]
        recipient: String,
        #[arg(long)]
        remote: Option<String>,
    },
    /// Clone and validate an encrypted vault
    Clone {
        url: String,
        /// Save this machine's identity path before validating the clone
        #[arg(long)]
        age_key_file: Option<PathBuf>,
    },
    /// Show local vault and upstream state
    Status,
    /// Validate and fast-forward to the remote vault
    Pull {
        /// Save this machine's identity path before validating updates
        #[arg(long)]
        age_key_file: Option<PathBuf>,
    },
    /// Configure local preferences, even before cloning a vault
    Settings {
        #[command(subcommand)]
        command: Option<settings::SettingsCommand>,
    },
    /// Commit the encrypted vault and push without forcing
    Push,
    /// Print the runtime Include directive, or prepend it to ~/.ssh/config
    InstallConfig {
        #[arg(long)]
        apply: bool,
    },
    /// Open the interactive configuration editor
    Tui,
    /// Import, edit, or export OpenSSH configuration
    Config {
        #[command(subcommand)]
        command: config::ConfigCommand,
    },
    /// Manage persistent vaulted identities and associations
    Key {
        #[command(subcommand)]
        command: vault::KeyCommand,
    },
    /// Import or export encrypted vault snapshots
    Vault {
        #[command(subcommand)]
        command: vault::VaultCommand,
    },
    /// Control the signing agent
    Agent {
        #[command(subcommand)]
        command: agent::AgentCommand,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let p = Paths::discover()?;
    match cli.cmd.unwrap_or(Cmd::Tui) {
        Cmd::Init { recipient, remote } => {
            vault::init(&p, &recipient)?;
            sync::init(&p, remote.as_deref())
        }
        Cmd::Clone { url, age_key_file } => {
            if let Some(path) = age_key_file {
                settings::set_identity(&p, &path)?;
            }
            sync::clone_repo(&p, &url)
        }
        Cmd::Status => sync::status(&p),
        Cmd::Pull { age_key_file } => {
            if let Some(path) = age_key_file {
                settings::set_identity(&p, &path)?;
            }
            sync::pull(&p)
        }
        Cmd::Settings { command } => {
            settings::run(&p, command.unwrap_or(settings::SettingsCommand::Show))
        }
        Cmd::Push => sync::push(&p),
        Cmd::Tui => config::tui(&p),
        Cmd::Config { command } => config::config_cmd(&p, command),
        Cmd::Key { command } => vault::key_cmd(&p, command),
        Cmd::Vault { command } => vault::vault_cmd(&p, command),
        Cmd::Agent { command } => agent::agent_cmd(&p, command),
        Cmd::InstallConfig { apply } => {
            let file = p.managed_config();
            if apply {
                p.prepare_runtime()?;
                integration::install_include(&file)?;
            }
            print!("{}", integration::include_line(&file)?);
            Ok(())
        }
    }
}
