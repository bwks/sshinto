use clap::{Parser, Subcommand};
use models::DeviceKind;

#[derive(Parser)]
#[command(name = "sshinto", about = "Connect to network devices over SSH")]
#[command(disable_help_flag = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Print help
    #[arg(long, action = clap::ArgAction::Help, global = true)]
    pub help: Option<bool>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Run commands on a device
    Run(RunArgs),
}

#[derive(Parser)]
pub struct RunArgs {
    /// Target host (IP or hostname)
    #[arg(short = 'h', long)]
    pub host: String,

    /// SSH port
    #[arg(short = 'p', long, default_value_t = 22)]
    pub port: u16,

    /// Username
    #[arg(short = 'U', long)]
    pub username: String,

    /// Password (omit to prompt interactively)
    #[arg(short = 'P', long)]
    pub password: Option<String>,

    /// Path to SSH private key file
    #[arg(short = 'k', long)]
    pub key_file: Option<String>,

    /// Passphrase for the private key
    #[arg(long)]
    pub key_passphrase: Option<String>,

    /// Device type
    #[arg(short = 'd', long)]
    pub device_type: DeviceKind,

    /// Enable legacy SSH crypto algorithms
    #[arg(long)]
    pub legacy_crypto: bool,

    /// Command to execute (repeatable)
    #[arg(short = 'c', long = "command", required = true)]
    pub commands: Vec<String>,

    /// Command timeout in seconds
    #[arg(short = 't', long, default_value_t = 10)]
    pub timeout: u64,
}
