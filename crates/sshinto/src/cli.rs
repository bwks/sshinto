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
    /// Run commands on multiple hosts from a jobfile
    Job(JobArgs),
    /// Upload a file to a remote device via SCP
    Scp(ScpArgs),
}

#[derive(Parser)]
pub struct RunArgs {
    /// Target host (IP or hostname)
    #[arg(short = 'h', long)]
    pub host: Option<String>,

    /// SSH port
    #[arg(short = 'p', long)]
    pub port: Option<u16>,

    /// Username
    #[arg(short = 'U', long)]
    pub username: Option<String>,

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
    pub device_type: Option<DeviceKind>,

    /// Enable legacy SSH crypto algorithms
    #[arg(long)]
    pub legacy_crypto: bool,

    /// Command to execute (repeatable)
    #[arg(short = 'c', long = "command")]
    pub commands: Vec<String>,

    /// Command timeout in seconds
    #[arg(short = 't', long)]
    pub timeout: Option<u64>,

    /// Save output to file (default: output/{host}/{timestamp}/output.txt)
    #[arg(short = 'o', long)]
    pub output_dir: Option<String>,

    /// Jump host (user@host:port)
    #[arg(short = 'J', long)]
    pub jumphost: Option<String>,

    /// Jump host username (overrides username parsed from -J spec)
    #[arg(long)]
    pub jumphost_username: Option<String>,

    /// Jump host password (omit to prompt or use key)
    #[arg(long)]
    pub jumphost_password: Option<String>,

    /// Jump host SSH key file
    #[arg(long)]
    pub jumphost_key_file: Option<String>,

    /// Jump host key passphrase
    #[arg(long)]
    pub jumphost_key_passphrase: Option<String>,

    /// Enable legacy crypto for jump host
    #[arg(long)]
    pub jumphost_legacy_crypto: bool,
}

#[derive(Parser)]
pub struct ScpArgs {
    /// Target host (IP or hostname)
    #[arg(short = 'h', long)]
    pub host: Option<String>,

    /// SSH port
    #[arg(short = 'p', long)]
    pub port: Option<u16>,

    /// Username
    #[arg(short = 'U', long)]
    pub username: Option<String>,

    /// Password (omit to prompt interactively)
    #[arg(short = 'P', long)]
    pub password: Option<String>,

    /// Path to SSH private key file
    #[arg(short = 'k', long)]
    pub key_file: Option<String>,

    /// Passphrase for the private key
    #[arg(long)]
    pub key_passphrase: Option<String>,

    /// Enable legacy SSH crypto algorithms
    #[arg(long)]
    pub legacy_crypto: bool,

    /// Local file path to upload
    #[arg(long)]
    pub source: String,

    /// Remote destination path
    #[arg(long)]
    pub dest: String,

    /// Transfer timeout in seconds
    #[arg(short = 't', long, default_value = "30")]
    pub timeout: u64,

    /// Jump host (user@host:port)
    #[arg(short = 'J', long)]
    pub jumphost: Option<String>,

    /// Jump host username (overrides username parsed from -J spec)
    #[arg(long)]
    pub jumphost_username: Option<String>,

    /// Jump host password (omit to prompt or use key)
    #[arg(long)]
    pub jumphost_password: Option<String>,

    /// Jump host SSH key file
    #[arg(long)]
    pub jumphost_key_file: Option<String>,

    /// Jump host key passphrase
    #[arg(long)]
    pub jumphost_key_passphrase: Option<String>,

    /// Enable legacy crypto for jump host
    #[arg(long)]
    pub jumphost_legacy_crypto: bool,
}

#[derive(Parser)]
pub struct JobArgs {
    /// Path to jobfile
    pub file: String,

    /// Max concurrent connections
    #[arg(long)]
    pub workers: Option<usize>,

    /// Save per-host output to files (default: output/{name}/{timestamp}/output.txt)
    #[arg(short = 'o', long)]
    pub output_dir: Option<String>,

    /// Jump host (user@host:port), overrides jobfile
    #[arg(short = 'J', long)]
    pub jumphost: Option<String>,

    /// Jump host username (overrides username parsed from -J spec)
    #[arg(long)]
    pub jumphost_username: Option<String>,

    /// Jump host password
    #[arg(long)]
    pub jumphost_password: Option<String>,

    /// Jump host SSH key file
    #[arg(long)]
    pub jumphost_key_file: Option<String>,

    /// Jump host key passphrase
    #[arg(long)]
    pub jumphost_key_passphrase: Option<String>,

    /// Enable legacy crypto for jump host
    #[arg(long)]
    pub jumphost_legacy_crypto: bool,
}
