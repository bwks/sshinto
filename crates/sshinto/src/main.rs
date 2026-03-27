mod cli;
mod config;
mod job;
mod writer;

use clap::Parser;
use cli::{Cli, Commands};
use config::{ResolvedArgs, ResolvedCheckArgs, ResolvedScpArgs};
use lib_sshinto::{strip_ansi, ConnectConfig, Connection, Credential, JumpHost, Session};
use models::DeviceKind;
use std::path::Path;
use std::time::Duration;

/// Build the final remote destination path.
///
/// If `dest` is explicitly provided, return it as-is.
/// Otherwise, extract the filename from `source` and prepend the device's `base_path`.
fn resolve_dest(source: &str, dest: Option<&str>, device_type: Option<DeviceKind>) -> String {
    if let Some(d) = dest {
        return d.to_string();
    }
    let filename = Path::new(source)
        .file_name()
        .map(|f| f.to_string_lossy().into_owned())
        .unwrap_or_else(|| source.to_string());
    let base_path = device_type
        .map(|dt| dt.profile().base_path)
        .unwrap_or("");
    format!("{base_path}{filename}")
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Run(args) => {
            let config = match config::Config::load() {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            };
            match config::resolve(&args, &config) {
                Ok(resolved) => run(resolved).await,
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            }
        }
        Commands::Job(args) => job::run_job(&args).await,
        Commands::Scp(args) => {
            let config = match config::Config::load() {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            };
            match config::resolve_scp(&args, &config) {
                Ok(resolved) => run_scp(resolved).await,
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            }
        }
        Commands::Check(args) => {
            let config = match config::Config::load() {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            };
            match config::resolve_check(&args, &config) {
                Ok(resolved) => run_check(resolved).await,
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            }
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

/// Convert a [`config::JumpHostResolved`] into a [`JumpHost`] ready for use in
/// [`ConnectConfig`]. Prompts for a password interactively if no credential is set.
fn build_jump_host(
    jh: config::JumpHostResolved,
) -> Result<JumpHost, Box<dyn std::error::Error>> {
    let credential = if let Some(ref key_path) = jh.key_file {
        Credential::PrivateKeyFile {
            path: key_path.clone(),
            passphrase: jh.key_passphrase.clone(),
        }
    } else if let Some(ref pw) = jh.password {
        Credential::Password(pw.clone())
    } else {
        eprint!("Password for jump host {}@{}: ", jh.username, jh.host);
        let pw = rpassword::read_password()?;
        Credential::Password(pw)
    };

    Ok(JumpHost {
        host: jh.host,
        port: jh.port,
        username: jh.username,
        credential,
        legacy_crypto: jh.legacy_crypto,
    })
}

/// Connect to a device, disable paging, run all commands, and print the output.
///
/// Optionally saves output to a file under `args.output_dir` when set.
async fn run(args: ResolvedArgs) -> Result<(), Box<dyn std::error::Error>> {
    let credential = if let Some(ref key_path) = args.key_file {
        Credential::PrivateKeyFile {
            path: key_path.clone(),
            passphrase: args.key_passphrase.clone(),
        }
    } else if let Some(ref pw) = args.password {
        Credential::Password(pw.clone())
    } else {
        eprint!("Password for {}@{}: ", args.username, args.host);
        let pw = rpassword::read_password()?;
        Credential::Password(pw)
    };

    let jump = match args.jump_host {
        Some(jh) => Some(build_jump_host(jh)?),
        None => None,
    };

    let config = ConnectConfig {
        legacy_crypto: args.legacy_crypto,
        jumphost: jump,
        ..Default::default()
    };

    let timeout = Duration::from_secs(args.timeout);
    let profile = args.device_type.profile();
    let prompt_re = profile.prompt_regex();

    eprintln!("Connecting to {}:{}...", args.host, args.port);

    let mut session =
        Session::connect(&args.host, args.port, &args.username, credential, config).await?;

    eprintln!("Connected.");

    // Two-round drain to reach a clean prompt. The first round clears any
    // initial banner or MOTD (it may time out — that is OK). The second
    // round forces a fresh prompt response from the device, so
    // read_until_prompt_re will consume any data still in-flight (e.g.
    // a MikroTik MOTD that arrives after the first prompt) before
    // matching the new prompt, leaving the session in a clean state.
    let _ = session.write(b"\n").await;
    let _ = session
        .read_until_prompt_re(&prompt_re, Duration::from_secs(5))
        .await;
    let _ = session.write(b"\n").await;
    let _ = session
        .read_until_prompt_re(&prompt_re, Duration::from_secs(5))
        .await;

    // Disable paging (skip if the device profile has no paging command)
    if !profile.paging_disable.is_empty() {
        match session
            .send_command_re(profile.paging_disable, &prompt_re, Duration::from_secs(5))
            .await
        {
            Ok(_) => eprintln!("Paging disabled."),
            Err(e) => eprintln!("Warning: could not disable paging: {e}"),
        }
    }

    let mut buf = String::new();

    for cmd in &args.commands {
        eprintln!("\n--- {} ---", cmd);
        match session.send_command_clean(cmd, &prompt_re, timeout).await {
            Ok(output) => {
                print!("{output}");
                buf.push_str(&output);
            }
            Err(e) => {
                let msg = format!("Error running '{}': {e}\n", cmd);
                eprint!("{msg}");
                buf.push_str(&msg);
            }
        }
    }

    if let Err(e) = session.close().await {
        eprintln!("Close error: {e}");
    }

    if let Some(ref base) = args.output_dir {
        match writer::build_output_path(base, &args.host) {
            Ok(path) => {
                if let Err(e) = writer::write_output(&path, &buf) {
                    eprintln!("Error writing output file: {e}");
                } else {
                    eprintln!("Output saved to {}", path.display());
                }
            }
            Err(e) => eprintln!("Error creating output directory: {e}"),
        }
    }

    Ok(())
}

/// Connect to a device and verify that the prompt is detected correctly.
///
/// Prints the detected prompt line and exits without running any commands.
async fn run_check(args: ResolvedCheckArgs) -> Result<(), Box<dyn std::error::Error>> {
    let credential = if let Some(ref key_path) = args.key_file {
        Credential::PrivateKeyFile {
            path: key_path.clone(),
            passphrase: args.key_passphrase.clone(),
        }
    } else if let Some(ref pw) = args.password {
        Credential::Password(pw.clone())
    } else {
        eprint!("Password for {}@{}: ", args.username, args.host);
        let pw = rpassword::read_password()?;
        Credential::Password(pw)
    };

    let jump = match args.jump_host {
        Some(jh) => Some(build_jump_host(jh)?),
        None => None,
    };

    let config = ConnectConfig {
        legacy_crypto: args.legacy_crypto,
        jumphost: jump,
        ..Default::default()
    };

    let profile = args.device_type.profile();
    let prompt_re = profile.prompt_regex();

    eprintln!("Connecting to {}:{}...", args.host, args.port);

    let mut session =
        Session::connect(&args.host, args.port, &args.username, credential, config).await?;

    eprintln!("Connected. Checking prompt...");

    // Drain initial banner (may timeout on some devices, that's OK)
    let _ = session.write(b"\n").await;
    let _ = session
        .read_until_prompt_re(&prompt_re, Duration::from_secs(5))
        .await;

    // Send a newline and wait for the prompt
    let _ = session.write(b"\n").await;

    match session
        .read_until_prompt_re(&prompt_re, Duration::from_secs(10))
        .await
    {
        Ok(output) => {
            let clean = strip_ansi(&output);
            let prompt_line = clean.trim_end().lines().last().unwrap_or(&clean);
            eprintln!("Prompt detected: {}", prompt_line.trim());
            eprintln!("Check passed for {} ({:?})", args.host, args.device_type);
        }
        Err(e) => {
            eprintln!("Prompt detection failed for {}: {e}", args.host);
        }
    }

    if let Err(e) = session.close().await {
        eprintln!("Close error: {e}");
    }

    Ok(())
}

/// Connect to a device and upload a single file via SCP.
///
/// The remote destination is derived from `args.dest`; if omitted, the device's
/// `base_path` is combined with the source filename via [`resolve_dest`].
async fn run_scp(args: ResolvedScpArgs) -> Result<(), Box<dyn std::error::Error>> {
    let credential = if let Some(ref key_path) = args.key_file {
        Credential::PrivateKeyFile {
            path: key_path.clone(),
            passphrase: args.key_passphrase.clone(),
        }
    } else if let Some(ref pw) = args.password {
        Credential::Password(pw.clone())
    } else {
        eprint!("Password for {}@{}: ", args.username, args.host);
        let pw = rpassword::read_password()?;
        Credential::Password(pw)
    };

    let jump = match args.jump_host {
        Some(jh) => Some(build_jump_host(jh)?),
        None => None,
    };

    let config = ConnectConfig {
        legacy_crypto: args.legacy_crypto,
        jumphost: jump,
        ..Default::default()
    };

    let timeout_dur = Duration::from_secs(args.timeout);
    let dest = resolve_dest(&args.source, args.dest.as_deref(), args.device_type);

    eprintln!("Connecting to {}:{}...", args.host, args.port);

    let conn =
        Connection::connect(&args.host, args.port, &args.username, credential, config).await?;

    eprintln!("Uploading {} -> {}...", args.source, dest);

    conn.upload_file(Path::new(&args.source), &dest, timeout_dur)
        .await?;

    eprintln!("Upload complete.");

    if let Err(e) = conn.close().await {
        eprintln!("Close error: {e}");
    }

    Ok(())
}
