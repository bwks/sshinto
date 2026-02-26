mod cli;

use cli::{Cli, Commands, RunArgs};
use clap::Parser;
use lib_sshinto::{ConnectConfig, Credential, Session};
use std::time::Duration;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Run(args) => run(args).await,
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

async fn run(args: RunArgs) -> Result<(), Box<dyn std::error::Error>> {
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

    let config = ConnectConfig {
        legacy_crypto: args.legacy_crypto,
        ..Default::default()
    };

    let timeout = Duration::from_secs(args.timeout);
    let profile = args.device_type.profile();
    let prompt_re = profile.prompt_regex();

    eprintln!("Connecting to {}:{}...", args.host, args.port);

    let mut session =
        Session::connect(&args.host, args.port, &args.username, credential, config).await?;

    eprintln!("Connected.");

    // Drain leftover output and get to a clean prompt
    let _ = session.write(b"\n").await;
    let _ = session
        .read_until_prompt_re(&prompt_re, Duration::from_secs(3))
        .await;

    // Disable paging
    match session
        .send_command_re(profile.paging_disable, &prompt_re, Duration::from_secs(5))
        .await
    {
        Ok(_) => eprintln!("Paging disabled."),
        Err(e) => eprintln!("Warning: could not disable paging: {e}"),
    }

    for cmd in &args.commands {
        eprintln!("\n--- {} ---", cmd);
        match session.send_command_re(cmd, &prompt_re, timeout).await {
            Ok(output) => print!("{output}"),
            Err(e) => eprintln!("Error running '{}': {e}", cmd),
        }
    }

    if let Err(e) = session.close().await {
        eprintln!("Close error: {e}");
    }

    Ok(())
}
