use lib_sshinto::{ConnectConfig, Credential, Session};
use std::time::Duration;

#[tokio::main]
async fn main() {
    let host = "172.31.0.11";
    let port = 22;
    let username = "sherpa";
    // let credential = Credential::Password("Everest1953!".into());
    let credential = Credential::PrivateKeyFile {
        path: "./sherpa_ssh_key".to_string(),
        passphrase: None,
    };
    let config = ConnectConfig::default();

    println!("Connecting to {host}:{port} as {username}...");

    let mut session = match Session::connect(host, port, username, credential, config).await {
        Ok(s) => {
            println!("Connected and authenticated!\n");
            s
        }
        Err(e) => {
            eprintln!("Connection failed: {e}");
            return;
        }
    };

    let prompt = "dev01#";

    // Drain any leftover and get to a clean prompt
    let _ = session.write(b"\n").await;
    let _ = session
        .read_until_prompt(prompt, Duration::from_secs(3))
        .await;

    // Disable paging so long output doesn't get stuck at --More--
    println!("Disabling paging...");
    match session
        .send_command("terminal length 0", prompt, Duration::from_secs(5))
        .await
    {
        Ok(_) => println!("Paging disabled.\n"),
        Err(e) => eprintln!("Warning: could not disable paging: {e}\n"),
    }

    // show version
    println!("=== show version ===");
    match session
        .send_command("show version", prompt, Duration::from_secs(10))
        .await
    {
        Ok(output) => println!("{output}"),
        Err(e) => eprintln!("Error: {e}"),
    }

    // show ip interface brief
    println!("\n=== show ip interface brief ===");
    match session
        .send_command("show ip interface brief", prompt, Duration::from_secs(10))
        .await
    {
        Ok(output) => println!("{output}"),
        Err(e) => eprintln!("Error: {e}"),
    }

    // show running-config hostname
    println!("\n=== show running-config | include hostname ===");
    match session
        .send_command(
            "show running-config | include hostname",
            prompt,
            Duration::from_secs(10),
        )
        .await
    {
        Ok(output) => println!("{output}"),
        Err(e) => eprintln!("Error: {e}"),
    }

    if let Err(e) = session.close().await {
        eprintln!("\nClose error: {e}");
    } else {
        println!("\nSession closed cleanly.");
    }
}
