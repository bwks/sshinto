use models::DeviceKind;
use serde::Deserialize;
use std::sync::Arc;
use std::time::Duration;

use lib_sshinto::{ConnectConfig, Credential, Session};
use tokio::sync::Semaphore;

use crate::cli::JobArgs;
use crate::config::{ConfigError, ResolvedArgs};

// ── Jobfile structs ─────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct JobFile {
    #[serde(default)]
    pub defaults: JobDefaults,
    pub hosts: Vec<JobHostEntry>,
}

#[derive(Debug, Default, Deserialize)]
pub struct JobDefaults {
    pub username: Option<String>,
    pub password: Option<String>,
    pub key_file: Option<String>,
    pub key_passphrase: Option<String>,
    pub port: Option<u16>,
    pub timeout: Option<u64>,
    pub legacy_crypto: Option<bool>,
    pub device_type: Option<DeviceKind>,
    #[serde(default)]
    pub commands: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct JobHostEntry {
    pub name: String,
    pub host: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub key_file: Option<String>,
    pub key_passphrase: Option<String>,
    pub port: Option<u16>,
    pub timeout: Option<u64>,
    pub legacy_crypto: Option<bool>,
    pub device_type: Option<DeviceKind>,
}

// ── Loading ─────────────────────────────────────────────────────────

impl JobFile {
    pub fn load(path: &str) -> Result<JobFile, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(ConfigError::Io)?;
        let job: JobFile = toml::from_str(&text).map_err(ConfigError::Parse)?;

        if job.defaults.commands.is_empty() {
            return Err(ConfigError::MissingField("commands"));
        }
        if job.hosts.is_empty() {
            return Err(ConfigError::MissingField("hosts"));
        }

        Ok(job)
    }
}

// ── Resolution ──────────────────────────────────────────────────────

fn resolve_host(
    entry: &JobHostEntry,
    defaults: &JobDefaults,
    commands: &[String],
    password_override: Option<&str>,
) -> Result<ResolvedArgs, ConfigError> {
    macro_rules! pick {
        ($host_field:expr, $def_field:expr) => {
            $host_field.clone().or_else(|| $def_field.clone())
        };
    }

    let host = entry.host.clone();

    let username = pick!(entry.username, defaults.username)
        .ok_or(ConfigError::MissingField("username"))?;

    let device_type = entry
        .device_type
        .or(defaults.device_type)
        .ok_or(ConfigError::MissingField("device_type"))?;

    let port = entry.port.or(defaults.port).unwrap_or(22);
    let timeout = entry.timeout.or(defaults.timeout).unwrap_or(10);

    let legacy_crypto = entry
        .legacy_crypto
        .or(defaults.legacy_crypto)
        .unwrap_or(false);

    let key_file = pick!(entry.key_file, defaults.key_file);
    let key_passphrase = pick!(entry.key_passphrase, defaults.key_passphrase);

    let password = if key_file.is_some() {
        // Key-based auth: no password needed for SSH
        pick!(entry.password, defaults.password)
    } else {
        // Password auth: host → defaults → override (prompted)
        pick!(entry.password, defaults.password)
            .or_else(|| password_override.map(String::from))
    };

    Ok(ResolvedArgs {
        host,
        port,
        username,
        password,
        key_file,
        key_passphrase,
        device_type,
        legacy_crypto,
        commands: commands.to_vec(),
        timeout,
    })
}

// ── Per-host execution ──────────────────────────────────────────────

async fn run_single_host(
    name: String,
    args: ResolvedArgs,
) -> (String, String, Result<String, Box<dyn std::error::Error + Send + Sync>>) {
    let host = args.host.clone();
    match run_single_host_inner(args).await {
        Ok(output) => (name, host, Ok(output)),
        Err(e) => (name, host, Err(e)),
    }
}

async fn run_single_host_inner(
    args: ResolvedArgs,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let credential = if let Some(ref key_path) = args.key_file {
        Credential::PrivateKeyFile {
            path: key_path.clone(),
            passphrase: args.key_passphrase.clone(),
        }
    } else if let Some(ref pw) = args.password {
        Credential::Password(pw.clone())
    } else {
        return Err("no credential available".into());
    };

    let config = ConnectConfig {
        legacy_crypto: args.legacy_crypto,
        ..Default::default()
    };

    let timeout_dur = Duration::from_secs(args.timeout);
    let profile = args.device_type.profile();
    let prompt_re = profile.prompt_regex();

    let mut session =
        Session::connect(&args.host, args.port, &args.username, credential, config).await?;

    // Drain leftover output and get to a clean prompt
    let _ = session.write(b"\n").await;
    let _ = session
        .read_until_prompt_re(&prompt_re, Duration::from_secs(3))
        .await;

    // Disable paging
    let _ = session
        .send_command_re(profile.paging_disable, &prompt_re, Duration::from_secs(5))
        .await;

    let mut buf = String::new();

    for cmd in &args.commands {
        buf.push_str(&format!("\n--- {cmd} ---\n"));
        match session.send_command_re(cmd, &prompt_re, timeout_dur).await {
            Ok(output) => buf.push_str(&output),
            Err(e) => buf.push_str(&format!("Error running '{cmd}': {e}\n")),
        }
    }

    if let Err(e) = session.close().await {
        buf.push_str(&format!("\nClose error: {e}\n"));
    }

    Ok(buf)
}

// ── Orchestrator ────────────────────────────────────────────────────

pub async fn run_job(job_args: &JobArgs) -> Result<(), Box<dyn std::error::Error>> {
    let job = JobFile::load(&job_args.file)?;

    // Determine if we need to prompt for a password.
    // Prompt once if any host lacks both key_file and explicit password.
    let needs_password = job.hosts.iter().any(|h| {
        let has_key = h.key_file.is_some() || job.defaults.key_file.is_some();
        let has_pw = h.password.is_some() || job.defaults.password.is_some();
        !has_key && !has_pw
    });

    let password_override = if needs_password {
        eprint!("Password (for hosts without key or explicit password): ");
        Some(rpassword::read_password()?)
    } else {
        None
    };

    // Resolve all hosts up front so we fail fast on config errors.
    let mut resolved: Vec<(String, ResolvedArgs)> = Vec::with_capacity(job.hosts.len());
    for entry in &job.hosts {
        let args = resolve_host(entry, &job.defaults, &job.defaults.commands, password_override.as_deref())?;
        resolved.push((entry.name.clone(), args));
    }

    // Spawn tasks with optional concurrency limit.
    let semaphore = job_args.workers.map(|w| Arc::new(Semaphore::new(w)));

    let mut handles = Vec::with_capacity(resolved.len());
    for (name, args) in resolved {
        let sem = semaphore.clone();
        handles.push(tokio::spawn(async move {
            let _permit = match &sem {
                Some(s) => Some(
                    s.acquire()
                        .await
                        .expect("semaphore should not be closed"),
                ),
                None => None,
            };
            run_single_host(name, args).await
        }));
    }

    // Collect results in order.
    let mut results = Vec::with_capacity(handles.len());
    for handle in handles {
        results.push(handle.await?);
    }

    // Print grouped output.
    for (name, host, result) in &results {
        println!("\n=== {name} ({host}) ===");
        match result {
            Ok(output) => print!("{output}"),
            Err(e) => println!("\nError: {e}"),
        }
    }

    // Print summary.
    println!("\n=== Summary ===");
    for (name, _host, result) in &results {
        match result {
            Ok(_) => println!("{name}: ok"),
            Err(e) => println!("{name}: error - {e}"),
        }
    }

    Ok(())
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_jobfile() {
        let toml_str = r#"
[defaults]
username = "sherpa"
device_type = "cisco_ios"
timeout = 10

commands = ["show version", "show ip route"]

[[hosts]]
name = "lab-router"
host = "172.31.0.11"
legacy_crypto = true

[[hosts]]
name = "core-switch"
host = "10.0.1.1"
device_type = "arista_eos"
username = "admin"
"#;
        let job: JobFile = toml::from_str(toml_str).unwrap();
        assert_eq!(job.defaults.commands.len(), 2);
        assert_eq!(job.hosts.len(), 2);
        assert_eq!(job.hosts[0].name, "lab-router");
        assert_eq!(job.hosts[1].device_type, Some(DeviceKind::AristaEos));
        assert_eq!(job.defaults.username.as_deref(), Some("sherpa"));
    }

    #[test]
    fn resolve_host_merges_defaults() {
        let defaults = JobDefaults {
            username: Some("sherpa".into()),
            device_type: Some(DeviceKind::CiscoIos),
            timeout: Some(15),
            ..Default::default()
        };
        let entry = JobHostEntry {
            name: "r1".into(),
            host: "10.0.0.1".into(),
            username: None,
            password: None,
            key_file: None,
            key_passphrase: None,
            port: None,
            timeout: None,
            legacy_crypto: Some(true),
            device_type: None,
        };
        let commands = vec!["show version".into()];
        let r = resolve_host(&entry, &defaults, &commands, Some("pass123")).unwrap();
        assert_eq!(r.host, "10.0.0.1");
        assert_eq!(r.username, "sherpa");
        assert_eq!(r.device_type, DeviceKind::CiscoIos);
        assert_eq!(r.timeout, 15);
        assert!(r.legacy_crypto);
        assert_eq!(r.password.as_deref(), Some("pass123"));
    }

    #[test]
    fn resolve_host_entry_overrides_defaults() {
        let defaults = JobDefaults {
            username: Some("sherpa".into()),
            device_type: Some(DeviceKind::CiscoIos),
            ..Default::default()
        };
        let entry = JobHostEntry {
            name: "r1".into(),
            host: "10.0.0.1".into(),
            username: Some("admin".into()),
            password: Some("secret".into()),
            key_file: None,
            key_passphrase: None,
            port: Some(2222),
            timeout: None,
            legacy_crypto: None,
            device_type: Some(DeviceKind::AristaEos),
        };
        let commands = vec!["show version".into()];
        let r = resolve_host(&entry, &defaults, &commands, None).unwrap();
        assert_eq!(r.username, "admin");
        assert_eq!(r.password.as_deref(), Some("secret"));
        assert_eq!(r.port, 2222);
        assert_eq!(r.device_type, DeviceKind::AristaEos);
    }

    #[test]
    fn resolve_host_missing_username_errors() {
        let defaults = JobDefaults {
            device_type: Some(DeviceKind::CiscoIos),
            ..Default::default()
        };
        let entry = JobHostEntry {
            name: "r1".into(),
            host: "10.0.0.1".into(),
            username: None,
            password: None,
            key_file: None,
            key_passphrase: None,
            port: None,
            timeout: None,
            legacy_crypto: None,
            device_type: None,
        };
        let err = resolve_host(&entry, &defaults, &["show ver".into()], None).unwrap_err();
        assert!(matches!(err, ConfigError::MissingField("username")));
    }

    #[test]
    fn load_missing_file_errors() {
        let err = JobFile::load("/tmp/nonexistent_sshinto_jobfile.toml").unwrap_err();
        assert!(matches!(err, ConfigError::Io(_)));
    }
}
