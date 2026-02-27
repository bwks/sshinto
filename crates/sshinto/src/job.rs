use models::DeviceKind;
use serde::Deserialize;
use std::sync::Arc;
use std::time::Duration;

use lib_sshinto::{ConnectConfig, Connection, Credential, JumpHost};
use tokio::sync::Semaphore;

use crate::cli::JobArgs;
use crate::config::{parse_jump_spec, Config, ConfigError, Defaults, JumpHostResolved, ResolvedArgs, ScpUpload};
use crate::writer;

// ── Jobfile structs ─────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct JobFile {
    #[serde(default)]
    pub defaults: JobDefaults,
    #[serde(default)]
    pub groups: Vec<JobGroup>,
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
    pub output_dir: Option<String>,
    pub jumphost: Option<String>,
    pub jumphost_username: Option<String>,
    pub jumphost_password: Option<String>,
    pub jumphost_key_file: Option<String>,
    pub jumphost_key_passphrase: Option<String>,
    pub jumphost_legacy_crypto: Option<bool>,
    #[serde(default)]
    pub uploads: Vec<ScpUpload>,
}

#[derive(Debug, Deserialize)]
pub struct JobGroup {
    pub name: String,
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
    pub jumphost: Option<String>,
    pub jumphost_username: Option<String>,
    pub jumphost_password: Option<String>,
    pub jumphost_key_file: Option<String>,
    pub jumphost_key_passphrase: Option<String>,
    pub jumphost_legacy_crypto: Option<bool>,
    #[serde(default)]
    pub uploads: Vec<ScpUpload>,
}

#[derive(Debug, Deserialize)]
pub struct JobHostEntry {
    pub name: String,
    pub host: String,
    pub group: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub key_file: Option<String>,
    pub key_passphrase: Option<String>,
    pub port: Option<u16>,
    pub timeout: Option<u64>,
    pub legacy_crypto: Option<bool>,
    pub device_type: Option<DeviceKind>,
    pub jumphost: Option<String>,
    pub jumphost_username: Option<String>,
    pub jumphost_password: Option<String>,
    pub jumphost_key_file: Option<String>,
    pub jumphost_key_passphrase: Option<String>,
    pub jumphost_legacy_crypto: Option<bool>,
    #[serde(default)]
    pub uploads: Vec<ScpUpload>,
}

// ── Loading ─────────────────────────────────────────────────────────

impl JobFile {
    pub fn load(path: &str) -> Result<JobFile, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(ConfigError::Io)?;
        let job: JobFile = toml::from_str(&text).map_err(ConfigError::Parse)?;

        if job.hosts.is_empty() {
            return Err(ConfigError::MissingField("hosts"));
        }

        // Validate that every host group reference points to an existing group.
        for entry in &job.hosts {
            if let Some(ref group_name) = entry.group {
                if !job.groups.iter().any(|g| g.name == *group_name) {
                    return Err(ConfigError::InvalidGroup(group_name.clone()));
                }
            }
        }

        // Commands must come from defaults or every host must get them from its group,
        // unless uploads are provided (a job with only uploads and no commands is valid).
        let has_default_uploads = !job.defaults.uploads.is_empty();
        if job.defaults.commands.is_empty() {
            let missing = job.hosts.iter().any(|h| {
                let group = h
                    .group
                    .as_ref()
                    .and_then(|gn| job.groups.iter().find(|g| g.name == *gn));
                let has_cmds = group.map_or(false, |g| !g.commands.is_empty());
                let has_uploads = !h.uploads.is_empty()
                    || group.map_or(false, |g| !g.uploads.is_empty())
                    || has_default_uploads;
                !has_cmds && !has_uploads
            });
            if missing {
                return Err(ConfigError::MissingField("commands"));
            }
        }

        Ok(job)
    }
}

// ── Resolution ──────────────────────────────────────────────────────

fn resolve_host(
    entry: &JobHostEntry,
    group: Option<&JobGroup>,
    defaults: &JobDefaults,
    config: &Defaults,
    commands: &[String],
    password_override: Option<&str>,
    cli_jump: Option<&CliJumpOverride>,
) -> Result<ResolvedArgs, ConfigError> {
    macro_rules! pick {
        ($host:expr, $group:expr, $def:expr, $cfg:expr) => {
            $host
                .clone()
                .or_else(|| $group.cloned())
                .or_else(|| $def.clone())
                .or_else(|| $cfg.clone())
        };
    }

    let host = entry.host.clone();

    let username = pick!(
        entry.username,
        group.and_then(|g| g.username.as_ref()),
        defaults.username,
        config.username
    )
    .ok_or(ConfigError::MissingField("username"))?;

    let device_type = entry
        .device_type
        .or(group.and_then(|g| g.device_type))
        .or(defaults.device_type)
        .or(config.device_type)
        .ok_or(ConfigError::MissingField("device_type"))?;

    let port = entry
        .port
        .or(group.and_then(|g| g.port))
        .or(defaults.port)
        .or(config.port)
        .unwrap_or(22);

    let timeout = entry
        .timeout
        .or(group.and_then(|g| g.timeout))
        .or(defaults.timeout)
        .or(config.timeout)
        .unwrap_or(10);

    let legacy_crypto = entry
        .legacy_crypto
        .or(group.and_then(|g| g.legacy_crypto))
        .or(defaults.legacy_crypto)
        .or(config.legacy_crypto)
        .unwrap_or(false);

    let key_file = pick!(
        entry.key_file,
        group.and_then(|g| g.key_file.as_ref()),
        defaults.key_file,
        config.key_file
    );
    let key_passphrase = pick!(
        entry.key_passphrase,
        group.and_then(|g| g.key_passphrase.as_ref()),
        defaults.key_passphrase,
        config.key_passphrase
    );

    let password = if key_file.is_some() {
        pick!(
            entry.password,
            group.and_then(|g| g.password.as_ref()),
            defaults.password,
            config.password
        )
    } else {
        pick!(
            entry.password,
            group.and_then(|g| g.password.as_ref()),
            defaults.password,
            config.password
        )
        .or_else(|| password_override.map(String::from))
    };

    // Commands: host has no per-host commands field, so use group commands if non-empty, else defaults.
    let resolved_commands = match group {
        Some(g) if !g.commands.is_empty() => &g.commands,
        _ => commands,
    };

    // Uploads: host entry uploads if non-empty, else group uploads, else defaults uploads.
    let resolved_uploads = if !entry.uploads.is_empty() {
        entry.uploads.clone()
    } else if let Some(g) = group {
        if !g.uploads.is_empty() {
            g.uploads.clone()
        } else {
            defaults.uploads.clone()
        }
    } else {
        defaults.uploads.clone()
    };

    let output_dir = defaults.output_dir.clone();

    // Resolve jump host: CLI override > host entry > group > job defaults > config defaults
    let jump_host = if let Some(cli_jh) = cli_jump {
        // CLI flag overrides everything
        let (jh_host, jh_port, mut jh_username) = parse_jump_spec(&cli_jh.spec, &username);
        if let Some(ref explicit_user) = cli_jh.username {
            jh_username = explicit_user.clone();
        }
        Some(JumpHostResolved {
            host: jh_host,
            port: jh_port,
            username: jh_username,
            password: cli_jh.password.clone(),
            key_file: cli_jh.key_file.clone(),
            key_passphrase: cli_jh.key_passphrase.clone(),
            legacy_crypto: cli_jh.legacy_crypto,
        })
    } else {
        let jh_spec = pick!(
            entry.jumphost,
            group.and_then(|g| g.jumphost.as_ref()),
            defaults.jumphost,
            config.jumphost
        );

        if let Some(spec) = jh_spec {
            let (jh_host, jh_port, mut jh_username) = parse_jump_spec(&spec, &username);

            // Explicit jumphost_username overrides the parsed spec username
            let explicit_user = pick!(
                entry.jumphost_username,
                group.and_then(|g| g.jumphost_username.as_ref()),
                defaults.jumphost_username,
                config.jumphost_username
            );
            if let Some(user) = explicit_user {
                jh_username = user;
            }

            let jh_password = pick!(
                entry.jumphost_password,
                group.and_then(|g| g.jumphost_password.as_ref()),
                defaults.jumphost_password,
                config.jumphost_password
            );
            let jh_key_file = pick!(
                entry.jumphost_key_file,
                group.and_then(|g| g.jumphost_key_file.as_ref()),
                defaults.jumphost_key_file,
                config.jumphost_key_file
            );
            let jh_key_passphrase = pick!(
                entry.jumphost_key_passphrase,
                group.and_then(|g| g.jumphost_key_passphrase.as_ref()),
                defaults.jumphost_key_passphrase,
                config.jumphost_key_passphrase
            );
            let jh_legacy_crypto = entry
                .jumphost_legacy_crypto
                .or(group.and_then(|g| g.jumphost_legacy_crypto))
                .or(defaults.jumphost_legacy_crypto)
                .or(config.jumphost_legacy_crypto)
                .unwrap_or(false);

            Some(JumpHostResolved {
                host: jh_host,
                port: jh_port,
                username: jh_username,
                password: jh_password,
                key_file: jh_key_file,
                key_passphrase: jh_key_passphrase,
                legacy_crypto: jh_legacy_crypto,
            })
        } else {
            None
        }
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
        commands: resolved_commands.to_vec(),
        timeout,
        output_dir,
        jump_host,
        uploads: resolved_uploads,
    })
}

/// CLI jump host override, extracted from JobArgs.
struct CliJumpOverride {
    spec: String,
    username: Option<String>,
    password: Option<String>,
    key_file: Option<String>,
    key_passphrase: Option<String>,
    legacy_crypto: bool,
}

// ── Per-host execution ──────────────────────────────────────────────

async fn run_single_host(
    name: String,
    args: ResolvedArgs,
    output_dir: Option<String>,
) -> (String, String, Result<String, Box<dyn std::error::Error + Send + Sync>>) {
    let host = args.host.clone();
    match run_single_host_inner(&name, args, output_dir).await {
        Ok(output) => (name, host, Ok(output)),
        Err(e) => (name, host, Err(e)),
    }
}

fn build_jump_host(jh: JumpHostResolved) -> Result<JumpHost, Box<dyn std::error::Error + Send + Sync>> {
    let credential = if let Some(ref key_path) = jh.key_file {
        Credential::PrivateKeyFile {
            path: key_path.clone(),
            passphrase: jh.key_passphrase.clone(),
        }
    } else if let Some(ref pw) = jh.password {
        Credential::Password(pw.clone())
    } else {
        return Err("no credential available for jump host".into());
    };

    Ok(JumpHost {
        host: jh.host,
        port: jh.port,
        username: jh.username,
        credential,
        legacy_crypto: jh.legacy_crypto,
    })
}

async fn run_single_host_inner(
    name: &str,
    args: ResolvedArgs,
    output_dir: Option<String>,
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
    let profile = args.device_type.profile();
    let prompt_re = profile.prompt_regex();

    let conn =
        Connection::connect(&args.host, args.port, &args.username, credential, config).await?;

    // Upload files before opening the shell channel (some devices like Cisco IOS
    // only support one channel at a time).
    for upload in &args.uploads {
        let source = std::path::Path::new(&upload.source);
        match conn.upload_file(source, &upload.dest, timeout_dur).await {
            Ok(()) => eprintln!("[{name}] Uploaded {} -> {}", upload.source, upload.dest),
            Err(e) => return Err(format!("upload {} -> {}: {e}", upload.source, upload.dest).into()),
        }
    }

    let mut session = conn.open_shell().await?;

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
        match session.send_command_clean(cmd, &prompt_re, timeout_dur).await {
            Ok(output) => buf.push_str(&output),
            Err(e) => buf.push_str(&format!("Error running '{cmd}': {e}\n")),
        }
    }

    if let Some(ref base) = output_dir {
        match writer::build_output_path(base, name) {
            Ok(path) => {
                if let Err(e) = writer::write_output(&path, &buf) {
                    eprintln!("[{name}] Error writing output file: {e}");
                } else {
                    eprintln!("[{name}] Output saved to {}", path.display());
                }
            }
            Err(e) => eprintln!("[{name}] Error creating output directory: {e}"),
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
    let config = Config::load().unwrap_or_default();

    // Build CLI jump override if provided.
    let cli_jump = job_args.jumphost.as_ref().map(|spec| CliJumpOverride {
        spec: spec.clone(),
        username: job_args.jumphost_username.clone(),
        password: job_args.jumphost_password.clone(),
        key_file: job_args.jumphost_key_file.clone(),
        key_passphrase: job_args.jumphost_key_passphrase.clone(),
        legacy_crypto: job_args.jumphost_legacy_crypto,
    });

    // Determine if we need to prompt for a password.
    // Prompt once if any host lacks both key_file and explicit password.
    let needs_password = job.hosts.iter().any(|h| {
        let group = h
            .group
            .as_ref()
            .and_then(|gn| job.groups.iter().find(|g| g.name == *gn));
        let has_key = h.key_file.is_some()
            || group.and_then(|g| g.key_file.as_ref()).is_some()
            || job.defaults.key_file.is_some()
            || config.defaults.key_file.is_some();
        let has_pw = h.password.is_some()
            || group.and_then(|g| g.password.as_ref()).is_some()
            || job.defaults.password.is_some()
            || config.defaults.password.is_some();
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
        let group = entry
            .group
            .as_ref()
            .and_then(|gn| job.groups.iter().find(|g| g.name == *gn));
        let args = resolve_host(
            entry,
            group,
            &job.defaults,
            &config.defaults,
            &job.defaults.commands,
            password_override.as_deref(),
            cli_jump.as_ref(),
        )?;
        resolved.push((entry.name.clone(), args));
    }

    // Resolve output_dir: CLI flag takes priority over job defaults.
    let output_dir = job_args
        .output_dir
        .clone()
        .or_else(|| job.defaults.output_dir.clone());

    // Spawn tasks with optional concurrency limit.
    let semaphore = job_args.workers.map(|w| Arc::new(Semaphore::new(w)));

    let mut handles = Vec::with_capacity(resolved.len());
    for (name, args) in resolved {
        let sem = semaphore.clone();
        let out_dir = output_dir.clone();
        handles.push(tokio::spawn(async move {
            let _permit = match &sem {
                Some(s) => Some(
                    s.acquire()
                        .await
                        .expect("semaphore should not be closed"),
                ),
                None => None,
            };
            run_single_host(name, args, out_dir).await
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
            group: None,
            username: None,
            password: None,
            key_file: None,
            key_passphrase: None,
            port: None,
            timeout: None,
            legacy_crypto: Some(true),
            device_type: None,
            jumphost: None,
            jumphost_username: None,
            jumphost_password: None,
            jumphost_key_file: None,
            jumphost_key_passphrase: None,
            jumphost_legacy_crypto: None,
            uploads: vec![],
        };
        let commands = vec!["show version".into()];
        let r = resolve_host(&entry, None, &defaults, &Defaults::default(), &commands, Some("pass123"), None).unwrap();
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
            group: None,
            username: Some("admin".into()),
            password: Some("secret".into()),
            key_file: None,
            key_passphrase: None,
            port: Some(2222),
            timeout: None,
            legacy_crypto: None,
            device_type: Some(DeviceKind::AristaEos),
            jumphost: None,
            jumphost_username: None,
            jumphost_password: None,
            jumphost_key_file: None,
            jumphost_key_passphrase: None,
            jumphost_legacy_crypto: None,
            uploads: vec![],
        };
        let commands = vec!["show version".into()];
        let r = resolve_host(&entry, None, &defaults, &Defaults::default(), &commands, None, None).unwrap();
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
            group: None,
            username: None,
            password: None,
            key_file: None,
            key_passphrase: None,
            port: None,
            timeout: None,
            legacy_crypto: None,
            device_type: None,
            jumphost: None,
            jumphost_username: None,
            jumphost_password: None,
            jumphost_key_file: None,
            jumphost_key_passphrase: None,
            jumphost_legacy_crypto: None,
            uploads: vec![],
        };
        let err = resolve_host(&entry, None, &defaults, &Defaults::default(), &["show ver".into()], None, None).unwrap_err();
        assert!(matches!(err, ConfigError::MissingField("username")));
    }

    #[test]
    fn resolve_host_group_overrides_defaults() {
        let defaults = JobDefaults {
            username: Some("sherpa".into()),
            device_type: Some(DeviceKind::CiscoIos),
            timeout: Some(10),
            ..Default::default()
        };
        let group = JobGroup {
            name: "eos_devices".into(),
            username: None,
            password: None,
            key_file: None,
            key_passphrase: None,
            port: None,
            timeout: Some(20),
            legacy_crypto: Some(true),
            device_type: Some(DeviceKind::AristaEos),
            commands: vec![],
            jumphost: None,
            jumphost_username: None,
            jumphost_password: None,
            jumphost_key_file: None,
            jumphost_key_passphrase: None,
            jumphost_legacy_crypto: None,
            uploads: vec![],
        };
        let entry = JobHostEntry {
            name: "sw1".into(),
            host: "10.0.0.2".into(),
            group: Some("eos_devices".into()),
            username: None,
            password: None,
            key_file: None,
            key_passphrase: None,
            port: None,
            timeout: None,
            legacy_crypto: None,
            device_type: None,
            jumphost: None,
            jumphost_username: None,
            jumphost_password: None,
            jumphost_key_file: None,
            jumphost_key_passphrase: None,
            jumphost_legacy_crypto: None,
            uploads: vec![],
        };
        let commands = vec!["show version".into()];
        let r = resolve_host(&entry, Some(&group), &defaults, &Defaults::default(), &commands, None, None).unwrap();
        assert_eq!(r.device_type, DeviceKind::AristaEos);
        assert_eq!(r.timeout, 20);
        assert!(r.legacy_crypto);
        assert_eq!(r.username, "sherpa"); // falls through group (None) to defaults
    }

    #[test]
    fn resolve_host_entry_overrides_group() {
        let defaults = JobDefaults {
            username: Some("sherpa".into()),
            device_type: Some(DeviceKind::CiscoIos),
            ..Default::default()
        };
        let group = JobGroup {
            name: "ios_devices".into(),
            username: Some("group_user".into()),
            password: None,
            key_file: None,
            key_passphrase: None,
            port: Some(830),
            timeout: Some(20),
            legacy_crypto: Some(true),
            device_type: Some(DeviceKind::CiscoIos),
            commands: vec![],
            jumphost: None,
            jumphost_username: None,
            jumphost_password: None,
            jumphost_key_file: None,
            jumphost_key_passphrase: None,
            jumphost_legacy_crypto: None,
            uploads: vec![],
        };
        let entry = JobHostEntry {
            name: "r1".into(),
            host: "10.0.0.1".into(),
            group: Some("ios_devices".into()),
            username: Some("host_user".into()),
            password: None,
            key_file: None,
            key_passphrase: None,
            port: Some(22),
            timeout: None,
            legacy_crypto: None,
            device_type: None,
            jumphost: None,
            jumphost_username: None,
            jumphost_password: None,
            jumphost_key_file: None,
            jumphost_key_passphrase: None,
            jumphost_legacy_crypto: None,
            uploads: vec![],
        };
        let commands = vec!["show version".into()];
        let r = resolve_host(&entry, Some(&group), &defaults, &Defaults::default(), &commands, None, None).unwrap();
        assert_eq!(r.username, "host_user"); // host overrides group
        assert_eq!(r.port, 22); // host overrides group
        assert_eq!(r.timeout, 20); // from group (host is None)
    }

    #[test]
    fn group_commands_override_defaults() {
        let defaults = JobDefaults {
            username: Some("sherpa".into()),
            device_type: Some(DeviceKind::CiscoIos),
            ..Default::default()
        };
        let group = JobGroup {
            name: "special".into(),
            username: None,
            password: None,
            key_file: None,
            key_passphrase: None,
            port: None,
            timeout: None,
            legacy_crypto: None,
            device_type: None,
            commands: vec!["show inventory".into()],
            jumphost: None,
            jumphost_username: None,
            jumphost_password: None,
            jumphost_key_file: None,
            jumphost_key_passphrase: None,
            jumphost_legacy_crypto: None,
            uploads: vec![],
        };
        let entry = JobHostEntry {
            name: "r1".into(),
            host: "10.0.0.1".into(),
            group: Some("special".into()),
            username: None,
            password: None,
            key_file: None,
            key_passphrase: None,
            port: None,
            timeout: None,
            legacy_crypto: None,
            device_type: None,
            jumphost: None,
            jumphost_username: None,
            jumphost_password: None,
            jumphost_key_file: None,
            jumphost_key_passphrase: None,
            jumphost_legacy_crypto: None,
            uploads: vec![],
        };
        let default_commands = vec!["show version".into()];
        let r = resolve_host(&entry, Some(&group), &defaults, &Defaults::default(), &default_commands, None, None).unwrap();
        assert_eq!(r.commands, vec!["show inventory".to_string()]);
    }

    #[test]
    fn invalid_group_reference_errors() {
        let toml_str = r#"
[defaults]
username = "sherpa"
device_type = "cisco_ios"
commands = ["show version"]

[[hosts]]
name = "r1"
host = "10.0.0.1"
group = "nonexistent"
"#;
        let _job: JobFile = toml::from_str(toml_str).unwrap();
        // load() validates group references, so we test via load with a temp file
        let tmp = std::env::temp_dir().join("sshinto_test_invalid_group.toml");
        std::fs::write(&tmp, toml_str).unwrap();
        let err = JobFile::load(tmp.to_str().unwrap()).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidGroup(_)));
        std::fs::remove_file(&tmp).unwrap();
    }

    #[test]
    fn parse_jobfile_with_groups() {
        let toml_str = r#"
[defaults]
username = "sherpa"
commands = ["show version"]

[[groups]]
name = "ios_devices"
device_type = "cisco_ios"
legacy_crypto = true
timeout = 10

[[groups]]
name = "eos_devices"
device_type = "arista_eos"
timeout = 15

[[hosts]]
name = "lab-router"
host = "172.31.0.11"
group = "ios_devices"

[[hosts]]
name = "core-switch"
host = "10.0.1.1"
group = "eos_devices"
username = "admin"
"#;
        let job: JobFile = toml::from_str(toml_str).unwrap();
        assert_eq!(job.groups.len(), 2);
        assert_eq!(job.groups[0].name, "ios_devices");
        assert_eq!(job.groups[0].device_type, Some(DeviceKind::CiscoIos));
        assert_eq!(job.groups[1].name, "eos_devices");
        assert_eq!(job.hosts[0].group.as_deref(), Some("ios_devices"));
        assert_eq!(job.hosts[1].group.as_deref(), Some("eos_devices"));
    }

    #[test]
    fn load_missing_file_errors() {
        let err = JobFile::load("/tmp/nonexistent_sshinto_jobfile.toml").unwrap_err();
        assert!(matches!(err, ConfigError::Io(_)));
    }

    #[test]
    fn resolve_host_with_jump_from_defaults() {
        let defaults = JobDefaults {
            username: Some("sherpa".into()),
            device_type: Some(DeviceKind::CiscoIos),
            jumphost: Some("admin@bastion:2222".into()),
            jumphost_password: Some("jumppass".into()),
            jumphost_legacy_crypto: Some(true),
            ..Default::default()
        };
        let entry = JobHostEntry {
            name: "r1".into(),
            host: "10.0.0.1".into(),
            group: None,
            username: None,
            password: Some("pass".into()),
            key_file: None,
            key_passphrase: None,
            port: None,
            timeout: None,
            legacy_crypto: None,
            device_type: None,
            jumphost: None,
            jumphost_username: None,
            jumphost_password: None,
            jumphost_key_file: None,
            jumphost_key_passphrase: None,
            jumphost_legacy_crypto: None,
            uploads: vec![],
        };
        let commands = vec!["show version".into()];
        let r = resolve_host(&entry, None, &defaults, &Defaults::default(), &commands, None, None).unwrap();
        let jh = r.jump_host.expect("should have jump host");
        assert_eq!(jh.host, "bastion");
        assert_eq!(jh.port, 2222);
        assert_eq!(jh.username, "admin");
        assert_eq!(jh.password.as_deref(), Some("jumppass"));
        assert!(jh.legacy_crypto);
    }

    #[test]
    fn cli_jump_overrides_jobfile() {
        let defaults = JobDefaults {
            username: Some("sherpa".into()),
            device_type: Some(DeviceKind::CiscoIos),
            jumphost: Some("admin@bastion:2222".into()),
            ..Default::default()
        };
        let entry = JobHostEntry {
            name: "r1".into(),
            host: "10.0.0.1".into(),
            group: None,
            username: None,
            password: Some("pass".into()),
            key_file: None,
            key_passphrase: None,
            port: None,
            timeout: None,
            legacy_crypto: None,
            device_type: None,
            jumphost: None,
            jumphost_username: None,
            jumphost_password: None,
            jumphost_key_file: None,
            jumphost_key_passphrase: None,
            jumphost_legacy_crypto: None,
            uploads: vec![],
        };
        let commands = vec!["show version".into()];
        let cli_jh = CliJumpOverride {
            spec: "override@jump:3333".into(),
            username: None,
            password: Some("clipass".into()),
            key_file: None,
            key_passphrase: None,
            legacy_crypto: false,
        };
        let r = resolve_host(&entry, None, &defaults, &Defaults::default(), &commands, None, Some(&cli_jh)).unwrap();
        let jh = r.jump_host.expect("should have jump host");
        assert_eq!(jh.host, "jump");
        assert_eq!(jh.port, 3333);
        assert_eq!(jh.username, "override");
        assert_eq!(jh.password.as_deref(), Some("clipass"));
    }
}
