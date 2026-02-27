use models::DeviceKind;
use serde::Deserialize;
use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;

use crate::cli::RunArgs;

// ── Error type ──────────────────────────────────────────────────────

#[derive(Debug)]
pub enum ConfigError {
    Io(std::io::Error),
    Parse(toml::de::Error),
    MissingField(&'static str),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Io(e) => write!(f, "config I/O error: {e}"),
            ConfigError::Parse(e) => write!(f, "config parse error: {e}"),
            ConfigError::MissingField(name) => {
                write!(f, "missing required field: {name}")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

// ── Config structs ──────────────────────────────────────────────────

#[derive(Debug, Default, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub defaults: Defaults,
    #[serde(default)]
    pub hosts: HashMap<String, HostEntry>,
}

#[derive(Debug, Default, Deserialize)]
pub struct Defaults {
    pub username: Option<String>,
    pub password: Option<String>,
    pub key_file: Option<String>,
    pub key_passphrase: Option<String>,
    pub port: Option<u16>,
    pub timeout: Option<u64>,
    pub legacy_crypto: Option<bool>,
    pub device_type: Option<DeviceKind>,
}

#[derive(Debug, Deserialize)]
pub struct HostEntry {
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

// ── Resolved args ───────────────────────────────────────────────────

#[derive(Debug)]
pub struct ResolvedArgs {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: Option<String>,
    pub key_file: Option<String>,
    pub key_passphrase: Option<String>,
    pub device_type: DeviceKind,
    pub legacy_crypto: bool,
    pub commands: Vec<String>,
    pub timeout: u64,
}

// ── Loading ─────────────────────────────────────────────────────────

impl Config {
    pub fn load() -> Result<Config, ConfigError> {
        // 1. ./sshinto.toml
        let local = PathBuf::from("sshinto.toml");
        if local.is_file() {
            let text = std::fs::read_to_string(&local).map_err(ConfigError::Io)?;
            return toml::from_str(&text).map_err(ConfigError::Parse);
        }

        // 2. ~/.sshinto/config.toml
        if let Some(home) = home_dir() {
            let global = home.join(".sshinto").join("sshinto.toml");
            if global.is_file() {
                let text = std::fs::read_to_string(&global).map_err(ConfigError::Io)?;
                return toml::from_str(&text).map_err(ConfigError::Parse);
            }
        }

        Ok(Config::default())
    }
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

// ── Resolution ──────────────────────────────────────────────────────

/// Merge CLI → host entry → defaults → hardcoded defaults.
pub fn resolve(cli: &RunArgs, config: &Config) -> Result<ResolvedArgs, ConfigError> {
    let host_entry = cli.name.as_ref().and_then(|n| config.hosts.get(n.as_str()));

    // Helper macro: first non-None in order wins
    macro_rules! pick {
        ($cli_field:expr, $host:ident . $field:ident, $def:ident . $dfield:ident) => {
            $cli_field
                .clone()
                .or_else(|| host_entry.and_then(|h| h.$field.clone()))
                .or_else(|| config.defaults.$dfield.clone())
        };
    }

    let host = cli
        .host
        .clone()
        .or_else(|| host_entry.map(|h| h.host.clone()))
        .ok_or(ConfigError::MissingField("host"))?;

    let username = pick!(cli.username, host.username, defaults.username)
        .ok_or(ConfigError::MissingField("username"))?;

    let device_type = cli
        .device_type
        .or_else(|| host_entry.and_then(|h| h.device_type))
        .or(config.defaults.device_type)
        .ok_or(ConfigError::MissingField("device_type"))?;

    let port = cli
        .port
        .or_else(|| host_entry.and_then(|h| h.port))
        .or(config.defaults.port)
        .unwrap_or(22);

    let timeout = cli
        .timeout
        .or_else(|| host_entry.and_then(|h| h.timeout))
        .or(config.defaults.timeout)
        .unwrap_or(10);

    // legacy_crypto: CLI flag is `bool` (default false). It acts as override
    // only when explicitly set (true). Otherwise fall through to config.
    let legacy_crypto = if cli.legacy_crypto {
        true
    } else {
        host_entry
            .and_then(|h| h.legacy_crypto)
            .or(config.defaults.legacy_crypto)
            .unwrap_or(false)
    };

    let password = pick!(cli.password, host.password, defaults.password);
    let key_file = pick!(cli.key_file, host.key_file, defaults.key_file);
    let key_passphrase = pick!(
        cli.key_passphrase,
        host.key_passphrase,
        defaults.key_passphrase
    );

    if cli.commands.is_empty() {
        return Err(ConfigError::MissingField("command (-c)"));
    }

    Ok(ResolvedArgs {
        host,
        port,
        username,
        password,
        key_file,
        key_passphrase,
        device_type,
        legacy_crypto,
        commands: cli.commands.clone(),
        timeout,
    })
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_config() -> Config {
        let toml_str = r#"
[defaults]
username = "sherpa"
timeout = 10

[hosts.lab-router]
host = "172.31.0.11"
device_type = "cisco_ios"
legacy_crypto = true

[hosts.core-switch]
host = "10.0.1.1"
port = 2222
device_type = "arista_eos"
username = "admin"
"#;
        toml::from_str(toml_str).unwrap()
    }

    fn empty_cli() -> RunArgs {
        RunArgs {
            name: None,
            host: None,
            port: None,
            username: None,
            password: None,
            key_file: None,
            key_passphrase: None,
            device_type: None,
            legacy_crypto: false,
            commands: vec!["show version".into()],
            timeout: None,
        }
    }

    #[test]
    fn resolve_named_host() {
        let config = sample_config();
        let mut cli = empty_cli();
        cli.name = Some("lab-router".into());

        let r = resolve(&cli, &config).unwrap();
        assert_eq!(r.host, "172.31.0.11");
        assert_eq!(r.username, "sherpa"); // from defaults
        assert_eq!(r.device_type, DeviceKind::CiscoIos);
        assert!(r.legacy_crypto);
        assert_eq!(r.port, 22);
        assert_eq!(r.timeout, 10);
    }

    #[test]
    fn cli_overrides_host_entry() {
        let config = sample_config();
        let mut cli = empty_cli();
        cli.name = Some("lab-router".into());
        cli.username = Some("override_user".into());
        cli.port = Some(2222);

        let r = resolve(&cli, &config).unwrap();
        assert_eq!(r.username, "override_user");
        assert_eq!(r.port, 2222);
    }

    #[test]
    fn fully_explicit_cli() {
        let config = Config::default();
        let cli = RunArgs {
            name: None,
            host: Some("1.2.3.4".into()),
            port: Some(22),
            username: Some("admin".into()),
            password: None,
            key_file: None,
            key_passphrase: None,
            device_type: Some(DeviceKind::AristaEos),
            legacy_crypto: false,
            commands: vec!["show version".into()],
            timeout: Some(5),
        };

        let r = resolve(&cli, &config).unwrap();
        assert_eq!(r.host, "1.2.3.4");
        assert_eq!(r.username, "admin");
        assert_eq!(r.timeout, 5);
    }

    #[test]
    fn missing_host_errors() {
        let config = Config::default();
        let cli = empty_cli();
        let err = resolve(&cli, &config).unwrap_err();
        assert!(matches!(err, ConfigError::MissingField("host")));
    }

    #[test]
    fn missing_commands_errors() {
        let config = sample_config();
        let mut cli = empty_cli();
        cli.name = Some("lab-router".into());
        cli.commands = vec![];

        let err = resolve(&cli, &config).unwrap_err();
        assert!(matches!(err, ConfigError::MissingField("command (-c)")));
    }

    #[test]
    fn parse_config_toml() {
        let config = sample_config();
        assert_eq!(config.defaults.username.as_deref(), Some("sherpa"));
        assert_eq!(config.hosts.len(), 2);
        assert_eq!(config.hosts["lab-router"].host, "172.31.0.11");
        assert_eq!(
            config.hosts["core-switch"].device_type,
            Some(DeviceKind::AristaEos)
        );
    }
}
