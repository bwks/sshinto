use models::DeviceKind;
use serde::Deserialize;
use std::fmt;
use std::path::PathBuf;

use crate::cli::{RunArgs, ScpArgs};

// ── Error type ──────────────────────────────────────────────────────

#[derive(Debug)]
pub enum ConfigError {
    Io(std::io::Error),
    Parse(toml::de::Error),
    MissingField(&'static str),
    InvalidGroup(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Io(e) => write!(f, "config I/O error: {e}"),
            ConfigError::Parse(e) => write!(f, "config parse error: {e}"),
            ConfigError::MissingField(name) => {
                write!(f, "missing required field: {name}")
            }
            ConfigError::InvalidGroup(name) => {
                write!(f, "host references unknown group: {name}")
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
    pub output_dir: Option<String>,
    pub jumphost: Option<String>,
    pub jumphost_username: Option<String>,
    pub jumphost_password: Option<String>,
    pub jumphost_key_file: Option<String>,
    pub jumphost_key_passphrase: Option<String>,
    pub jumphost_legacy_crypto: Option<bool>,
}

// ── SCP upload ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct ScpUpload {
    pub source: String,
    pub dest: String,
}

// ── Resolved args ───────────────────────────────────────────────────

#[derive(Debug)]
pub struct JumpHostResolved {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: Option<String>,
    pub key_file: Option<String>,
    pub key_passphrase: Option<String>,
    pub legacy_crypto: bool,
}

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
    pub output_dir: Option<String>,
    pub jump_host: Option<JumpHostResolved>,
    pub uploads: Vec<ScpUpload>,
}

#[derive(Debug)]
pub struct ResolvedScpArgs {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: Option<String>,
    pub key_file: Option<String>,
    pub key_passphrase: Option<String>,
    pub legacy_crypto: bool,
    pub source: String,
    pub dest: String,
    pub timeout: u64,
    pub jump_host: Option<JumpHostResolved>,
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

// ── Jump host spec parsing ──────────────────────────────────────────

/// Parse a jump host spec like `user@host:port`, `host:port`, `user@host`, or `host`.
/// Returns `(host, port, username)`. Falls back to `default_username` and port 22.
pub fn parse_jump_spec(spec: &str, default_username: &str) -> (String, u16, String) {
    let (username, rest) = if let Some(idx) = spec.find('@') {
        (spec[..idx].to_string(), &spec[idx + 1..])
    } else {
        (default_username.to_string(), spec)
    };

    let (host, port) = if let Some(idx) = rest.rfind(':') {
        if let Ok(p) = rest[idx + 1..].parse::<u16>() {
            (rest[..idx].to_string(), p)
        } else {
            (rest.to_string(), 22)
        }
    } else {
        (rest.to_string(), 22)
    };

    (host, port, username)
}

// ── Resolution ──────────────────────────────────────────────────────

/// Merge CLI → defaults → hardcoded defaults.
pub fn resolve(cli: &RunArgs, config: &Config) -> Result<ResolvedArgs, ConfigError> {
    macro_rules! pick {
        ($cli_field:expr, $def:ident . $dfield:ident) => {
            $cli_field
                .clone()
                .or_else(|| config.defaults.$dfield.clone())
        };
    }

    let host = cli.host.clone().ok_or(ConfigError::MissingField("host"))?;

    let username =
        pick!(cli.username, defaults.username).ok_or(ConfigError::MissingField("username"))?;

    let device_type = cli
        .device_type
        .or(config.defaults.device_type)
        .ok_or(ConfigError::MissingField("device_type"))?;

    let port = cli.port.or(config.defaults.port).unwrap_or(22);

    let timeout = cli.timeout.or(config.defaults.timeout).unwrap_or(10);

    let legacy_crypto = if cli.legacy_crypto {
        true
    } else {
        config.defaults.legacy_crypto.unwrap_or(false)
    };

    let password = pick!(cli.password, defaults.password);
    let key_file = pick!(cli.key_file, defaults.key_file);
    let key_passphrase = pick!(cli.key_passphrase, defaults.key_passphrase);
    let output_dir = cli.output_dir.clone().or_else(|| config.defaults.output_dir.clone());

    if cli.commands.is_empty() {
        return Err(ConfigError::MissingField("command (-c)"));
    }

    // Resolve jump host
    let jump_spec = cli
        .jumphost
        .clone()
        .or_else(|| config.defaults.jumphost.clone());

    let jump_host = if let Some(spec) = jump_spec {
        let (jh_host, jh_port, mut jh_username) = parse_jump_spec(&spec, &username);

        // Explicit jumphost_username overrides the parsed spec username
        if let Some(ref explicit_user) = cli.jumphost_username.clone().or_else(|| config.defaults.jumphost_username.clone()) {
            jh_username = explicit_user.clone();
        }

        let jh_password = cli
            .jumphost_password
            .clone()
            .or_else(|| config.defaults.jumphost_password.clone());
        let jh_key_file = cli
            .jumphost_key_file
            .clone()
            .or_else(|| config.defaults.jumphost_key_file.clone());
        let jh_key_passphrase = cli
            .jumphost_key_passphrase
            .clone()
            .or_else(|| config.defaults.jumphost_key_passphrase.clone());
        let jh_legacy_crypto = if cli.jumphost_legacy_crypto {
            true
        } else {
            config.defaults.jumphost_legacy_crypto.unwrap_or(false)
        };

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
        commands: cli.commands.clone(),
        timeout,
        output_dir,
        jump_host,
        uploads: Vec::new(),
    })
}

/// Merge CLI → defaults → hardcoded defaults for SCP.
pub fn resolve_scp(cli: &ScpArgs, config: &Config) -> Result<ResolvedScpArgs, ConfigError> {
    macro_rules! pick {
        ($cli_field:expr, $def:ident . $dfield:ident) => {
            $cli_field
                .clone()
                .or_else(|| config.defaults.$dfield.clone())
        };
    }

    let host = cli.host.clone().ok_or(ConfigError::MissingField("host"))?;

    let username =
        pick!(cli.username, defaults.username).ok_or(ConfigError::MissingField("username"))?;

    let port = cli.port.or(config.defaults.port).unwrap_or(22);

    let timeout = cli.timeout;

    let legacy_crypto = if cli.legacy_crypto {
        true
    } else {
        config.defaults.legacy_crypto.unwrap_or(false)
    };

    let password = pick!(cli.password, defaults.password);
    let key_file = pick!(cli.key_file, defaults.key_file);
    let key_passphrase = pick!(cli.key_passphrase, defaults.key_passphrase);

    // Resolve jump host
    let jump_spec = cli
        .jumphost
        .clone()
        .or_else(|| config.defaults.jumphost.clone());

    let jump_host = if let Some(spec) = jump_spec {
        let (jh_host, jh_port, mut jh_username) = parse_jump_spec(&spec, &username);

        if let Some(ref explicit_user) = cli.jumphost_username.clone().or_else(|| config.defaults.jumphost_username.clone()) {
            jh_username = explicit_user.clone();
        }

        let jh_password = cli
            .jumphost_password
            .clone()
            .or_else(|| config.defaults.jumphost_password.clone());
        let jh_key_file = cli
            .jumphost_key_file
            .clone()
            .or_else(|| config.defaults.jumphost_key_file.clone());
        let jh_key_passphrase = cli
            .jumphost_key_passphrase
            .clone()
            .or_else(|| config.defaults.jumphost_key_passphrase.clone());
        let jh_legacy_crypto = if cli.jumphost_legacy_crypto {
            true
        } else {
            config.defaults.jumphost_legacy_crypto.unwrap_or(false)
        };

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
    };

    Ok(ResolvedScpArgs {
        host,
        port,
        username,
        password,
        key_file,
        key_passphrase,
        legacy_crypto,
        source: cli.source.clone(),
        dest: cli.dest.clone(),
        timeout,
        jump_host,
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
"#;
        toml::from_str(toml_str).unwrap()
    }

    fn empty_cli() -> RunArgs {
        RunArgs {
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
            output_dir: None,
            jumphost: None,
            jumphost_username: None,
            jumphost_password: None,
            jumphost_key_file: None,
            jumphost_key_passphrase: None,
            jumphost_legacy_crypto: false,
        }
    }

    #[test]
    fn fully_explicit_cli() {
        let config = Config::default();
        let cli = RunArgs {
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
            output_dir: None,
            jumphost: None,
            jumphost_username: None,
            jumphost_password: None,
            jumphost_key_file: None,
            jumphost_key_passphrase: None,
            jumphost_legacy_crypto: false,
        };

        let r = resolve(&cli, &config).expect("should resolve");
        assert_eq!(r.host, "1.2.3.4");
        assert_eq!(r.username, "admin");
        assert_eq!(r.timeout, 5);
    }

    #[test]
    fn defaults_fill_gaps() {
        let config = sample_config();
        let mut cli = empty_cli();
        cli.host = Some("10.0.0.1".into());
        cli.device_type = Some(DeviceKind::CiscoIos);

        let r = resolve(&cli, &config).expect("should resolve");
        assert_eq!(r.username, "sherpa"); // from defaults
        assert_eq!(r.timeout, 10); // from defaults
    }

    #[test]
    fn cli_overrides_defaults() {
        let config = sample_config();
        let mut cli = empty_cli();
        cli.host = Some("10.0.0.1".into());
        cli.device_type = Some(DeviceKind::CiscoIos);
        cli.username = Some("override_user".into());
        cli.port = Some(2222);

        let r = resolve(&cli, &config).expect("should resolve");
        assert_eq!(r.username, "override_user");
        assert_eq!(r.port, 2222);
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
        cli.host = Some("10.0.0.1".into());
        cli.device_type = Some(DeviceKind::CiscoIos);
        cli.commands = vec![];

        let err = resolve(&cli, &config).unwrap_err();
        assert!(matches!(err, ConfigError::MissingField("command (-c)")));
    }

    #[test]
    fn parse_defaults_only_config() {
        let config = sample_config();
        assert_eq!(config.defaults.username.as_deref(), Some("sherpa"));
        assert_eq!(config.defaults.timeout, Some(10));
    }

    // ── parse_jump_spec tests ───────────────────────────────────────

    #[test]
    fn parse_jump_spec_host_only() {
        let (host, port, user) = parse_jump_spec("bastion.example.com", "default_user");
        assert_eq!(host, "bastion.example.com");
        assert_eq!(port, 22);
        assert_eq!(user, "default_user");
    }

    #[test]
    fn parse_jump_spec_host_port() {
        let (host, port, user) = parse_jump_spec("bastion.example.com:2222", "default_user");
        assert_eq!(host, "bastion.example.com");
        assert_eq!(port, 2222);
        assert_eq!(user, "default_user");
    }

    #[test]
    fn parse_jump_spec_user_host() {
        let (host, port, user) = parse_jump_spec("admin@bastion.example.com", "default_user");
        assert_eq!(host, "bastion.example.com");
        assert_eq!(port, 22);
        assert_eq!(user, "admin");
    }

    #[test]
    fn parse_jump_spec_user_host_port() {
        let (host, port, user) = parse_jump_spec("admin@bastion.example.com:2222", "default_user");
        assert_eq!(host, "bastion.example.com");
        assert_eq!(port, 2222);
        assert_eq!(user, "admin");
    }

    #[test]
    fn parse_jump_spec_ip_address() {
        let (host, port, user) = parse_jump_spec("sherpa@172.31.0.11:22", "default");
        assert_eq!(host, "172.31.0.11");
        assert_eq!(port, 22);
        assert_eq!(user, "sherpa");
    }

    // ── jump host resolution tests ──────────────────────────────────

    #[test]
    fn resolve_with_jump_host() {
        let config = sample_config();
        let mut cli = empty_cli();
        cli.host = Some("10.0.0.1".into());
        cli.device_type = Some(DeviceKind::CiscoIos);
        cli.jumphost = Some("admin@bastion:2222".into());
        cli.jumphost_password = Some("jumppass".into());
        cli.jumphost_legacy_crypto = true;

        let r = resolve(&cli, &config).expect("should resolve");
        let jh = r.jump_host.expect("should have jump host");
        assert_eq!(jh.host, "bastion");
        assert_eq!(jh.port, 2222);
        assert_eq!(jh.username, "admin");
        assert_eq!(jh.password.as_deref(), Some("jumppass"));
        assert!(jh.legacy_crypto);
    }

    #[test]
    fn resolve_jump_host_defaults_username_from_target() {
        let config = sample_config();
        let mut cli = empty_cli();
        cli.host = Some("10.0.0.1".into());
        cli.device_type = Some(DeviceKind::CiscoIos);
        cli.jumphost = Some("bastion".into());

        let r = resolve(&cli, &config).expect("should resolve");
        let jh = r.jump_host.expect("should have jump host");
        assert_eq!(jh.username, "sherpa"); // inherited from resolved target username
    }

    #[test]
    fn resolve_jump_host_explicit_username_overrides_spec() {
        let config = sample_config();
        let mut cli = empty_cli();
        cli.host = Some("10.0.0.1".into());
        cli.device_type = Some(DeviceKind::CiscoIos);
        cli.jumphost = Some("admin@bastion:2222".into());
        cli.jumphost_username = Some("override_user".into());

        let r = resolve(&cli, &config).expect("should resolve");
        let jh = r.jump_host.expect("should have jump host");
        assert_eq!(jh.username, "override_user"); // explicit overrides spec
        assert_eq!(jh.host, "bastion");
        assert_eq!(jh.port, 2222);
    }
}
