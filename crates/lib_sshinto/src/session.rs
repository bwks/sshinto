use std::borrow::Cow;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use regex::Regex;
use russh::client::{self, Msg};
use russh::keys::ssh_key::HashAlg;
use russh::keys::{decode_secret_key, PrivateKeyWithHashAlg};
use russh::{ChannelMsg, Disconnect};
use tokio::time::timeout;

use crate::error::{Result, SshintoError};
use crate::handler::SshHandler;

pub struct JumpHost {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub credential: Credential,
    pub legacy_crypto: bool,
}

pub struct ConnectConfig {
    pub timeout: Duration,
    pub term: String,
    pub cols: u32,
    pub rows: u32,
    /// Enable legacy SSH algorithms (e.g. diffie-hellman-group14-sha1) for
    /// older devices that don't support modern key exchange.
    pub legacy_crypto: bool,
    /// Optional jump host to connect through.
    pub jumphost: Option<JumpHost>,
}

impl Default for ConnectConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            term: "xterm".into(),
            cols: 200,
            rows: 48,
            legacy_crypto: false,
            jumphost: None,
        }
    }
}

pub enum Credential {
    Password(String),
    PrivateKey {
        key_pem: String,
        passphrase: Option<String>,
    },
    PrivateKeyFile {
        path: String,
        passphrase: Option<String>,
    },
}

pub struct Session {
    handle: client::Handle<SshHandler>,
    _jump_handle: Option<client::Handle<SshHandler>>,
    reader: russh::ChannelReadHalf,
    writer: russh::ChannelWriteHalf<Msg>,
}

fn build_ssh_config(legacy_crypto: bool) -> Arc<client::Config> {
    if legacy_crypto {
        let mut kex = russh::Preferred::default().kex.into_owned();
        kex.push(russh::kex::DH_G14_SHA1);
        kex.push(russh::kex::DH_GEX_SHA1);
        Arc::new(client::Config {
            preferred: russh::Preferred {
                kex: Cow::Owned(kex),
                ..Default::default()
            },
            ..Default::default()
        })
    } else {
        Arc::new(client::Config::default())
    }
}

async fn authenticate(
    handle: &mut client::Handle<SshHandler>,
    username: &str,
    credential: Credential,
    legacy_crypto: bool,
    timeout_dur: Duration,
) -> Result<()> {
    let auth_result = match credential {
        Credential::Password(password) => {
            timeout(
                timeout_dur,
                handle.authenticate_password(username, password),
            )
            .await
            .map_err(|_| SshintoError::Timeout)?
            .map_err(SshintoError::Ssh)?
        }
        Credential::PrivateKey {
            key_pem,
            passphrase,
        } => {
            let key = decode_secret_key(&key_pem, passphrase.as_deref())?;
            let hash_alg = hash_alg_for_key(&key, legacy_crypto);
            let key = PrivateKeyWithHashAlg::new(Arc::new(key), hash_alg);
            timeout(
                timeout_dur,
                handle.authenticate_publickey(username, key),
            )
            .await
            .map_err(|_| SshintoError::Timeout)?
            .map_err(SshintoError::Ssh)?
        }
        Credential::PrivateKeyFile { path, passphrase } => {
            let expanded = expand_tilde(&path);
            let pem = std::fs::read_to_string(Path::new(&expanded))?;
            let key = decode_secret_key(&pem, passphrase.as_deref())?;
            let hash_alg = hash_alg_for_key(&key, legacy_crypto);
            let key = PrivateKeyWithHashAlg::new(Arc::new(key), hash_alg);
            timeout(
                timeout_dur,
                handle.authenticate_publickey(username, key),
            )
            .await
            .map_err(|_| SshintoError::Timeout)?
            .map_err(SshintoError::Ssh)?
        }
    };

    if !auth_result.success() {
        return Err(SshintoError::AuthFailed);
    }

    Ok(())
}

impl Session {
    pub async fn connect(
        host: &str,
        port: u16,
        username: &str,
        credential: Credential,
        config: ConnectConfig,
    ) -> Result<Self> {
        let (mut handle, jump_handle) = if let Some(jh) = config.jumphost {
            // Connect to the jump host first.
            let jump_ssh_config = build_ssh_config(jh.legacy_crypto);
            let jump_addr = format!("{}:{}", jh.host, jh.port);

            let mut jh_handle = timeout(
                config.timeout,
                client::connect(jump_ssh_config, &*jump_addr, SshHandler),
            )
            .await
            .map_err(|_| SshintoError::Timeout)?
            .map_err(SshintoError::Ssh)?;

            authenticate(
                &mut jh_handle,
                &jh.username,
                jh.credential,
                jh.legacy_crypto,
                config.timeout,
            )
            .await?;

            // Open a direct-tcpip channel through the jump host to the target.
            let channel = jh_handle
                .channel_open_direct_tcpip(host, port as u32, "0.0.0.0", 0)
                .await
                .map_err(SshintoError::Ssh)?;
            let stream = channel.into_stream();

            // Establish the nested SSH session over the forwarded stream.
            let target_ssh_config = build_ssh_config(config.legacy_crypto);
            let target_handle = timeout(
                config.timeout,
                client::connect_stream(target_ssh_config, stream, SshHandler),
            )
            .await
            .map_err(|_| SshintoError::Timeout)?
            .map_err(SshintoError::Ssh)?;

            (target_handle, Some(jh_handle))
        } else {
            // Direct connection.
            let ssh_config = build_ssh_config(config.legacy_crypto);
            let addr = format!("{host}:{port}");

            let direct_handle = timeout(
                config.timeout,
                client::connect(ssh_config, &*addr, SshHandler),
            )
            .await
            .map_err(|_| SshintoError::Timeout)?
            .map_err(SshintoError::Ssh)?;

            (direct_handle, None)
        };

        authenticate(
            &mut handle,
            username,
            credential,
            config.legacy_crypto,
            config.timeout,
        )
        .await?;

        let channel = handle.channel_open_session().await?;
        let (mut reader, writer) = channel.split();

        writer
            .request_pty(false, &config.term, config.cols, config.rows, 0, 0, &[])
            .await?;
        writer.request_shell(false).await?;

        // Drain initial banner/prompt output
        let _ = drain_initial(&mut reader, Duration::from_secs(2)).await;

        Ok(Self {
            handle,
            _jump_handle: jump_handle,
            reader,
            writer,
        })
    }

    pub async fn write(&self, data: &[u8]) -> Result<()> {
        self.writer.data(&data[..]).await?;
        Ok(())
    }

    pub async fn read_until_prompt(&mut self, prompt: &str, timeout_dur: Duration) -> Result<String> {
        let mut buffer = String::new();

        timeout(timeout_dur, async {
            loop {
                match self.reader.wait().await {
                    Some(ChannelMsg::Data { data }) => {
                        buffer.push_str(&String::from_utf8_lossy(&data));
                        if buffer.trim_end().ends_with(prompt) {
                            return Ok(buffer);
                        }
                    }
                    Some(ChannelMsg::ExtendedData { data, .. }) => {
                        buffer.push_str(&String::from_utf8_lossy(&data));
                        if buffer.trim_end().ends_with(prompt) {
                            return Ok(buffer);
                        }
                    }
                    Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => {
                        return Err(SshintoError::ChannelClosed);
                    }
                    _ => {}
                }
            }
        })
        .await
        .map_err(|_| SshintoError::Timeout)?
    }

    pub async fn send_command(
        &mut self,
        command: &str,
        prompt: &str,
        timeout_dur: Duration,
    ) -> Result<String> {
        let data = format!("{command}\n");
        self.write(data.as_bytes()).await?;
        self.read_until_prompt(prompt, timeout_dur).await
    }

    pub async fn read_until_prompt_re(
        &mut self,
        prompt_re: &Regex,
        timeout_dur: Duration,
    ) -> Result<String> {
        let mut buffer = String::new();

        timeout(timeout_dur, async {
            loop {
                match self.reader.wait().await {
                    Some(ChannelMsg::Data { data }) => {
                        buffer.push_str(&String::from_utf8_lossy(&data));
                        if prompt_re.is_match(buffer.trim_end()) {
                            return Ok(buffer);
                        }
                    }
                    Some(ChannelMsg::ExtendedData { data, .. }) => {
                        buffer.push_str(&String::from_utf8_lossy(&data));
                        if prompt_re.is_match(buffer.trim_end()) {
                            return Ok(buffer);
                        }
                    }
                    Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => {
                        return Err(SshintoError::ChannelClosed);
                    }
                    _ => {}
                }
            }
        })
        .await
        .map_err(|_| SshintoError::Timeout)?
    }

    pub async fn send_command_re(
        &mut self,
        command: &str,
        prompt_re: &Regex,
        timeout_dur: Duration,
    ) -> Result<String> {
        let data = format!("{command}\n");
        self.write(data.as_bytes()).await?;
        self.read_until_prompt_re(prompt_re, timeout_dur).await
    }

    pub async fn send_command_clean(
        &mut self,
        command: &str,
        prompt_re: &Regex,
        timeout_dur: Duration,
    ) -> Result<String> {
        let raw = self.send_command_re(command, prompt_re, timeout_dur).await?;
        Ok(crate::output::strip_command_output(&raw, command, prompt_re))
    }

    /// Read all data arriving within the given duration. Useful for diagnostics.
    pub async fn read_for(&mut self, duration: Duration) -> String {
        let mut buffer = String::new();
        let _ = timeout(duration, async {
            loop {
                match self.reader.wait().await {
                    Some(ChannelMsg::Data { data }) => {
                        buffer.push_str(&String::from_utf8_lossy(&data));
                    }
                    Some(ChannelMsg::ExtendedData { data, .. }) => {
                        buffer.push_str(&String::from_utf8_lossy(&data));
                    }
                    Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => break,
                    _ => {}
                }
            }
        })
        .await;
        buffer
    }

    pub async fn close(self) -> Result<()> {
        let _ = self.writer.close().await;
        self.handle
            .disconnect(Disconnect::ByApplication, "closing session", "en")
            .await?;
        if let Some(jh) = self._jump_handle {
            let _ = jh
                .disconnect(Disconnect::ByApplication, "closing jump session", "en")
                .await;
        }
        Ok(())
    }
}

fn expand_tilde(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return Path::new(&home).join(rest).to_string_lossy().into_owned();
        }
    }
    path.to_string()
}

fn hash_alg_for_key(key: &russh::keys::PrivateKey, legacy_crypto: bool) -> Option<HashAlg> {
    if key.algorithm().is_rsa() && !legacy_crypto {
        // Modern devices expect rsa-sha2-256.
        // When legacy_crypto is true, return None to use the original ssh-rsa (SHA-1) signature
        // scheme, which older devices (e.g. legacy Cisco IOS) require.
        Some(HashAlg::Sha256)
    } else {
        None
    }
}

async fn drain_initial(reader: &mut russh::ChannelReadHalf, wait: Duration) -> String {
    let mut buffer = String::new();
    let _ = timeout(wait, async {
        loop {
            match reader.wait().await {
                Some(ChannelMsg::Data { data }) => {
                    buffer.push_str(&String::from_utf8_lossy(&data));
                }
                Some(ChannelMsg::ExtendedData { data, .. }) => {
                    buffer.push_str(&String::from_utf8_lossy(&data));
                }
                _ => break,
            }
        }
    })
    .await;
    buffer
}
