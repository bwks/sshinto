use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use russh::client::{self, Msg};
use russh::keys::ssh_key::HashAlg;
use russh::keys::{decode_secret_key, PrivateKeyWithHashAlg};
use russh::{ChannelMsg, Disconnect};
use tokio::time::timeout;

use crate::error::{Result, SshintoError};
use crate::handler::SshHandler;

pub struct ConnectConfig {
    pub timeout: Duration,
    pub term: String,
    pub cols: u32,
    pub rows: u32,
}

impl Default for ConnectConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            term: "xterm".into(),
            cols: 200,
            rows: 48,
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
    reader: russh::ChannelReadHalf,
    writer: russh::ChannelWriteHalf<Msg>,
}

impl Session {
    pub async fn connect(
        host: &str,
        port: u16,
        username: &str,
        credential: Credential,
        config: ConnectConfig,
    ) -> Result<Self> {
        let ssh_config = Arc::new(client::Config::default());
        let addr = format!("{host}:{port}");

        let mut handle = timeout(config.timeout, client::connect(ssh_config, &*addr, SshHandler))
            .await
            .map_err(|_| SshintoError::Timeout)?
            .map_err(SshintoError::Ssh)?;

        let auth_result = match credential {
            Credential::Password(password) => {
                timeout(
                    config.timeout,
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
                let hash_alg = hash_alg_for_key(&key);
                let key = PrivateKeyWithHashAlg::new(Arc::new(key), hash_alg);
                timeout(
                    config.timeout,
                    handle.authenticate_publickey(username, key),
                )
                .await
                .map_err(|_| SshintoError::Timeout)?
                .map_err(SshintoError::Ssh)?
            }
            Credential::PrivateKeyFile { path, passphrase } => {
                let pem = std::fs::read_to_string(Path::new(&path))?;
                let key = decode_secret_key(&pem, passphrase.as_deref())?;
                let hash_alg = hash_alg_for_key(&key);
                let key = PrivateKeyWithHashAlg::new(Arc::new(key), hash_alg);
                timeout(
                    config.timeout,
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
        Ok(())
    }
}

fn hash_alg_for_key(key: &russh::keys::PrivateKey) -> Option<HashAlg> {
    if key.algorithm().is_rsa() {
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
