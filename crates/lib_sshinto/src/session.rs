use std::borrow::Cow;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use regex::Regex;
use russh::client::{self, Msg};
use russh::keys::ssh_key::HashAlg;
use russh::keys::{PrivateKeyWithHashAlg, decode_secret_key};
use russh::{ChannelMsg, Disconnect, client::KeyboardInteractiveAuthResponse};
use russh_sftp::client::SftpSession;
use russh_sftp::protocol::OpenFlags;
use tokio::io::AsyncWriteExt;
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
            timeout: Duration::from_secs(30),
            // "dumb" prevents interactive terminal applications (e.g. PAN-OS CLISH)
            // from enabling character-by-character echo with line-editing control
            // sequences (\r\x1b[K redraws). Those sequences cause false prompt
            // matches in read_until_prompt_re and contaminate command output.
            term: "dumb".into(),
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

/// Authenticated SSH connection without a shell channel.
/// Use this for SCP-only operations, or call `open_shell()` to get a full `Session`.
pub struct Connection {
    handle: client::Handle<SshHandler>,
    _jump_handle: Option<client::Handle<SshHandler>>,
    config: ShellConfig,
}

/// Shell configuration extracted from ConnectConfig for deferred shell opening.
struct ShellConfig {
    term: String,
    cols: u32,
    rows: u32,
}

pub struct Session {
    conn: Connection,
    reader: russh::ChannelReadHalf,
    writer: russh::ChannelWriteHalf<Msg>,
}

/// Build a russh client config, optionally enabling legacy key-exchange algorithms
/// (`diffie-hellman-group14-sha1`, `diffie-hellman-group-exchange-sha1`) for
/// older devices that do not support modern KEX.
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

/// Authenticate an already-connected SSH handle using the given credential.
///
/// Supports password (with keyboard-interactive fallback) and private-key
/// (PEM string or file path) authentication.
/// Returns [`SshintoError::AuthFailed`] if the server rejects the credential.
async fn authenticate(
    handle: &mut client::Handle<SshHandler>,
    username: &str,
    credential: Credential,
    legacy_crypto: bool,
    timeout_dur: Duration,
) -> Result<()> {
    let auth_result = match credential {
        Credential::Password(password) => {
            // Try keyboard-interactive first: this is the method used by most
            // modern SSH servers and required by some devices (e.g. Cisco FTD)
            // that do not accept the bare SSH `password` method. Trying
            // keyboard-interactive first avoids wasting an auth attempt on
            // devices with a low MaxAuthTries limit.
            let mut ki = timeout(
                timeout_dur,
                handle.authenticate_keyboard_interactive_start(username, None),
            )
            .await
            .map_err(|_| SshintoError::Timeout)?
            .map_err(SshintoError::Ssh)?;

            loop {
                match ki {
                    KeyboardInteractiveAuthResponse::Success => return Ok(()),
                    KeyboardInteractiveAuthResponse::Failure { .. } => break,
                    KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => {
                        let responses = vec![password.clone(); prompts.len()];
                        // Yield to the tokio runtime so that russh's internal
                        // client-handler task can finish processing the
                        // InfoRequest packet before we send the response.
                        // A single yield_now() is not enough on fast schedulers;
                        // several yields are more reliable without adding latency
                        // that could exceed the device's response deadline
                        // (Cisco FTD has a tight window for keyboard-interactive).
                        for _ in 0..10 {
                            tokio::task::yield_now().await;
                        }

                        ki = timeout(
                            timeout_dur,
                            handle.authenticate_keyboard_interactive_respond(responses),
                        )
                        .await
                        .map_err(|_| SshintoError::Timeout)?
                        .map_err(SshintoError::Ssh)?;
                    }
                }
            }

            // keyboard-interactive was rejected without any InfoRequest
            // (server doesn't support it). Fall back to the SSH password method.
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
            timeout(timeout_dur, handle.authenticate_publickey(username, key))
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
            timeout(timeout_dur, handle.authenticate_publickey(username, key))
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

impl Connection {
    /// Connect and authenticate without opening a shell channel.
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

        Ok(Self {
            handle,
            _jump_handle: jump_handle,
            config: ShellConfig {
                term: config.term,
                cols: config.cols,
                rows: config.rows,
            },
        })
    }

    /// Open a shell channel, consuming this connection into a full Session.
    pub async fn open_shell(self) -> Result<Session> {
        let channel = self.handle.channel_open_session().await?;
        let (mut reader, writer) = channel.split();

        writer
            .request_pty(
                false,
                &self.config.term,
                self.config.cols,
                self.config.rows,
                0,
                0,
                &[],
            )
            .await?;
        writer.request_shell(false).await?;

        // Drain initial banner/prompt output
        let _ = drain_initial(&mut reader, Duration::from_secs(2)).await;

        Ok(Session {
            conn: self,
            reader,
            writer,
        })
    }

    /// Upload a local file to `remote_path` on the device.
    ///
    /// Tries SFTP first (supported by most modern SSH servers including Linux
    /// hosts that may not have the `scp` binary installed). Falls back to the
    /// legacy SCP sink protocol for devices that expose SCP but not SFTP
    /// (e.g. some Cisco IOS-XR configurations).
    pub async fn upload_file(
        &self,
        local_path: &Path,
        remote_path: &str,
        timeout_dur: Duration,
    ) -> Result<()> {
        match self.upload_file_sftp(local_path, remote_path, timeout_dur).await {
            Ok(()) => return Ok(()),
            Err(_) => {}
        }
        self.upload_file_scp(local_path, remote_path, timeout_dur).await
    }

    /// Upload using the SFTP subsystem.
    async fn upload_file_sftp(
        &self,
        local_path: &Path,
        remote_path: &str,
        timeout_dur: Duration,
    ) -> Result<()> {
        let expanded = expand_tilde(&local_path.to_string_lossy());
        let local = Path::new(&expanded);
        let contents = tokio::fs::read(local)
            .await
            .map_err(|e| SshintoError::ScpError(format!("cannot read {}: {e}", local.display())))?;

        let channel = timeout(timeout_dur, self.handle.channel_open_session())
            .await
            .map_err(|_| SshintoError::Timeout)?
            .map_err(SshintoError::Ssh)?;

        timeout(timeout_dur, channel.request_subsystem(true, "sftp"))
            .await
            .map_err(|_| SshintoError::Timeout)?
            .map_err(SshintoError::Ssh)?;

        let sftp = timeout(timeout_dur, SftpSession::new(channel.into_stream()))
            .await
            .map_err(|_| SshintoError::ScpError("SFTP session init timed out".into()))?
            .map_err(|e| SshintoError::ScpError(e.to_string()))?;

        let mut file = sftp
            .open_with_flags(
                remote_path,
                OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE,
            )
            .await
            .map_err(|e| SshintoError::ScpError(e.to_string()))?;

        file.write_all(&contents)
            .await
            .map_err(|e| SshintoError::ScpError(e.to_string()))?;

        file.shutdown()
            .await
            .map_err(|e| SshintoError::ScpError(e.to_string()))?;

        Ok(())
    }

    /// Upload using the legacy SCP sink protocol (`scp -t`).
    ///
    /// Opens a new exec channel for each call so this can be used before or after
    /// a shell channel is open (some devices only allow one channel at a time).
    async fn upload_file_scp(
        &self,
        local_path: &Path,
        remote_path: &str,
        timeout_dur: Duration,
    ) -> Result<()> {
        let expanded = expand_tilde(&local_path.to_string_lossy());
        let local = Path::new(&expanded);

        let meta = tokio::fs::metadata(local)
            .await
            .map_err(|e| SshintoError::ScpError(format!("cannot stat {}: {e}", local.display())))?;
        let size = meta.len();
        let contents = tokio::fs::read(local)
            .await
            .map_err(|e| SshintoError::ScpError(format!("cannot read {}: {e}", local.display())))?;

        let filename = local
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "file".to_string());

        let channel = timeout(timeout_dur, self.handle.channel_open_session())
            .await
            .map_err(|_| SshintoError::Timeout)?
            .map_err(SshintoError::Ssh)?;

        let (mut reader, writer) = channel.split();

        // When you run scp normally from a terminal, the client-side scp
        // automatically SSHes to the remote host and invokes scp -t <path> on
        // the other end. We're doing that same thing manually — opening an
        // exec channel and running scp -t <path> ourselves, then speaking
        // the SCP protocol (header, ack, data, ack) over that channel.
        let scp_cmd = format!("scp -t {remote_path}");
        writer
            .exec(true, scp_cmd.into_bytes())
            .await
            .map_err(SshintoError::Ssh)?;

        // Read initial ack from remote scp
        read_scp_ack(&mut reader, timeout_dur).await?;

        // Send file header: C0644 <size> <filename>\n
        let header = format!("C0644 {size} {filename}\n");
        writer
            .data(&header.as_bytes()[..])
            .await
            .map_err(SshintoError::Ssh)?;

        // Read ack for header
        read_scp_ack(&mut reader, timeout_dur).await?;

        // Send file contents
        writer
            .data(&contents[..])
            .await
            .map_err(SshintoError::Ssh)?;

        // Send 0-byte end marker
        writer.data(&[0u8][..]).await.map_err(SshintoError::Ssh)?;

        // Read final ack
        read_scp_ack(&mut reader, timeout_dur).await?;

        let _ = writer.eof().await;
        let _ = writer.close().await;

        Ok(())
    }

    /// Gracefully disconnect the SSH session, including the jump-host connection if one exists.
    pub async fn close(self) -> Result<()> {
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

impl Session {
    /// Connect, authenticate, and open a shell channel in one step.
    pub async fn connect(
        host: &str,
        port: u16,
        username: &str,
        credential: Credential,
        config: ConnectConfig,
    ) -> Result<Self> {
        let conn = Connection::connect(host, port, username, credential, config).await?;
        conn.open_shell().await
    }

    /// Write raw bytes into the shell channel (e.g. a command followed by `\n`).
    pub async fn write(&self, data: &[u8]) -> Result<()> {
        self.writer.data(&data[..]).await?;
        Ok(())
    }

    /// Accumulate channel output until the buffer ends with the exact `prompt` string.
    ///
    /// Returns the full accumulated output including the prompt line.
    pub async fn read_until_prompt(
        &mut self,
        prompt: &str,
        timeout_dur: Duration,
    ) -> Result<String> {
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

    /// Send `command\n` and wait until the output ends with the exact `prompt` string.
    ///
    /// Returns the raw accumulated output (echo + response + prompt).
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

    /// Accumulate channel output until the trimmed buffer matches `prompt_re`.
    ///
    /// ANSI escape sequences are stripped before the regex is tested so that
    /// prompt colouring on Linux/Cumulus hosts does not prevent detection.
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
                        if prompt_visible(&buffer, prompt_re) {
                            return Ok(buffer);
                        }
                    }
                    Some(ChannelMsg::ExtendedData { data, .. }) => {
                        buffer.push_str(&String::from_utf8_lossy(&data));
                        if prompt_visible(&buffer, prompt_re) {
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

    /// Send `command\n` and wait until the output matches `prompt_re`.
    ///
    /// Returns the raw accumulated output (echo + response + prompt).
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

    /// Send `command\n`, wait for the prompt, and return the cleaned output.
    ///
    /// Strips the echoed command from the first line and the trailing prompt from the
    /// last line via [`crate::output::strip_command_output`].
    pub async fn send_command_clean(
        &mut self,
        command: &str,
        prompt_re: &Regex,
        timeout_dur: Duration,
    ) -> Result<String> {
        let raw = self
            .send_command_re(command, prompt_re, timeout_dur)
            .await?;
        Ok(crate::output::strip_command_output(
            &raw, command, prompt_re,
        ))
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

    /// Upload a local file via SCP. Delegates to [`Connection::upload_file`].
    pub async fn upload_file(
        &self,
        local_path: &Path,
        remote_path: &str,
        timeout_dur: Duration,
    ) -> Result<()> {
        self.conn
            .upload_file(local_path, remote_path, timeout_dur)
            .await
    }

    /// Close the shell channel and the underlying SSH connection.
    pub async fn close(self) -> Result<()> {
        let _ = self.writer.close().await;
        self.conn.close().await
    }
}

/// Read and validate a single SCP acknowledgement byte from the remote `scp -t` process.
///
/// SCP protocol: `0x00` = OK, `0x01` = warning, `0x02` = fatal error.
/// The byte is followed by an optional message terminated by `\n`.
async fn read_scp_ack(reader: &mut russh::ChannelReadHalf, timeout_dur: Duration) -> Result<()> {
    timeout(timeout_dur, async {
        loop {
            match reader.wait().await {
                Some(ChannelMsg::Data { data }) => {
                    if data.is_empty() {
                        continue;
                    }
                    match data[0] {
                        0 => return Ok(()),
                        1 | 2 => {
                            let msg = String::from_utf8_lossy(&data[1..]).trim().to_string();
                            return Err(SshintoError::ScpError(msg));
                        }
                        _ => {
                            return Err(SshintoError::ScpError(format!(
                                "unexpected SCP response: {}",
                                String::from_utf8_lossy(&data)
                            )));
                        }
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

/// Expand a leading `~/` in `path` to the value of the `HOME` environment variable.
///
/// Returns the path unchanged if it does not start with `~/` or if `HOME` is unset.
fn expand_tilde(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return Path::new(&home).join(rest).to_string_lossy().into_owned();
        }
    }
    path.to_string()
}

/// Choose the signature hash algorithm for RSA keys.
///
/// Modern devices require `rsa-sha2-256`; legacy devices (e.g. older Cisco IOS) only
/// accept the original `ssh-rsa` (SHA-1) scheme. Non-RSA key types return `None` to
/// let russh negotiate automatically.
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

/// Drain the initial SSH channel output (banner, MOTD, shell prompt) for up to `wait`.
///
/// Control messages such as `WindowAdjust` are silently ignored rather than
/// treated as a termination signal; only `Eof`, `Close`, or channel closure
/// stops the drain early.  The accumulated text is returned but is typically
/// discarded by callers — its main purpose is to clear the read buffer so
/// subsequent reads start on a clean prompt.
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
                // EOF or channel close — nothing more will arrive.
                Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => break,
                // WindowAdjust, ExitStatus, and other control messages arrive
                // before or alongside banner data on Linux hosts. Ignore them
                // instead of breaking so we don't exit before the shell prompt.
                _ => {}
            }
        }
    })
    .await;
    buffer
}

/// Check whether a stable prompt is visible at the end of `buf`.
///
/// Strips ANSI escape sequences, then examines the *visible* last line.
/// A carriage return (`\r`) without a following newline means the device is
/// overwriting the current line (e.g. PAN-OS character-by-character echo).
/// Only the text after the final `\r` on the last `\n`-terminated segment is
/// matched against the regex, so intermediate echo redraws do not trigger a
/// false-positive match.
fn prompt_visible(buf: &str, prompt_re: &Regex) -> bool {
    let clean = strip_ansi(buf);
    // Last \n-delimited segment (may be empty if buf ends with \n).
    let last_segment = clean.split('\n').next_back().unwrap_or("");
    // Within that segment, take only what follows the last \r — this is the
    // text that is visually on screen after all overwrite redraws.
    let visible = last_segment.split('\r').next_back().unwrap_or("");
    let visible = visible.trim_end();
    !visible.is_empty() && prompt_re.is_match(visible)
}

/// Strip ANSI escape sequences (CSI sequences) so prompt regexes can match cleanly.
pub fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            if let Some(next) = chars.next() {
                if next == '[' {
                    for c2 in chars.by_ref() {
                        if c2.is_ascii_alphabetic() || c2 == '~' {
                            break;
                        }
                    }
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}
