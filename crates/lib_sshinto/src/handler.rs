use russh::client;
use russh::keys::ssh_key;

pub(crate) struct SshHandler;

impl client::Handler for SshHandler {
    type Error = russh::Error;

    /// Accept any server host key without verification.
    ///
    /// sshinto is used in lab and automation contexts where host key pinning
    /// is not required. This callback always returns `true` (trusted).
    async fn check_server_key(
        &mut self,
        _server_public_key: &ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}
