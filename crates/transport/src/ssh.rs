//! SSH transport implementation using russh (pure Rust)
//!
//! Uses russh for native Rust SSH with binary protocol support.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use color_eyre::Result;
use russh::keys::agent::client::AgentClient;
use russh::keys::key::PrivateKeyWithHashAlg;
use russh::keys::{PublicKey, load_secret_key};
use russh::{ChannelMsg, Disconnect};
use tracing::{debug, info};

use crate::Platform;
use crate::agent::AgentBundle;
use zsync_core::{Message, Snapshot, protocol};

/// SSH transport for communicating with remote hosts
pub struct SshTransport {
    session: russh::client::Handle<ClientHandler>,
    host: String,
    port: u16,
    user: String,
    platform: Platform,
    agent_path: Option<PathBuf>,
}

struct ClientHandler;

impl russh::client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &PublicKey,
    ) -> Result<bool, Self::Error> {
        // TODO: Proper host key verification
        Ok(true)
    }
}

/// Active agent session for communicating with remote
pub struct AgentSession {
    channel: russh::Channel<russh::client::Msg>,
    root: PathBuf,
    buffer: Vec<u8>,
}

impl AgentSession {
    /// Read exact number of bytes from channel
    async fn read_exact(&mut self, buf: &mut [u8]) -> Result<()> {
        let mut offset = 0;

        // First, drain from buffer
        let drain_len = buf.len().min(self.buffer.len());
        if drain_len > 0 {
            buf[..drain_len].copy_from_slice(&self.buffer[..drain_len]);
            self.buffer.drain(..drain_len);
            offset = drain_len;
        }

        // Then read from channel
        while offset < buf.len() {
            match self.channel.wait().await {
                Some(ChannelMsg::Data { data }) => {
                    let bytes = data.as_ref();
                    let to_copy = (buf.len() - offset).min(bytes.len());
                    buf[offset..offset + to_copy].copy_from_slice(&bytes[..to_copy]);
                    offset += to_copy;

                    // Buffer any extra
                    if to_copy < bytes.len() {
                        self.buffer.extend_from_slice(&bytes[to_copy..]);
                    }
                }
                Some(ChannelMsg::Eof | ChannelMsg::Close) => {
                    return Err(color_eyre::eyre::eyre!("Channel closed unexpectedly"));
                }
                Some(_) => {}
                None => {
                    return Err(color_eyre::eyre::eyre!("Channel closed"));
                }
            }
        }

        Ok(())
    }

    /// Read a message from the agent
    async fn read_message(&mut self) -> Result<Message> {
        // Read header: type (1 byte) + length (4 bytes)
        let mut header = [0u8; 5];
        self.read_exact(&mut header).await?;

        let msg_type = header[0];
        let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;

        // Read payload
        let mut payload = vec![0u8; len];
        if len > 0 {
            self.read_exact(&mut payload).await?;
        }

        // Parse based on type
        match msg_type {
            protocol::msg::SNAPSHOT_RESP => {
                let snapshot = decode_snapshot(&payload)?;
                Ok(Message::SnapshotResp(snapshot))
            }
            protocol::msg::OK => Ok(Message::Ok),
            protocol::msg::ERROR => {
                let message = String::from_utf8_lossy(&payload).to_string();
                Ok(Message::Error(message))
            }
            _ => Err(color_eyre::eyre::eyre!("Unknown message type: {msg_type}")),
        }
    }

    /// Send raw bytes to agent
    async fn send(&self, data: &[u8]) -> Result<()> {
        self.channel.data(data).await?;
        Ok(())
    }

    /// Get snapshot from remote
    pub async fn snapshot(&mut self) -> Result<Snapshot> {
        // Send snapshot request: type=0x01, len=0
        self.send(&[protocol::msg::SNAPSHOT_REQ, 0, 0, 0, 0])
            .await?;

        match self.read_message().await? {
            Message::SnapshotResp(snapshot) => Ok(snapshot),
            Message::Error(msg) => Err(color_eyre::eyre::eyre!("Snapshot failed: {msg}")),
            other => Err(color_eyre::eyre::eyre!("Unexpected response: {other:?}")),
        }
    }

    /// Write a file to the remote
    pub async fn write_file(&mut self, path: &Path, data: &[u8], executable: bool) -> Result<()> {
        // Build payload: path_len(2) + path + executable(1) + data
        let path_bytes = path.to_string_lossy().as_bytes().to_vec();
        let payload_len = 2 + path_bytes.len() + 1 + data.len();

        // Header
        let mut msg = Vec::with_capacity(5 + payload_len);
        msg.push(protocol::msg::WRITE_FILE);
        msg.extend_from_slice(&(payload_len as u32).to_be_bytes());

        // Path
        msg.extend_from_slice(&(path_bytes.len() as u16).to_be_bytes());
        msg.extend_from_slice(&path_bytes);

        // Executable flag
        msg.push(u8::from(executable));

        // Data
        msg.extend_from_slice(data);

        self.send(&msg).await?;

        match self.read_message().await? {
            Message::Ok => Ok(()),
            Message::Error(msg) => Err(color_eyre::eyre::eyre!("Write failed: {msg}")),
            other => Err(color_eyre::eyre::eyre!("Unexpected response: {other:?}")),
        }
    }

    /// Delete a file on the remote
    pub async fn delete_file(&mut self, path: &Path) -> Result<()> {
        let path_bytes = path.to_string_lossy().as_bytes().to_vec();
        let payload_len = 2 + path_bytes.len();

        let mut msg = Vec::with_capacity(5 + payload_len);
        msg.push(protocol::msg::DELETE_FILE);
        msg.extend_from_slice(&(payload_len as u32).to_be_bytes());
        msg.extend_from_slice(&(path_bytes.len() as u16).to_be_bytes());
        msg.extend_from_slice(&path_bytes);

        self.send(&msg).await?;

        match self.read_message().await? {
            Message::Ok => Ok(()),
            Message::Error(msg) => Err(color_eyre::eyre::eyre!("Delete failed: {msg}")),
            other => Err(color_eyre::eyre::eyre!("Unexpected response: {other:?}")),
        }
    }

    /// Shutdown the agent
    pub async fn shutdown(&mut self) -> Result<()> {
        self.send(&[protocol::msg::SHUTDOWN, 0, 0, 0, 0]).await?;
        let _ = self.read_message().await;
        Ok(())
    }

    /// Get the remote root path
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }
}

/// Decode snapshot from binary (same format as protocol.rs)
fn decode_snapshot(data: &[u8]) -> Result<Snapshot> {
    use std::io::{Cursor, Read};
    use zsync_core::{ContentHash, FileEntry};

    let mut cursor = Cursor::new(data);

    // File count
    let mut count_buf = [0u8; 4];
    cursor.read_exact(&mut count_buf)?;
    let count = u32::from_be_bytes(count_buf) as usize;

    let mut entries = Vec::with_capacity(count);

    for _ in 0..count {
        // Path
        let mut path_len_buf = [0u8; 2];
        cursor.read_exact(&mut path_len_buf)?;
        let path_len = u16::from_be_bytes(path_len_buf) as usize;

        let mut path_buf = vec![0u8; path_len];
        cursor.read_exact(&mut path_buf)?;
        let path = PathBuf::from(String::from_utf8_lossy(&path_buf).to_string());

        // Size
        let mut size_buf = [0u8; 8];
        cursor.read_exact(&mut size_buf)?;
        let size = u64::from_be_bytes(size_buf);

        // Hash
        let mut hash_buf = [0u8; 32];
        cursor.read_exact(&mut hash_buf)?;
        let hash = ContentHash::from_raw(hash_buf);

        // Executable
        let mut exec_buf = [0u8; 1];
        cursor.read_exact(&mut exec_buf)?;
        let executable = exec_buf[0] != 0;

        entries.push(FileEntry {
            path,
            size,
            modified: std::time::SystemTime::UNIX_EPOCH,
            hash,
            executable,
        });
    }

    Ok(Snapshot::from_entries(entries))
}

/// Parsed SSH config for a specific host
struct SshHostConfig {
    identity_agent: Option<PathBuf>,
    identity_files: Vec<PathBuf>,
    port: Option<u16>,
    user: Option<String>,
    host_name: Option<String>,
}

impl SshTransport {
    /// Connect to a remote host via SSH
    pub async fn connect(host: &str, port: u16, user: &str) -> Result<Self> {
        info!("Connecting to {user}@{host}:{port}");

        let config = Arc::new(russh::client::Config::default());
        let handler = ClientHandler;

        let mut session = russh::client::connect(config, (host, port), handler).await?;

        // Try to authenticate with SSH keys
        let authenticated = Self::authenticate(&mut session, user, host).await?;
        if !authenticated {
            return Err(color_eyre::eyre::eyre!(
                "SSH authentication failed for {user}@{host}"
            ));
        }

        // Detect remote platform
        let platform = Self::detect_platform(&session).await?;
        info!("Remote platform: {platform:?}");

        Ok(Self {
            session,
            host: host.to_string(),
            port,
            user: user.to_string(),
            platform,
            agent_path: None,
        })
    }

    /// Parse SSH config for a specific host using ssh2-config
    fn parse_ssh_config(host: &str) -> SshHostConfig {
        let home = match dirs::home_dir() {
            Some(h) => h,
            None => {
                return SshHostConfig {
                    identity_agent: None,
                    identity_files: Vec::new(),
                    port: None,
                    user: None,
                    host_name: None,
                };
            }
        };

        let ssh_config_path = home.join(".ssh/config");
        let file = match std::fs::File::open(&ssh_config_path) {
            Ok(f) => f,
            Err(_) => {
                return SshHostConfig {
                    identity_agent: None,
                    identity_files: Vec::new(),
                    port: None,
                    user: None,
                    host_name: None,
                };
            }
        };

        let mut reader = std::io::BufReader::new(file);
        let config = match ssh2_config::SshConfig::default().parse(
            &mut reader,
            ssh2_config::ParseRule::ALLOW_UNSUPPORTED_FIELDS,
        ) {
            Ok(c) => c,
            Err(e) => {
                debug!("Failed to parse SSH config: {e}");
                return SshHostConfig {
                    identity_agent: None,
                    identity_files: Vec::new(),
                    port: None,
                    user: None,
                    host_name: None,
                };
            }
        };

        let params = config.query(host);

        // Get IdentityAgent from unsupported_fields (ssh2-config parses but doesn't expose it)
        // Note: ssh2-config splits on whitespace, so paths with spaces are split into multiple values
        // We need to join them back together
        let identity_agent = params
            .unsupported_fields
            .get("identityagent")
            .and_then(|values| {
                // Join all values with spaces (paths with spaces get split)
                let value = values.join(" ");
                let value = value.trim_matches('"').trim_matches('\'');
                let expanded = if value.starts_with("~/") {
                    home.join(&value[2..])
                } else {
                    PathBuf::from(value)
                };
                if expanded.exists() {
                    debug!(
                        "Found IdentityAgent for host {host}: {}",
                        expanded.display()
                    );
                    Some(expanded)
                } else {
                    debug!("IdentityAgent path does not exist: {}", expanded.display());
                    None
                }
            });

        SshHostConfig {
            identity_agent,
            identity_files: params.identity_file.unwrap_or_default(),
            port: params.port,
            user: params.user,
            host_name: params.host_name,
        }
    }

    /// Get the SSH agent socket path from SSH config or environment
    fn get_agent_socket_path(host: &str) -> Option<PathBuf> {
        // First, try SSH config for this specific host
        let config = Self::parse_ssh_config(host);
        if let Some(agent_path) = config.identity_agent {
            return Some(agent_path);
        }

        // Fall back to SSH_AUTH_SOCK environment variable
        if let Ok(sock) = std::env::var("SSH_AUTH_SOCK") {
            let path = PathBuf::from(&sock);
            if path.exists() {
                debug!("Using SSH_AUTH_SOCK: {sock}");
                return Some(path);
            }
        }

        None
    }

    /// Authenticate using SSH keys
    async fn authenticate(
        session: &mut russh::client::Handle<ClientHandler>,
        user: &str,
        host: &str,
    ) -> Result<bool> {
        // Try SSH agent first (from config or environment)
        if let Some(agent_path) = Self::get_agent_socket_path(host) {
            match AgentClient::connect_uds(&agent_path).await {
                Ok(mut agent) => {
                    debug!("Connected to SSH agent at {}", agent_path.display());
                    match agent.request_identities().await {
                        Ok(identities) => {
                            debug!("SSH agent has {} identities", identities.len());
                            for identity in identities {
                                if let Ok(result) = session
                                    .authenticate_publickey_with(user, identity, None, &mut agent)
                                    .await
                                {
                                    if result.success() {
                                        info!("Authenticated via SSH agent");
                                        return Ok(true);
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            debug!("Failed to get identities from agent: {e}");
                        }
                    }
                }
                Err(e) => {
                    debug!(
                        "Failed to connect to SSH agent at {}: {e}",
                        agent_path.display()
                    );
                }
            }
        }

        // Try default key paths
        let home = dirs::home_dir().ok_or_else(|| color_eyre::eyre::eyre!("No home directory"))?;
        let key_paths = [
            home.join(".ssh/id_ed25519"),
            home.join(".ssh/id_rsa"),
            home.join(".ssh/id_ecdsa"),
        ];

        for key_path in &key_paths {
            if key_path.exists() {
                match load_secret_key(key_path, None) {
                    Ok(key) => {
                        let key_with_hash = PrivateKeyWithHashAlg::new(Arc::new(key), None);
                        if let Ok(result) =
                            session.authenticate_publickey(user, key_with_hash).await
                        {
                            if result.success() {
                                info!("Authenticated with key: {}", key_path.display());
                                return Ok(true);
                            }
                        }
                    }
                    Err(e) => {
                        debug!("Failed to load key {}: {e}", key_path.display());
                    }
                }
            }
        }

        Ok(false)
    }

    /// Detect remote platform via uname
    async fn detect_platform(session: &russh::client::Handle<ClientHandler>) -> Result<Platform> {
        let mut channel = session.channel_open_session().await?;
        channel.exec(true, "uname -s && uname -m").await?;

        let mut stdout = String::new();
        loop {
            match channel.wait().await {
                Some(ChannelMsg::Data { data }) => {
                    stdout.push_str(&String::from_utf8_lossy(&data));
                }
                Some(ChannelMsg::Eof | ChannelMsg::Close) | None => break,
                Some(_) => {}
            }
        }

        let lines: Vec<&str> = stdout.lines().collect();
        if lines.len() < 2 {
            return Err(color_eyre::eyre::eyre!(
                "Failed to detect platform: unexpected uname output: {stdout}"
            ));
        }

        Platform::from_uname(lines[0], lines[1]).ok_or_else(|| {
            color_eyre::eyre::eyre!("Unsupported platform: {} {}", lines[0], lines[1])
        })
    }

    /// Get the remote platform
    #[must_use]
    pub fn platform(&self) -> Platform {
        self.platform
    }

    /// Execute a command on the remote host
    pub async fn execute(&self, command: &str) -> Result<(String, String, i32)> {
        let mut channel = self.session.channel_open_session().await?;
        channel.exec(true, command).await?;

        let mut stdout = String::new();
        let mut stderr = String::new();
        let mut exit_code = 0;

        loop {
            match channel.wait().await {
                Some(ChannelMsg::Data { data }) => {
                    stdout.push_str(&String::from_utf8_lossy(&data));
                }
                Some(ChannelMsg::ExtendedData { data, ext: 1 }) => {
                    stderr.push_str(&String::from_utf8_lossy(&data));
                }
                Some(ChannelMsg::ExitStatus { exit_status }) => {
                    exit_code = exit_status as i32;
                }
                Some(ChannelMsg::Eof | ChannelMsg::Close) | None => break,
                Some(_) => {}
            }
        }

        Ok((stdout, stderr, exit_code))
    }

    /// Ensure the agent is deployed to the remote host
    pub async fn ensure_agent(&mut self, bundle: &AgentBundle) -> Result<PathBuf> {
        if let Some(path) = &self.agent_path {
            return Ok(path.clone());
        }

        // Get agent binary for this platform
        let agent_data = bundle.get(self.platform).ok_or_else(|| {
            color_eyre::eyre::eyre!("No agent binary for platform {:?}", self.platform)
        })?;

        // Use content hash to ensure agent is re-deployed when code changes
        let agent_hash = zsync_core::ContentHash::from_bytes(agent_data);
        let hash_prefix = &agent_hash.to_hex()[..12];
        let remote_dir = format!(".zsync/agents/{hash_prefix}");
        let remote_path = format!("{remote_dir}/zsync-agent");

        // Check if this exact agent version already exists
        let (stdout, _, _) = self
            .execute(&format!("test -x ~/{remote_path} && echo exists"))
            .await?;

        if stdout.contains("exists") {
            debug!("Agent already deployed at ~/{remote_path}");
            let (home, _, _) = self.execute("echo $HOME").await?;
            let home = home.trim();
            let path = PathBuf::from(format!("{home}/{remote_path}"));
            self.agent_path = Some(path.clone());
            return Ok(path);
        }

        info!("Deploying agent to remote host...");

        // Create directory
        self.execute(&format!("mkdir -p ~/{remote_dir}")).await?;

        // Get remote home dir
        let (home, _, _) = self.execute("echo $HOME").await?;
        let home = home.trim();
        let full_path = format!("{home}/{remote_path}");

        // Upload via exec + stdin
        self.upload_bytes(agent_data, &full_path).await?;

        // Make executable
        self.execute(&format!("chmod +x {full_path}")).await?;

        info!("Agent deployed to {full_path}");
        self.agent_path = Some(PathBuf::from(&full_path));
        Ok(PathBuf::from(full_path))
    }

    /// Upload bytes to remote path via exec + stdin
    async fn upload_bytes(&self, data: &[u8], remote_path: &str) -> Result<()> {
        let mut channel = self.session.channel_open_session().await?;
        channel.exec(true, format!("cat > {remote_path}")).await?;

        channel.data(data).await?;
        channel.eof().await?;

        // Wait for completion
        loop {
            if let Some(ChannelMsg::Eof | ChannelMsg::Close) = channel.wait().await {
                break;
            }
        }

        Ok(())
    }

    /// Start the agent process on the remote host and return a session
    pub async fn start_agent(&self, root: &str) -> Result<AgentSession> {
        let agent_path = self.agent_path.as_ref().ok_or_else(|| {
            color_eyre::eyre::eyre!("Agent not deployed - call ensure_agent first")
        })?;

        let channel = self.session.channel_open_session().await?;
        channel
            .exec(
                true,
                format!("{} daemon --root {root}", agent_path.display()),
            )
            .await?;

        Ok(AgentSession {
            channel,
            root: PathBuf::from(root),
            buffer: Vec::new(),
        })
    }

    /// Disconnect from the remote host
    pub async fn disconnect(self) -> Result<()> {
        self.session
            .disconnect(Disconnect::ByApplication, "", "English")
            .await?;
        Ok(())
    }
}
