//! SSH transport implementation using system ssh/scp commands
//!
//! Uses system SSH for reliability and to leverage user's existing SSH config.

use std::path::{Path, PathBuf};
use std::process::Stdio;

use color_eyre::Result;
use tokio::process::{Child, Command};
use tracing::{debug, info};

use crate::Platform;
use crate::agent::AgentBundle;

/// SSH transport for communicating with remote hosts
pub struct SshTransport {
    host: String,
    port: u16,
    user: String,
    platform: Platform,
    agent_path: Option<PathBuf>,
}

impl SshTransport {
    /// Connect to a remote host via SSH
    ///
    /// # Errors
    /// Returns an error if connection or platform detection fails
    pub async fn connect(host: &str, port: u16, user: &str) -> Result<Self> {
        info!("Connecting to {user}@{host}:{port}");

        // Detect remote platform
        let platform = Self::detect_platform_static(host, port, user).await?;
        info!("Remote platform: {:?}", platform);

        Ok(Self {
            host: host.to_string(),
            port,
            user: user.to_string(),
            platform,
            agent_path: None,
        })
    }

    /// Detect remote platform via uname
    async fn detect_platform_static(host: &str, port: u16, user: &str) -> Result<Platform> {
        let output = Command::new("ssh")
            .args([
                "-p",
                &port.to_string(),
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=10",
                &format!("{user}@{host}"),
                "uname -s && uname -m",
            ])
            .output()
            .await?;

        if !output.status.success() {
            return Err(color_eyre::eyre::eyre!(
                "SSH connection failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let lines: Vec<&str> = stdout.lines().collect();

        if lines.len() < 2 {
            return Err(color_eyre::eyre::eyre!(
                "Failed to detect platform: unexpected uname output: {stdout}"
            ));
        }

        Platform::from_uname(lines.first().unwrap_or(&""), lines.get(1).unwrap_or(&"")).ok_or_else(
            || {
                color_eyre::eyre::eyre!(
                    "Unsupported platform: {} {}",
                    lines.first().unwrap_or(&""),
                    lines.get(1).unwrap_or(&"")
                )
            },
        )
    }

    /// Get the remote platform
    #[must_use]
    pub fn platform(&self) -> Platform {
        self.platform
    }

    /// Build SSH destination string
    fn ssh_dest(&self) -> String {
        format!("{}@{}", self.user, self.host)
    }

    /// Ensure the agent is deployed to the remote host
    ///
    /// # Errors
    /// Returns an error if agent deployment fails
    pub async fn ensure_agent(&mut self, bundle: &AgentBundle) -> Result<PathBuf> {
        if let Some(path) = &self.agent_path {
            return Ok(path.clone());
        }

        let version = env!("CARGO_PKG_VERSION");
        let remote_dir = format!(".zsync/agents/{version}");
        let remote_path = format!("{remote_dir}/zsync-agent");

        // Check if agent already exists
        let (stdout, _, _exit) = self
            .execute(&format!("test -x ~/{remote_path} && echo exists"))
            .await?;

        if stdout.contains("exists") {
            debug!("Agent already deployed at ~/{remote_path}");
            let home = self.get_home_dir().await?;
            let path = PathBuf::from(format!("{home}/{remote_path}"));
            self.agent_path = Some(path.clone());
            return Ok(path);
        }

        info!("Deploying agent to remote host...");

        // Create directory
        self.execute(&format!("mkdir -p ~/{remote_dir}")).await?;

        // Get agent binary for this platform
        let agent_data = bundle.get(self.platform).ok_or_else(|| {
            color_eyre::eyre::eyre!("No agent binary for platform {:?}", self.platform)
        })?;

        // Write to temp file and scp
        let temp_file = tempfile::NamedTempFile::new()?;
        tokio::fs::write(temp_file.path(), agent_data).await?;

        // Get remote home dir
        let home = self.get_home_dir().await?;
        let full_path = format!("{home}/{remote_path}");

        // SCP upload
        let status = Command::new("scp")
            .args([
                "-P",
                &self.port.to_string(),
                "-o",
                "BatchMode=yes",
                temp_file.path().to_str().unwrap(),
                &format!("{}:{}", self.ssh_dest(), full_path),
            ])
            .status()
            .await?;

        if !status.success() {
            return Err(color_eyre::eyre::eyre!("SCP upload failed"));
        }

        // Make executable
        self.execute(&format!("chmod +x {full_path}")).await?;

        info!("Agent deployed to {full_path}");
        self.agent_path = Some(PathBuf::from(full_path.clone()));
        Ok(PathBuf::from(full_path))
    }

    /// Get remote home directory
    async fn get_home_dir(&self) -> Result<String> {
        let (stdout, _, _) = self.execute("echo $HOME").await?;
        Ok(stdout.trim().to_string())
    }

    /// Execute a command on the remote host
    ///
    /// # Errors
    /// Returns an error if execution fails
    pub async fn execute(&self, command: &str) -> Result<(String, String, i32)> {
        let output = Command::new("ssh")
            .args([
                "-p",
                &self.port.to_string(),
                "-o",
                "BatchMode=yes",
                &self.ssh_dest(),
                command,
            ])
            .output()
            .await?;

        Ok((
            String::from_utf8_lossy(&output.stdout).to_string(),
            String::from_utf8_lossy(&output.stderr).to_string(),
            output.status.code().unwrap_or(-1),
        ))
    }

    /// Upload a file to the remote host
    ///
    /// # Errors
    /// Returns an error if upload fails
    pub async fn upload(&self, local_path: &Path, remote_path: &str) -> Result<()> {
        let status = Command::new("scp")
            .args([
                "-P",
                &self.port.to_string(),
                "-o",
                "BatchMode=yes",
                local_path.to_str().unwrap(),
                &format!("{}:{}", self.ssh_dest(), remote_path),
            ])
            .status()
            .await?;

        if !status.success() {
            return Err(color_eyre::eyre::eyre!("SCP upload failed"));
        }
        Ok(())
    }

    /// Download a file from the remote host
    ///
    /// # Errors
    /// Returns an error if download fails
    pub async fn download(&self, remote_path: &str, local_path: &Path) -> Result<()> {
        let status = Command::new("scp")
            .args([
                "-P",
                &self.port.to_string(),
                "-o",
                "BatchMode=yes",
                &format!("{}:{}", self.ssh_dest(), remote_path),
                local_path.to_str().unwrap(),
            ])
            .status()
            .await?;

        if !status.success() {
            return Err(color_eyre::eyre::eyre!("SCP download failed"));
        }
        Ok(())
    }

    /// Upload bytes directly to a remote path
    ///
    /// # Errors
    /// Returns an error if upload fails
    pub async fn upload_bytes(&self, data: &[u8], remote_path: &str) -> Result<()> {
        let temp_file = tempfile::NamedTempFile::new()?;
        tokio::fs::write(temp_file.path(), data).await?;
        self.upload(temp_file.path(), remote_path).await
    }

    /// Start the agent process on the remote host
    ///
    /// # Errors
    /// Returns an error if starting the agent fails
    pub fn start_agent(&self, root: &str) -> Result<Child> {
        let agent_path = self.agent_path.as_ref().ok_or_else(|| {
            color_eyre::eyre::eyre!("Agent not deployed - call ensure_agent first")
        })?;

        let child = Command::new("ssh")
            .args([
                "-p",
                &self.port.to_string(),
                "-o",
                "BatchMode=yes",
                &self.ssh_dest(),
                &format!("{} daemon --root {}", agent_path.display(), root),
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        Ok(child)
    }
}
