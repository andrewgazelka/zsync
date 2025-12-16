//! zsync configuration file parsing (.zsync.toml)

use std::path::Path;

/// zsync project configuration
#[derive(Debug, Default, serde::Deserialize)]
#[serde(default)]
pub struct ZsyncConfig {
    /// Files to include even if gitignored
    pub include: Vec<String>,

    /// Port forwarding rules
    #[serde(default)]
    pub forward: Vec<PortForward>,
}

/// Port forwarding configuration
#[derive(Debug, serde::Deserialize)]
pub struct PortForward {
    /// Local port to listen on
    pub local: u16,
    /// Remote port to connect to
    pub remote: u16,
    /// Remote host (default: "localhost")
    #[serde(default = "default_remote_host")]
    pub remote_host: String,
}

fn default_remote_host() -> String {
    "localhost".to_string()
}

/// Config file name
pub const CONFIG_FILE: &str = ".zsync.toml";

impl ZsyncConfig {
    /// Load config from project root.
    ///
    /// Returns default config if .zsync.toml doesn't exist.
    ///
    /// # Errors
    /// Returns an error if the file exists but cannot be parsed.
    pub fn load(root: &Path) -> color_eyre::Result<Self> {
        let config_path = root.join(CONFIG_FILE);
        if config_path.exists() {
            let content = std::fs::read_to_string(&config_path)?;
            let config: Self = toml::from_str(&content)?;
            Ok(config)
        } else {
            Ok(Self::default())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_config_with_forwards() {
        let toml = r#"
include = ["secrets/key.pem", ".env"]

[[forward]]
local = 8080
remote = 8080

[[forward]]
local = 3000
remote = 3000
remote_host = "api-server"
"#;

        let config: ZsyncConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.include.len(), 2);
        assert_eq!(config.include[0], "secrets/key.pem");
        assert_eq!(config.forward.len(), 2);
        assert_eq!(config.forward[0].local, 8080);
        assert_eq!(config.forward[0].remote, 8080);
        assert_eq!(config.forward[0].remote_host, "localhost");
        assert_eq!(config.forward[1].remote_host, "api-server");
    }

    #[test]
    fn test_parse_empty_config() {
        let toml = "";
        let config: ZsyncConfig = toml::from_str(toml).unwrap();
        assert!(config.include.is_empty());
        assert!(config.forward.is_empty());
    }

    #[test]
    fn test_parse_include_only() {
        let toml = r#"
include = [".env.local"]
"#;

        let config: ZsyncConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.include.len(), 1);
        assert!(config.forward.is_empty());
    }
}
