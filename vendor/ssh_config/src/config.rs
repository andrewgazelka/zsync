/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use crate::{
    parser::entry_parser::{Entry, EntryParser},
    pattern::Pattern,
    Error,
};
use std::collections::HashMap;

pub type HostPattern = Pattern;
pub type ConfigKey = String;
pub type ConfigValue = String;

pub type HostConfig = HashMap<ConfigKey, ConfigValue>;

#[derive(Debug, Clone, PartialEq)]
pub struct SSHConfig {
    entries: HashMap<HostPattern, HostConfig>,
}

impl SSHConfig {
    /// Creates an empty config
    pub fn empty() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Query a host for its settings
    pub fn query<Q: AsRef<str>>(&self, query: Q) -> HostConfig {
        let query = query.as_ref();

        self.entries.keys().fold(HashMap::new(), |mut acc, host| {
            if host.matches(query) {
                let host_settings = &self.entries[host];
                acc.extend(host_settings.iter().map(|(k, v)| (k.clone(), v.clone())));
                acc
            } else {
                acc
            }
        })
    }

    /// Parses a config from a source str
    pub fn parse_str(source: &str) -> Result<Self, Error> {
        // Fails the entire operation on the first parser error
        let all_entries = EntryParser::new(source).collect::<Result<Vec<Entry>, Error>>()?;

        // Convert borrowed entries to owned
        let entries = all_entries
            .into_iter()
            .fold(HashMap::new(), |mut hm, entry| {
                let host = HostPattern::new(entry.host);
                if !hm.contains_key(&host) {
                    hm.insert(host.clone(), HashMap::new());
                }

                let host_hm = hm.get_mut(&host).unwrap(); // We are safe to unwrap because we just created the HashMap above

                host_hm.insert(entry.key.to_string(), entry.value.to_string());

                hm
            });

        Ok(Self { entries })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_simple() {
        let config = SSHConfig::parse_str(
            r#"
        Host test-host
          Port 22
          Username user
        "#,
        )
        .unwrap();

        let host_settings = config.query("test-host");
        assert_eq!(host_settings["Port"], "22");
        assert_eq!(host_settings["Username"], "user");
    }

    #[test]
    fn config_multi() {
        let config = SSHConfig::parse_str(
            r#"
        Host test-host,other-host
          Port 22
          Username user
        "#,
        )
        .unwrap();

        let host_settings = config.query("test-host");
        assert_eq!(host_settings["Port"], "22");
        assert_eq!(host_settings["Username"], "user");

        let other_host_settings = config.query("test-host");
        assert_eq!(other_host_settings["Port"], "22");
        assert_eq!(other_host_settings["Username"], "user");
    }
}
