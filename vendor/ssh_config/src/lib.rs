/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

// A complete overview of the file format can be found here
// https://man.openbsd.org/OpenBSD-current/man5/ssh_config.5

//! # ssh_config
//!
//! A crate to parse OpenBSD ssh_config files
//!
//! ## Usage
//!
//! Using this crate involves parsing a ssh_config file and querying the resulting
//! `SSHConfig` object for host definitions
//!
//! ```
//! # fn test() -> Result<(), ssh_config::Error> {
//! use ssh_config::SSHConfig;
//!
//! let config = SSHConfig::parse_str(r#"
//! Host test-host
//!   Port 22
//!   Username user
//! "#)?;
//!
//! let host_settings = config.query("test-host");
//! assert_eq!(host_settings["Port"], "22");
//! assert_eq!(host_settings["Username"], "User");
//!
//! # Ok(())
//! # }
//! ```

#![allow(warnings)]

mod config;
mod error;
mod parser;
mod pattern;

pub use config::*;
pub use error::Error;
pub use pattern::Pattern;
