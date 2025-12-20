# ssh_config

A small library to parse OpenBSD ssh_config files.

More documentation on the file format can be found in the [OpenBSD man pages](https://man.openbsd.org/OpenBSD-current/man5/ssh_config.5).

## Usage example

```
use ssh_config::SSHConfig;

let config = SSHConfig::parse_str(r#"
Host test-host
  Port 22
  Username user
"#)?;

let host_settings = config.query("test-host");
assert_eq!(host_settings["Port"], "22");
assert_eq!(host_settings["Username"], "User");
```
## License

This library is licensed under the Mozilla Public License, v. 2.0. The license file can be found in [LICENSE](./LICENSE).
