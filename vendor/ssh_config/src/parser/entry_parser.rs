/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use crate::{parser::tokenizer::*, Error};

/// A config entry for a host
///
/// A ssh config file has blocks of hosts and configs as such:
/// ```text
/// Host hello-hos
///   User username
///   Port 1000
/// ```
///
/// A `Entry` represents a single config entry associated
/// with a host.
/// So in the above example we would have a `Entry` for the
/// `User` field in the `hello-hos` Host.
/// and a different `Entry` for the `Port` field
#[derive(Debug, Clone, PartialEq)]
pub struct Entry<'a> {
    pub host: &'a str,
    pub key: &'a str,
    pub value: &'a str,
}

impl<'a> Entry<'a> {
    pub fn new(host: &'a str, key: &'a str, value: &'a str) -> Self {
        Self { host, key, value }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum EntryParserError {
    /// We return this if we find a config option without a preceding host
    ///
    /// An example would be
    /// ```text
    ///   User hello
    /// ```
    /// The setting has no preceding host, so we don't know which host to associate it to
    InvalidHostEntry,

    /// Happens if we get a `Host` keyword, but nothing following it
    IncompleteHostEntry,

    /// Happens if we get a key name that's delimited by double quotes
    InvalidKeyName,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EntryParser<'a> {
    tokenizer: Tokenizer<'a>,
    current_host: Option<&'a str>,
}

impl<'a> EntryParser<'a> {
    pub fn new(source: &'a str) -> Self {
        Self {
            tokenizer: Tokenizer::new(source),
            current_host: None,
        }
    }

    /// Matches a token that we can use when parsing an entry
    /// (not a comment or whitespace)
    fn next_valid_token<'b>(&'b mut self) -> Option<Result<Token<'a>, Error>> {
        match self.tokenizer.next() {
            Some(Ok(Token::Comment(_))) => self.next_valid_token(),
            token => token,
        }
    }
}

impl<'a> Iterator for EntryParser<'a> {
    type Item = Result<Entry<'a>, Error>;

    /// Iterate the token stream by pairs of tokens
    ///
    /// This should neatly map into one entry per call
    ///
    /// We have an exception, if the first entry is a Host
    /// we need to switch our current host and procede with parsing
    /// the next config
    ///
    /// Example:
    /// ```text
    /// Host hello
    ///   Username user
    ///   Port 22
    /// ```
    ///
    /// On the first call, we would notice the `Host` key, and change our `current_host`
    /// into that. We would then call `next()` ourselfs so we can return an option.
    ///
    /// On the second next call, we already have `current_host`, The first
    /// token will be `Username` and the second `user` which is a KV entry.
    /// so we can return that.
    ///
    /// The `next()` call after that we get `Port` and `22` which is also easly parsable
    fn next(&mut self) -> Option<Self::Item> {
        match (self.next_valid_token(), self.next_valid_token()) {
            (Some(Ok(Token::Word("Host"))), Some(Err(_)))
            | (Some(Ok(Token::Word("Host"))), None) => {
                Some(Err(EntryParserError::IncompleteHostEntry.into()))
            }
            (Some(Ok(Token::Word("Host"))), Some(Ok(Token::Word(hostname)))) => {
                // We will switch the host, but recurse into next for the next entry
                self.current_host = Some(hostname);
                self.next()
            }
            (Some(Ok(Token::Word(key))), Some(Ok(value))) => {
                if let Some(current_host) = self.current_host {
                    Some(Ok(Entry::new(current_host, key, value.into())))
                } else {
                    Some(Err(EntryParserError::InvalidHostEntry.into()))
                }
            }
            (Some(Ok(Token::String(_))), Some(Ok(_))) => {
                Some(Err(EntryParserError::InvalidKeyName.into()))
            }

            (Some(Ok(Token::Comment(_))), _) | (_, Some(Ok(Token::Comment(_)))) => {
                // This is unreachable because `next_valid_token` will never pass us comments
                unreachable!()
            }
            (Some(Err(error)), _) => Some(Err(error)),
            (_, Some(Err(error))) => Some(Err(error)),
            (None, None) | (None, _) | (_, None) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_full(input: &str) -> Vec<Result<Entry, Error>> {
        EntryParser::new(input).collect()
    }

    #[test]
    fn parse_simple() {
        assert_eq!(
            parse_full(
                r#"
                Host test
                  Username user
                  Password "pass"
            "#
            ),
            vec![
                Ok(Entry::new("test", "Username", "user")),
                Ok(Entry::new("test", "Password", "pass")),
            ]
        );
    }

    #[test]
    fn no_setting() {
        assert_eq!(
            parse_full(
                r#"
                Host ayy
            "#
            ),
            vec![]
        );
    }

    #[test]
    fn multi_host() {
        assert_eq!(
            parse_full(
                r#"
                Host ayy
                  Username user

                Host test
                  Address 10.1.1.1
            "#
            ),
            vec![
                Ok(Entry::new("ayy", "Username", "user")),
                Ok(Entry::new("test", "Address", "10.1.1.1")),
            ]
        );
    }

    #[test]
    fn no_host_error() {
        assert_eq!(
            parse_full(r"Host"),
            vec![Err(EntryParserError::IncompleteHostEntry.into())]
        );
    }

    #[test]
    fn invalid_host_entry() {
        assert_eq!(
            parse_full(r"Username test"),
            vec![Err(EntryParserError::InvalidHostEntry.into())]
        );
    }

    #[test]
    fn invalid_key_name() {
        assert_eq!(
            parse_full(
                r#"
                Host test
                  "Hellokey" 123
            "#
            ),
            vec![Err(EntryParserError::InvalidKeyName.into())]
        );
    }

    #[test]
    fn comment() {
        assert_eq!(
            parse_full(
                r#"
                # This is a test
                Host test
                  Hellokey 123
            "#
            ),
            vec![Ok(Entry::new("test", "Hellokey", "123"))]
        );
    }

    #[test]
    fn inline_comment() {
        assert_eq!(
            parse_full(
                r#"
                Host test # This is a test
                  Hellokey 123
            "#
            ),
            vec![Ok(Entry::new("test", "Hellokey", "123"))]
        );
    }

    #[test]
    fn inline_comment_2() {
        assert_eq!(
            parse_full(
                r#"
                Host test
                  Hellokey 123  # This is a test
            "#
            ),
            vec![Ok(Entry::new("test", "Hellokey", "123"))]
        );
    }
}
