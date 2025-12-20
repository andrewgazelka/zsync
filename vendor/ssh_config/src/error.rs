/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use crate::parser::{entry_parser::EntryParserError, tokenizer::TokenizerError};
use std::env::VarError;

#[derive(Debug, Clone, PartialEq)]
pub enum Error {
    /// An error occured when parsing the file
    TokenizerError(TokenizerError),
    /// An error occured when parsing the file
    EntryParserError(EntryParserError),

    /// An error occured when reading an environment variable
    ReadEnvVarError(VarError),
}

impl From<EntryParserError> for Error {
    fn from(entry_error: EntryParserError) -> Self {
        Error::EntryParserError(entry_error)
    }
}

impl From<TokenizerError> for Error {
    fn from(tokenizer_error: TokenizerError) -> Self {
        Error::TokenizerError(tokenizer_error)
    }
}

impl From<VarError> for Error {
    fn from(var_error: VarError) -> Self {
        Error::ReadEnvVarError(var_error)
    }
}
