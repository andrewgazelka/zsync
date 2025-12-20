/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use crate::Error;

#[derive(Debug, Clone, PartialEq)]
pub enum TokenizerError {
    /// If we parsed a double quote but found no matching quote.
    UnterminatedString,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Token<'a> {
    /// Any freestanding word delimited by whitespace
    Word(&'a str),

    /// A double-quote delimited string
    String(&'a str),

    /// A comment
    Comment(&'a str),
}

impl<'a> Token<'a> {
    pub fn len(&self) -> usize {
        match self {
            Token::Word(w) => w.len(),
            Token::String(s) => s.len(),
            Token::Comment(c) => c.len(),
        }
    }
}

impl<'a> Into<&'a str> for Token<'a> {
    fn into(self) -> &'a str {
        match self {
            Token::Word(w) => w,
            Token::String(s) => s,
            Token::Comment(c) => c,
        }
    }
}

/// A sshconfig tokenizer
///
/// A small difference between us and the libssh parser
/// is that we consider all unicode whitespace instead of only
/// ascii whitespace.
#[derive(Debug, Clone, PartialEq)]
pub struct Tokenizer<'a> {
    source: &'a str,
}

impl<'a> Tokenizer<'a> {
    pub fn new(source: &'a str) -> Self {
        Self { source }
    }

    fn skip_whitespace(&mut self) {
        self.source = self.source.trim_start();
    }
}

impl<'a> Iterator for Tokenizer<'a> {
    type Item = Result<Token<'a>, Error>;

    // TODO: This is terrible, please clean it up
    fn next(&mut self) -> Option<Self::Item> {
        self.skip_whitespace();

        match self.source {
            // Comments
            a if a.starts_with('#') => Some(Ok({
                let comment = a[1..]
                    .lines()
                    .next()
                    .map(Token::Comment)
                    .unwrap_or(Token::Comment(""));

                let skip_len = 1 + comment.len();
                self.source = &a[skip_len..];
                comment
            })),

            // Strings
            a if a.starts_with('\"') => {
                // Find terminating "
                if let Some(idx) = self.source[1..].find('\"') {
                    let token = Token::String(&self.source[1..=idx]);
                    self.source = &self.source[idx + 2..];
                    Some(Ok(token))
                } else {
                    Some(Err(TokenizerError::UnterminatedString.into()))
                }
            }

            _ => {
                if let Some(word) = self.source.split_whitespace().next() {
                    let len = word.len();
                    let token = Token::Word(&self.source[0..len]);
                    self.source = &self.source[word.len()..];
                    Some(Ok(token))
                } else {
                    None
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tokenize_single<'a>(tok: &'a str) -> Option<Result<Token<'a>, Error>> {
        let mut tokenizer = Tokenizer::new(tok);
        tokenizer.next()
    }

    #[test]
    fn tokenizes_words() {
        assert_eq!(tokenize_single("hello"), Some(Ok(Token::Word("hello"))));
        assert_eq!(tokenize_single("  hello"), Some(Ok(Token::Word("hello"))));
    }

    #[test]
    fn tokenizes_strings() {
        assert_eq!(
            tokenize_single("\"hello\""),
            Some(Ok(Token::String("hello")))
        );
        assert_eq!(
            tokenize_single("   \"hello\"   "),
            Some(Ok(Token::String("hello")))
        );
        assert_eq!(
            tokenize_single("   \"he---llo\"   "),
            Some(Ok(Token::String("he---llo")))
        );
    }

    #[test]
    fn multiple_tokens() {
        let mut tokenizer = Tokenizer::new(
            r#"
        hello
        "boys"
        and
        girls
        "#,
        );

        assert_eq!(tokenizer.next(), Some(Ok(Token::Word("hello"))));
        assert_eq!(tokenizer.next(), Some(Ok(Token::String("boys"))));
        assert_eq!(tokenizer.next(), Some(Ok(Token::Word("and"))));
        assert_eq!(tokenizer.next(), Some(Ok(Token::Word("girls"))));
        assert_eq!(tokenizer.next(), None);
    }

    #[test]
    fn unterminated_error() {
        let mut tokenizer = Tokenizer::new("   \"he---llo   ");

        assert_eq!(
            tokenizer.next(),
            Some(Err(TokenizerError::UnterminatedString.into()))
        );
        assert_eq!(
            tokenizer.next(),
            Some(Err(TokenizerError::UnterminatedString.into()))
        );
        assert_eq!(
            tokenizer.next(),
            Some(Err(TokenizerError::UnterminatedString.into()))
        );
    }

    #[test]
    fn comment() {
        let mut tokenizer = Tokenizer::new("#hello");
        assert_eq!(tokenizer.next(), Some(Ok(Token::Comment("hello"))));
    }

    #[test]
    fn comment_eof() {
        let mut tokenizer = Tokenizer::new("#");
        assert_eq!(tokenizer.next(), Some(Ok(Token::Comment(""))));
    }
}
