/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PatternEntry {
    pub is_negated: bool,
    pub pattern: String,
}

impl PatternEntry {
    pub fn new<S: AsRef<str>>(src: S) -> Self {
        let src = src.as_ref();
        debug_assert!(src.find(',').is_none());
        let is_negated = src.starts_with('!');

        let pattern = (if is_negated { &src[1..] } else { src }).to_string();

        Self {
            is_negated,
            pattern,
        }
    }

    pub fn matches<S: AsRef<str>>(&self, query: S) -> bool {
        let query = query.as_ref();

        self.pattern == query
    }
}

impl fmt::Display for PatternEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_negated {
            write!(f, "!")?;
        }

        write!(f, "{}", self.pattern)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Pattern {
    entries: Vec<PatternEntry>,
}

impl Pattern {
    pub fn new<S: AsRef<str>>(src: S) -> Self {
        Pattern {
            entries: src.as_ref().split(',').map(PatternEntry::new).collect(),
        }
    }

    pub fn matches<S: AsRef<str>>(&self, query: S) -> bool {
        let query = query.as_ref();

        let mut has_matched = false;
        for entry in self.entries.iter() {
            let matches = entry.matches(query);

            // If the entry is negated and it matches we can stop searching
            if matches && entry.is_negated {
                return false;
            }

            has_matched |= matches;
        }

        has_matched
    }
}

impl<'a> From<&'a str> for Pattern {
    fn from(src: &'a str) -> Pattern {
        Pattern::new(src)
    }
}

impl<'a> Into<String> for Pattern {
    fn into(self) -> String {
        format!("{}", self)
    }
}

impl fmt::Display for Pattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self
            .entries
            .iter()
            .map(|p| format!("{}", p))
            .collect::<Vec<String>>()
            .join(",");

        write!(f, "{}", s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_pattern() {
        let pat = Pattern::new("hello");

        assert_eq!(pat.matches("hello"), true);
        assert_eq!(pat.matches("what"), false);
        assert_eq!(pat.matches("ahello"), false);
        assert_eq!(pat.matches("helloa"), false);
    }

    #[test]
    fn multi_pattern() {
        let pat = Pattern::new("hello,what");

        assert_eq!(pat.matches("hello"), true);
        assert_eq!(pat.matches("what"), true);
        assert_eq!(pat.matches("hello,what"), false);
    }

    #[test]
    fn negate_pattern() {
        let pat = Pattern::new("hello,!what");

        assert_eq!(pat.matches("hello"), true);
        assert_eq!(pat.matches("what"), false);
        assert_eq!(pat.matches("!what"), false);
        assert_eq!(pat.matches("hello,!what"), false);
    }

    #[test]
    #[ignore]
    fn wildcard() {
        let pat = Pattern::new("*.com");

        assert_eq!(pat.matches("test.com"), true);
        assert_eq!(pat.matches("test.co"), false);
    }

    #[test]
    #[ignore]
    fn multiple_wildcards() {
        let pat = Pattern::new("*.*.uk");

        assert_eq!(pat.matches("test.test.uk"), true);
        assert_eq!(pat.matches("test.co.uk"), true);
        assert_eq!(pat.matches("..uk"), true);
        assert_eq!(pat.matches("testco.uk"), false);
    }

    #[test]
    #[ignore]
    fn question_mark() {
        let pat = Pattern::new("?.uk");

        assert_eq!(pat.matches("a.uk"), true);
        assert_eq!(pat.matches("ab.uk"), false);
    }

    #[test]
    #[ignore]
    fn multi_wildcard() {
        let pat = Pattern::new("!host1,!host2,*");

        assert_eq!(pat.matches("a"), true);
        assert_eq!(pat.matches("whatever"), true);
        assert_eq!(pat.matches("host1"), false);
        assert_eq!(pat.matches("host2"), false);
    }

    #[test]
    fn format_tests() {
        let pat = "hello,!test,*ayy";
        assert_eq!(format!("{}", Pattern::new(pat)), String::from(pat));
    }
}
