use std::io::Read;

use anyhow::Result;
use url::Host;

use crate::parser_combinator::{parse_config, NetrcConfig};

/// A netrc entry validated to have at least a password.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedEntry {
    pub(crate) login: Option<String>,
    pub(crate) password: String,
}

impl ValidatedEntry {
    fn new<T, Y>(login: T, password: Y) -> Self
    where
        T: Into<Option<String>>,
        Y: Into<String>,
    {
        Self {
            login: login.into(),
            password: password.into(),
        }
    }

    /// Get the login value for the entry
    pub fn login(&self) -> Option<&String> {
        self.login.as_ref()
    }

    /// Get the password value for the entry
    pub fn password(&self) -> &str {
        &self.password
    }
}

/// Netrc parser mimicking the curl netrc parsers rules. This is a high level parser and is
/// recommended to be used for most use-cases. For a lower-level alternative, use
/// [crate::raw_netrc_parser::RawNetrcParser].
#[derive(Debug)]
pub struct NetrcParser<R: Read> {
    buffer: R,
    config: Option<NetrcConfig>,
}

impl<R: Read> NetrcParser<R> {
    /// Create a new parser from a buffer
    pub fn new(buffer: R) -> Self {
        Self {
            buffer,
            config: None,
        }
    }

    /// Parse the config file from the constructor and attempt to find the entry related to the
    /// given host.
    ///
    /// This method follows the following rules:
    ///
    /// - A entry must have a password and may have a login
    /// - Incomplete entries cannot fallback to the default entry
    /// - Field cannot be mixed with fields from the default entry
    /// - If the login is missing, the account value is used instead
    ///
    /// Invalid entries are filtered out from the resulting set.
    ///
    /// # Returns
    ///
    /// - An error if reading the input buffer failed
    /// - `Ok(None)` if the host was not found and no default was setup
    /// - `Ok(Some)` if either a default was setup or the host was found
    pub fn entry_for_host(&mut self, host: &Host) -> Result<Option<ValidatedEntry>> {
        let mut buf_content = String::new();
        self.buffer.read_to_string(&mut buf_content)?;

        let config = match &self.config {
            Some(config) => config.clone(),
            None => {
                let config = parse_config(&buf_content);
                self.config = Some(config.clone());

                config
            }
        };

        let entry = config.entries.get(host).or(config.default.as_ref());

        match entry {
            Some(entry) => match (
                entry.login.as_ref().or(entry.account.as_ref()),
                entry.password.as_ref(),
            ) {
                (login, Some(password)) => Ok(Some(ValidatedEntry::new(login.cloned(), password))),
                _ => Ok(None),
            },
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::BufReader;

    use super::*;

    const COM: &str = "example.com";
    const ORG: &str = "example.org";
    const UNI: &str = "xn--9ca.com";
    const IP1: &str = "1.1.1.1";
    const IP2: &str = "2.2.2.2.";

    #[test]
    fn parse_simple_config() {
        const SIMPLE: &str = "
            machine example.com
            login user
            password pass
        ";
        found(SIMPLE, COM, "user", "pass");
        notfound(SIMPLE, ORG);
        notfound(SIMPLE, UNI);
        notfound(SIMPLE, IP1);
    }

    #[test]
    fn parse_oneliner_config() {
        const ONELINE: &str = "
            machine example.com login user password pass
        ";
        found(ONELINE, COM, "user", "pass");
        notfound(ONELINE, ORG);
    }

    #[test]
    fn parse_config_with_multiple_records() {
        const MULTI: &str = "
            machine example.com login user password pass
            machine example.org login foo password bar
        ";
        found(MULTI, COM, "user", "pass");
        found(MULTI, ORG, "foo", "bar");
        notfound(MULTI, UNI);
    }

    #[test]
    fn parse_config_with_unicode() {
        const UNICODE: &str = "
            machine É.com login user password pass
        ";
        found(UNICODE, UNI, "user", "pass");
        notfound(UNICODE, COM);
    }

    #[test]
    fn parse_missing_password() {
        const MISSING_PASS: &str = "
            machine example.com login user
        ";
        notfound(MISSING_PASS, COM);
    }

    #[test]
    fn parse_missing_user() {
        const MISSING_USER: &str = "
            machine example.com password pass
            default login user
        ";
        found(MISSING_USER, COM, None, "pass");
        notfound(MISSING_USER, ORG);
    }

    #[test]
    fn parse_missing_default_missing_user() {
        const DEFAULT_PASSWORD_MISSING_USER: &str = "
            machine example.com password pass
            default password def
        ";
        found(DEFAULT_PASSWORD_MISSING_USER, COM, None, "pass");
        found(DEFAULT_PASSWORD_MISSING_USER, ORG, None, "def");
    }

    #[test]
    fn parse_default_last() {
        const DEFAULT_LAST: &str = "
            machine example.com login ex password am
            default login def password ault
        ";
        found(DEFAULT_LAST, COM, "ex", "am");
        found(DEFAULT_LAST, ORG, "def", "ault");
    }

    #[test]
    fn parse_default_first() {
        const DEFAULT_FIRST: &str = "
            default login def password ault
            machine example.com login ex password am
        ";
        found(DEFAULT_FIRST, COM, "ex", "am");
        found(DEFAULT_FIRST, ORG, "def", "ault");
    }

    #[test]
    fn parse_fallback_to_account() {
        const ACCOUNT_FALLBACK: &str = "
            machine example.com account acc password pass
        ";
        found(ACCOUNT_FALLBACK, COM, "acc", "pass");
    }

    #[test]
    fn parse_ignore_account() {
        const ACCOUNT_NOT_PREFERRED: &str = "
            machine example.com password pass login log account acc
            machine example.org password pass account acc login log
        ";
        found(ACCOUNT_NOT_PREFERRED, COM, "log", "pass");
        found(ACCOUNT_NOT_PREFERRED, ORG, "log", "pass");
    }

    #[test]
    fn parse_with_ip() {
        const WITH_IP: &str = "
            machine 1.1.1.1 login us password pa
        ";
        found(WITH_IP, IP1, "us", "pa");
        notfound(WITH_IP, IP2);
        notfound(WITH_IP, COM);
    }

    #[test]
    fn parse_weird_ip() {
        const WEIRD_IP: &str = "
            machine 16843009 login us password pa
        ";
        found(WEIRD_IP, IP1, "us", "pa");
        notfound(WEIRD_IP, IP2);
        notfound(WEIRD_IP, COM);
    }

    #[test]
    fn parse_malformed_config() {
        const MALFORMED: &str = "
            I'm a malformed netrc!
        ";
        notfound(MALFORMED, COM);
    }

    #[test]
    fn parse_ignore_config() {
        const COMMENT: &str = "
            # machine example.com login user password pass
            machine example.org login lo password pa
        ";
        notfound(COMMENT, COM);
        found(COMMENT, ORG, "lo", "pa");
    }

    #[test]
    fn parse_octothorpe() {
        const OCTOTHORPE_IN_VALUE: &str = "
            machine example.com login #!@$ password pass
        ";
        found(OCTOTHORPE_IN_VALUE, COM, "#!@$", "pass");
    }

    #[test]
    fn parse_sudden_end() {
        const SUDDEN_END: &str = "
            machine example.com login
        ";
        notfound(SUDDEN_END, COM);
    }

    #[test]
    fn parse_incomplete_and_default() {
        const INCOMPLETE_AND_DEFAULT: &str = "
            machine example.com login user
            default login u password p
        ";
        notfound(INCOMPLETE_AND_DEFAULT, COM);
        found(INCOMPLETE_AND_DEFAULT, ORG, "u", "p");
    }

    #[test]
    fn parse_unknown_token() {
        const UNKNOWN_TOKEN_INTERRUPT: &str = "
            machine example.com
            login user
            foo bar
            password pass
        ";
        notfound(UNKNOWN_TOKEN_INTERRUPT, COM);
    }

    #[test]
    fn parse_macro() {
        const MACRO: &str = "
            macdef foo
            machine example.com login mac password def
            qux

            machine example.com login user password pass
        ";
        found(MACRO, COM, "user", "pass");
        notfound(MACRO, ORG);
    }

    #[test]
    fn parse_unterminated_macro() {
        const MACRO_UNTERMINATED: &str = "
            macdef foo
            machine example.com login mac password def
            qux
            machine example.com login user password pass";
        notfound(MACRO_UNTERMINATED, COM);
    }

    #[test]
    fn parse_macro_blank_line_before_name() {
        const MACRO_BLANK_LINE_BEFORE_NAME: &str = "
            macdef

            foo
            machine example.com login mac password def";
        notfound(MACRO_BLANK_LINE_BEFORE_NAME, COM);
    }

    #[test]
    fn parse_many_lines() {
        const MANY_LINES: &str = "
            machine
            example.com
            login

            user
            password
            pass
        ";
        found(MANY_LINES, COM, "user", "pass");
    }

    #[test]
    fn parse_strange_characters() {
        const STRANGE_CHARACTERS: &str = "
            machine\u{2029}oké\t\u{2029}login  u   password  p\t\t\t\r\n
        ";
        notfound(STRANGE_CHARACTERS, COM);
    }

    #[track_caller]
    fn found(netrc: &str, host: &str, login: impl Into<Option<&'static str>>, password: &str) {
        let entry = NetrcParser::new(BufReader::new(netrc.as_bytes()))
            .entry_for_host(&Host::parse(host).unwrap());
        let entry = entry.unwrap().expect("Didn't find entry");

        assert_eq!(entry.login.as_deref(), login.into());
        assert_eq!(entry.password, password.to_string());
    }

    #[track_caller]
    fn notfound(netrc: &str, host: &str) {
        let entry = NetrcParser::new(netrc.as_bytes()).entry_for_host(&Host::parse(host).unwrap());

        assert!(entry.unwrap().is_none(), "Found entry");
    }
}
