use std::io::Read;

use anyhow::Result;
use url::Host;

use crate::parser_combinator::{parse_config, NetrcConfig};

/// A raw netrc entry which may contain values.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RawEntry {
    pub(crate) login: Option<String>,
    pub(crate) password: Option<String>,
    pub(crate) account: Option<String>,
}

/// A raw netrc entry containing some values.
impl RawEntry {
    /// Get the login value for the entry.
    pub fn login(&self) -> Option<&String> {
        self.login.as_ref()
    }

    /// Get the password value for the entry.
    pub fn password(&self) -> Option<&String> {
        self.password.as_ref()
    }

    /// Get the account value for the entry.
    pub fn account(&self) -> Option<&String> {
        self.account.as_ref()
    }
}

/// A lower-level netrc parser without any business rules related to it. Not recommended for most
/// use-cases. For a higher-level parser use the [crate::netrc_parser::NetrcParser].
#[derive(Debug)]
pub struct RawNetrcParser<R: Read> {
    buffer: R,
    config: Option<NetrcConfig>,
}

impl<R: Read> RawNetrcParser<R> {
    /// Create a new parser from a buffer
    pub fn new(buffer: R) -> Self {
        Self {
            buffer,
            config: None,
        }
    }

    /// Parse the config file from the constructor and attempt to find the entry related to the
    /// given host. Entries are not validated to contain any values and could be empty.
    ///
    /// # Returns
    ///
    /// - An error if reading the input buffer failed
    /// - `Ok(None)` if the host was not found and no default was setup
    /// - `Ok(Some)` if either a default was setup or the host was found
    pub fn entry_for_host(&mut self, host: &Host) -> Result<Option<RawEntry>> {
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

        Ok(config
            .entries
            .get(host)
            .or(config.default.as_ref())
            .cloned())
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
            account acc
        ";
        found(SIMPLE, COM, "user", "pass", "acc");
        notfound(SIMPLE, ORG);
        notfound(SIMPLE, UNI);
        notfound(SIMPLE, IP1);
    }

    #[test]
    fn parse_empty_config() {
        const SIMPLE: &str = "
            machine example.com
        ";
        found(SIMPLE, COM, None, None, None);
        notfound(SIMPLE, ORG);
        notfound(SIMPLE, UNI);
        notfound(SIMPLE, IP1);
    }

    #[track_caller]
    fn found(
        netrc: &str,
        host: &str,
        login: impl Into<Option<&'static str>>,
        password: impl Into<Option<&'static str>>,
        account: impl Into<Option<&'static str>>,
    ) {
        let entry = RawNetrcParser::new(BufReader::new(netrc.as_bytes()))
            .entry_for_host(&Host::parse(host).unwrap());
        let entry = entry.unwrap().expect("Didn't find entry");

        assert_eq!(entry.login.as_deref(), login.into());
        assert_eq!(entry.password.as_deref(), password.into());
        assert_eq!(entry.account.as_deref(), account.into());
    }

    #[track_caller]
    fn notfound(netrc: &str, host: &str) {
        let entry =
            RawNetrcParser::new(netrc.as_bytes()).entry_for_host(&Host::parse(host).unwrap());

        assert!(entry.unwrap().is_none(), "Found entry");
    }
}
