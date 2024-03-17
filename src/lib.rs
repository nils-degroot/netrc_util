//! # `netrc_util`
//!
//! A simple libary for parsing [netrc](https://www.gnu.org/software/inetutils/manual/html_node/The-_002enetrc-file.html) files.
//!
//! ## Usage
//!
//! ```rust
//! use netrc_util::{Host, NetrcParser};
//!
//! let netrc_content = "machine sample.test login user password pass";
//! let host = Host::parse("sample.test").unwrap();
//!
//! let entry = NetrcParser::new(netrc_content.as_bytes())
//!     .entry_for_host(&host)
//!     .unwrap()
//!     .unwrap();
//!
//! assert_eq!(entry.login(), Some("user".to_string()).as_ref());
//! assert_eq!(entry.password(), "pass");
//! ```
pub mod netrc_parser;
mod parser_combinator;
pub mod raw_netrc_parser;

pub use crate::netrc_parser::{NetrcParser, ValidatedEntry};
pub use crate::raw_netrc_parser::{RawEntry, RawNetrcParser};
pub use url::Host;
