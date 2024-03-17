# `netrc_util`

A simple libary for parsing [netrc](https://www.gnu.org/software/inetutils/manual/html_node/The-_002enetrc-file.html) files.

## Usage

```rust
use netrc_util::{Host, NetrcParser};

fn main() {
    let netrc_content = "machine sample.test login user password pass";
    let host = Host::parse("sample.test").unwrap();

    let entry = NetrcParser::new(netrc_content).entry_for_host(&host).unwrap().unwrap();

    assert_eq!(entry.login(), Some("login"));
    assert_eq!(entry.password(), Some("pass"));
}
