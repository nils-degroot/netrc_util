use std::collections::HashMap;

use nom::{
    branch::alt,
    bytes::complete::{tag, take_until, take_while, take_while1},
    combinator::map,
    sequence::tuple,
    IResult,
};
use url::Host;

use super::raw_netrc_parser::RawEntry;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct NetrcConfig {
    pub(crate) entries: HashMap<Host, RawEntry>,
    pub(crate) default: Option<RawEntry>,
}

#[derive(Debug)]
enum Token {
    Machine,
    Default,
    Login,
    Password,
    Account,
    MacDef(String, String),
    Comment(String),
    Text(String),
}

impl ToString for Token {
    fn to_string(&self) -> String {
        match self {
            Token::Machine => "machine".to_string(),
            Token::Default => "default".to_string(),
            Token::Login => "login".to_string(),
            Token::Password => "password".to_string(),
            Token::Account => "account".to_string(),
            Token::MacDef(name, content) => format!("macdef {name} {content}"),
            Token::Comment(comment) => format!("# {comment}"),
            Token::Text(text) => text.to_string(),
        }
    }
}

pub(crate) fn parse_config(input: &str) -> NetrcConfig {
    let tokens = tokenize(input);

    let mut entries = HashMap::new();
    let mut default = RawEntry::default();

    let mut active_machine: Option<Host> = None;
    let mut active_entry = RawEntry::default();

    let mut i = 0;
    let mut in_default = false;

    while let Some(next) = tokens.get(i) {
        match next {
            Token::Machine => {
                i += 1;
                in_default = false;

                if let Some(ref machine) = active_machine {
                    entries.insert(machine.clone(), active_entry.clone());
                }

                if let Some(machine) = tokens.get(i) {
                    active_machine = Host::parse(&machine.to_string()).ok();
                    active_entry = RawEntry::default()
                }
            }
            Token::Default => {
                in_default = true;
            }
            Token::Login => {
                i += 1;

                if in_default {
                    default.login = tokens.get(i).map(Token::to_string);
                } else {
                    active_entry.login = tokens.get(i).map(Token::to_string);
                }
            }
            Token::Password => {
                i += 1;

                if in_default {
                    default.password = tokens.get(i).map(Token::to_string);
                } else {
                    active_entry.password = tokens.get(i).map(Token::to_string);
                }
            }
            Token::Account => {
                i += 1;

                if in_default {
                    default.account = tokens.get(i).map(Token::to_string);
                } else {
                    active_entry.account = tokens.get(i).map(Token::to_string);
                }
            }
            // Macros should be ignored
            Token::MacDef(..) => (),
            // Comments should be ignored
            Token::Comment(_) => (),
            // Text here should invalidate the whole entry
            Token::Text(_) => {
                active_machine = None;
            }
        }

        i += 1;
    }

    if let Some(machine) = active_machine {
        entries.insert(machine, active_entry);
    }

    NetrcConfig {
        entries,
        default: if default == RawEntry::default() {
            None
        } else {
            Some(default)
        },
    }
}

fn tokenize(input: &str) -> Vec<Token> {
    let mut input = input;
    let mut tokens = vec![];

    while let Ok((rest, (_, token))) = tuple((drop_whitespace, token))(input) {
        input = rest;

        match token {
            Token::Comment(_) => (),
            token => tokens.push(token),
        }
    }

    tokens
}

fn token(input: &str) -> IResult<&str, Token> {
    alt((
        machine, login, password, account, default, comment, macdef, text,
    ))(input)
}

fn machine(input: &str) -> IResult<&str, Token> {
    map(tag("machine"), |_| Token::Machine)(input)
}

fn login(input: &str) -> IResult<&str, Token> {
    map(tag("login"), |_| Token::Login)(input)
}

fn password(input: &str) -> IResult<&str, Token> {
    map(tag("password"), |_| Token::Password)(input)
}

fn account(input: &str) -> IResult<&str, Token> {
    map(tag("account"), |_| Token::Account)(input)
}

fn default(input: &str) -> IResult<&str, Token> {
    map(tag("default"), |_| Token::Default)(input)
}

fn comment(input: &str) -> IResult<&str, Token> {
    map(
        tuple((tag("# "), take_until("\n"))),
        |(_, comment): (_, &str)| Token::Comment(comment.to_string()),
    )(input)
}

fn text(input: &str) -> IResult<&str, Token> {
    map(word, |text| Token::Text(text.to_string()))(input)
}

fn macdef(input: &str) -> IResult<&str, Token> {
    map(
        tuple((
            tag("macdef"),
            drop_whitespace,
            word,
            alt((take_until("\n\n"), take_while(|_| true))),
        )),
        |(_, _, name, content)| Token::MacDef(name.to_string(), content.to_string()),
    )(input)
}

fn drop_whitespace(input: &str) -> IResult<&str, ()> {
    map(take_while(|c: char| c.is_whitespace()), |_| ())(input)
}

fn word(input: &str) -> IResult<&str, &str> {
    take_while1(|c: char| !c.is_whitespace())(input)
}
