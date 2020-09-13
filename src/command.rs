use crate::{Error, Result, error::{bail, new_error}};
use std::net::SocketAddr;
use std::str::FromStr;

pub enum Command {
    Connect { peer: SocketAddr },
    Send { to: SocketAddr, text: String },
}

fn split_at_first_space<'a>(s: &'a str) -> Result<(&'a str, &'a str)> {
    let first_space = s
        .find(' ')
        .ok_or_else(|| new_error!("Cannot split by space"))?;
    let (a, b) = s.split_at(first_space);
    Ok((a, b.trim()))
}

impl FromStr for Command {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        let (cmd, next) = split_at_first_space(s)?;
        Ok(match cmd {
            "connect" | "c" => Command::Connect {
                peer: next.parse()?,
            },
            "send" | "s" => {
                let (addr, text) = split_at_first_space(next)?;
                Command::Send {
                    to: addr.parse()?,
                    text: text.into(),
                }
            }
            _ => bail!("Invalid command {}", cmd),
        })
    }
}
