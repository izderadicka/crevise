#![warn(rust_2018_idioms)]
#![recursion_limit = "512"]

use bytes::Bytes;
use crevise::{generate_keypair, Error, MainLoop, Message, Result};
use futures::prelude::*;
use std::env;
use tokio::io;
use tokio_util::codec::{BytesCodec, FramedRead, FramedWrite, LinesCodec};

fn format_message(m: Message) -> String {
    match m {
        Message::Post { peer, content } => format!("\r:-> ({}) {}\n", peer, content),
        Message::NewLine => "<-: ".into(),
        Message::HadshakeDone { peer } => format!("\nHandshake done with peer {}\n", peer),
        _ => "".into(),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let addr = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:8080".to_string());

    let key = generate_keypair();

    let input = FramedRead::new(io::stdin(), LinesCodec::new())
        .err_into()
        .and_then(|s| future::ready(s.parse()));
    let output = io::stdout();
    let output = FramedWrite::new(output, BytesCodec::new())
        .with(|m: Message| future::ok::<_, Error>(Bytes::from(format_message(m))));

    let server = MainLoop::new(addr, key, input, output).await?;
    // This starts the server task.
    let res = server.run().await;
    match res {
        Err(e) => eprintln!("finished with error {}", e),
        Ok(_) => eprintln!("finished"),
    }

    // workaround as background thread which reads from stdin is still running
    std::process::exit(0);
}
