#![warn(rust_2018_idioms)]
#![recursion_limit = "512"]

use anyhow::Context;
use args::parse_args;
use bytes::Bytes;
use crevise::{generate_key, load_key, save_key, Error, MainLoop, Message, Result};
use futures::prelude::*;
use tokio::io;
use tokio_util::codec::{BytesCodec, FramedRead, FramedWrite, LinesCodec};

mod args;

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
    let args = parse_args()?;
    if args.generate_secret_key {
        let key = generate_key();
        save_key(&key, args.secret_key_file(), args.password())
            .context("Error generating secret key")?;
        eprintln!("Key was generated and saved");
        Ok(())
    } else {
        let key = load_key(args.secret_key_file(), args.password())
            .context("Error while loading secret key, you may need to generate it first")?;

        if args.show_my_id {
            let peer_id = crevise::PeerId::from(&key);
            println!("{}", peer_id);
            return Ok(())
        }

        let input = FramedRead::new(io::stdin(), LinesCodec::new())
            .err_into()
            .and_then(|s| future::ready(s.parse()));
        let output = io::stdout();
        let output = FramedWrite::new(output, BytesCodec::new())
            .with(|m: Message| future::ok::<_, Error>(Bytes::from(format_message(m))));

        let server = MainLoop::new(args.listen, key, input, output).await?;
        // This starts the server task.
        let res = server.run().await;
        match res {
            Err(e) => eprintln!("finished with error {}", e),
            Ok(_) => eprintln!("finished"),
        }

        // workaround as background thread which reads from stdin is still running
        std::process::exit(0);
    }
}
