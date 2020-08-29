#![warn(rust_2018_idioms)]
#![recursion_limit = "512"]

use encrypted::{generate_keypair, EncryptedChannel, Keypair};
use futures::prelude::*;
use futures::select;
use std::env;
use std::mem::replace;
use std::net::SocketAddr;
use tokio::io::AsyncWriteExt;
use tokio::net::UdpSocket;
use tokio::signal::unix::{signal, SignalKind};
use tokio::{io, net::ToSocketAddrs};
use tokio_util::codec::{FramedRead, LinesCodec};

type Error = Box<dyn std::error::Error + Send + Sync>;
type Result<T> = std::result::Result<T, Error>;

mod encrypted;

enum Message {
    None,
    Plain((SocketAddr, usize)),
    Encrypted((SocketAddr, usize)),
}

struct MainLoop {
    socket: UdpSocket,
    buf: Vec<u8>,
    buf2: Vec<u8>,
    to_send: Message,
    input: FramedRead<io::Stdin, LinesCodec>,
    peer: Option<SocketAddr>,
    key: Keypair,
}

impl MainLoop {
    async fn new(
        addr: impl ToSocketAddrs,
        key: Keypair,
        peer: Option<impl ToSocketAddrs>,
    ) -> Result<Self> {
        let socket = UdpSocket::bind(&addr).await?;
        eprintln!("Listening on: {}", socket.local_addr()?);

        let peer = match peer {
            Some(a) => {
                let peer = a
                    .to_socket_addrs()
                    .await?
                    .next()
                    .ok_or_else(|| "cannot resolve")?;
                Some(peer)
            }
            None => None,
        };

        let server = MainLoop {
            socket,
            buf: vec![0; 10000],
            buf2: vec![0; 10000],
            to_send: Message::None,
            input: FramedRead::new(io::stdin(), LinesCodec::new()),
            peer,
            key,
        };

        Ok(server)
    }

    async fn process_incomming(len: usize, enc: &mut EncryptedChannel) {

    }
    async fn run(mut self) -> Result<()> {
        let mut sigint = signal(SignalKind::interrupt())?;
        let mut sigterm = signal(SignalKind::terminate())?;
        let mut stdout = io::stdout();

        let mut enc = EncryptedChannel::new(self.key);
        if let Some(peer) = self.peer {
            let len = enc.start_handshake(&mut self.buf)?;
            self.to_send = Message::Plain((peer, len));
            eprintln!("Encrypted channel initiated")
        }

        loop {
            // First we check to see if there's a message we need to echo back.
            // If so then we try to send it back to the original source, waiting
            // until it's writable and we're able to do so.
            let msg = match replace(&mut self.to_send, Message::None) {
                Message::Encrypted((peer, l)) => {
                    let len = enc.encrypt(&self.buf[..l], &mut self.buf2)?;
                    Some((len, &self.buf2, peer))
                }
                Message::Plain((peer, l)) => {
                    if enc.is_connected() {eprintln!("\nDone handshake") };
                    Some((l, &self.buf, peer))
                }
                Message::None => None,
            };
            if let Some((l, b, peer)) = msg {
                self.socket.send_to(&b[..l], peer).await?;
            }

            stdout.write_all("<-: ".as_bytes()).await?;
            stdout.flush().await?;

            // If we're here then `to_send` is `None`, so we take a look for the
            // next message we're going to echo back.
            select!(
                msg = self.socket.recv_from(&mut self.buf2).fuse() => {
                    match msg {
                        Ok((len, peer)) => {
                            //eprintln!("Received message size {}, enc is {}", len, enc.is_connected());
                            if enc.is_connected() {
                                let size = enc.decrypt(&self.buf2[..len], &mut self.buf)?;
                                stdout.write_all(format!("\n:-> ({}) :: {}\n", peer,
                                std::str::from_utf8(&self.buf[..size]).unwrap_or("<invalid string>")).as_bytes()).await?;
                            } else {
                                let size = enc.continue_handshake(&self.buf2[..len], &mut self.buf)?;
                                if self.peer.is_none() {
                                    self.peer = Some(peer);
                                }
                                if size > 0 {
                                    self.to_send = Message::Plain((peer, size))
                                } else {
                                    eprintln!("\nDone handshake");
                                }
                            }


                        }
                        Err(e) => eprintln!("error receiving message: {}", e)
                        }
                    }

                msg = self.input.next().fuse() => {
                    match msg {
                        Some(Ok(msg)) => if enc.is_connected(){
                            let msg = msg.as_bytes();
                            let size = msg.len();
                            self.buf[..size].copy_from_slice(msg);
                            self.to_send = Message::Encrypted((self.peer.ok_or("Peer is not known")?,size));
                        } else {
                                eprintln!("Encrypted channel is not connected");
                            }
                        Some(Err(e)) => eprintln!("input error {}", e),
                        None => {
                            eprintln!("EOF of input");
                            return Ok(())
                        }
                    }

                }

                s = sigint.recv().fuse() => {
                    eprintln!("Received SIGINT, terminating");
                    break
                }

                s = sigterm.recv().fuse() => {
                    eprintln!("Received SIGTERM, terminating");
                    break
                }
            )
        }
        eprintln!("main loop done");
        //input.next().await;
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let addr = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:8080".to_string());

    let peer = env::args().nth(2);

    let key = generate_keypair();

    let server = MainLoop::new(addr, key, peer).await?;
    // This starts the server task.
    let res = server.run().await;
    match res {
        Err(e) => eprintln!("finished with error {}", e),
        Ok(_) => eprintln!("finished"),
    }

    // workaround as background thread which reads from stdin is still running
    std::process::exit(0);
}
