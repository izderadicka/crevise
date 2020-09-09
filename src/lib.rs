#![warn(rust_2018_idioms)]
#![recursion_limit = "512"]

use encrypted::Keypair;
use futures::prelude::*;
use futures::select;
use std::mem::replace;
use std::net::SocketAddr;
use tokio::net::ToSocketAddrs;
use tokio::net::UdpSocket;
use tokio::signal::unix::{signal, SignalKind};

use command::Command;
pub use encrypted::generate_keypair;
pub use message::Message;
use peers::PeersMap;

pub type Error = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T> = std::result::Result<T, Error>;

mod command;
mod encrypted;
pub mod message;
mod peers;

enum OutputMessage {
    None,
    Plain((SocketAddr, usize)),
    Encrypted((SocketAddr, usize)),
}

pub struct MainLoop<I, O> {
    socket: UdpSocket,
    buf: Vec<u8>,
    buf2: Vec<u8>,
    to_send: OutputMessage,
    input: I,
    //key: Keypair,
    peers: PeersMap,
    out: O,
}

impl<I, O> MainLoop<I, O>
where
    I: Stream<Item = Result<Command>> + Unpin,
    O: Sink<Message, Error = Error> + Unpin,
{
    pub async fn new(addr: impl ToSocketAddrs, key: Keypair, input: I, output: O) -> Result<Self> {
        let socket = UdpSocket::bind(&addr).await?;
        eprintln!("Listening on: {}", socket.local_addr()?);

        let server = MainLoop {
            socket,
            buf: vec![0; 10000],
            buf2: vec![0; 10000],
            to_send: OutputMessage::None,
            input,
            peers: PeersMap::new(key),
            out: output,
            //key,
        };

        Ok(server)
    }

    async fn process_incomming(&mut self, len: usize, peer: SocketAddr) -> Result<()> {
        //eprintln!("Received message size {}, enc is {}", len, enc.is_connected());
        if self.peers.is_connected(&peer).await {
            let size = self
                .peers
                .decrypt(&peer, &self.buf2[..len], &mut self.buf)
                .await?;
            self.out
                .send(Message::Post {
                    peer,
                    content: std::str::from_utf8(&self.buf[..size])
                        .unwrap_or("<invalid string>")
                        .to_string(),
                })
                .await?;
        } else {
            let size = self
                .peers
                .continue_handshake(peer, &self.buf2[..len], &mut self.buf)
                .await?;

            if size > 0 {
                self.to_send = OutputMessage::Plain((peer, size))
            } else {
                self.out.send(Message::HadshakeDone { peer }).await?;
            }
        }
        Ok(())
    }

    async fn process_command(&mut self, command: Command) -> Result<()> {
        match command {
            Command::Connect { peer } => {
                let len = self.peers.start_handshake(peer, &mut self.buf).await?;
                self.to_send = OutputMessage::Plain((peer, len));
                //eprintln!("Encrypted channel initiated")
            }
            Command::Send { to: peer, text } => {
                if self.peers.is_connected(&peer).await {
                    let msg = text.as_bytes();
                    let size = msg.len();
                    self.buf[..size].copy_from_slice(msg);
                    self.to_send = OutputMessage::Encrypted((peer, size));
                } else {
                    eprintln!("Encrypted channel is not connected");
                }
            }
        }

        Ok(())
    }

    pub async fn run(mut self) -> Result<()> {
        let mut sigint = signal(SignalKind::interrupt())?;
        let mut sigterm = signal(SignalKind::terminate())?;

        loop {
            // First we check to see if there's a message we need to echo back.
            // If so then we try to send it back to the original source, waiting
            // until it's writable and we're able to do so.
            match replace(&mut self.to_send, OutputMessage::None) {
                OutputMessage::Encrypted((peer, l)) => {
                    let len = self
                        .peers
                        .encrypt(&peer, &self.buf[..l], &mut self.buf2)
                        .await?;
                    self.socket.send_to(&self.buf2[..len], peer).await?;
                    self.out.send(Message::Sent { peer }).await?;
                }
                OutputMessage::Plain((peer, l)) => {
                    if self.peers.is_connected(&peer).await {
                        self.out.send(Message::HadshakeDone { peer }).await?;
                    };
                    self.socket.send_to(&self.buf[..l], peer).await?;
                    eprintln!("Sending handshake message");
                }
                OutputMessage::None => (),
            };

            self.out.send(Message::NewLine).await?;

            // If we're here then `to_send` is `None`, so we take a look for the
            // next message we're going to echo back.
            select!(
                msg = self.socket.recv_from(&mut self.buf2).fuse() => {
                    match msg {
                        Ok((len, peer)) => self.process_incomming(len, peer).await?,
                        Err(e) => eprintln!("error receiving message: {}", e)
                        }
                    }

                msg = self.input.next().fuse() => {
                    match msg {
                        Some(Ok(msg)) => self.process_command(msg).await?,
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
