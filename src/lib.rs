#![warn(rust_2018_idioms)]
#![recursion_limit = "512"]

use encrypted::{EncryptedChannel, Keypair};
use futures::prelude::*;
use futures::select;
use std::mem::replace;
use std::net::SocketAddr;
use tokio::net::ToSocketAddrs;
use tokio::net::UdpSocket;
use tokio::signal::unix::{signal, SignalKind};

pub use message::Message;
pub use encrypted::generate_keypair;

pub type Error = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T> = std::result::Result<T, Error>;



mod encrypted;
pub mod message;

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
    peer: Option<SocketAddr>,
    //key: Keypair,
    enc: EncryptedChannel,
    out: O,
}

impl<I, O> MainLoop<I, O>
where
    I: Stream<Item = Result<String>> + Unpin,
    O: Sink<Message, Error = Error> + Unpin,
{
    pub async fn new(
        addr: impl ToSocketAddrs,
        key: Keypair,
        peer: Option<impl ToSocketAddrs>,
        input: I,
        output: O,
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
            to_send: OutputMessage::None,
            input,
            peer,
            enc: EncryptedChannel::new(key),
            out: output,
            //key,
        };

        Ok(server)
    }

    async fn process_incomming(&mut self, len: usize, peer: SocketAddr) -> Result<()> {
        //eprintln!("Received message size {}, enc is {}", len, enc.is_connected());
        if self.enc.is_connected() {
            let size = self.enc.decrypt(&self.buf2[..len], &mut self.buf)?;
            self.out
                .send(Message::Post{peer,
                    content: std::str::from_utf8(&self.buf[..size]).unwrap_or("<invalid string>").to_string()
                })
                .await?;
        } else {
            let size = self
                .enc
                .continue_handshake(&self.buf2[..len], &mut self.buf)?;
            if self.peer.is_none() {
                self.peer = Some(peer);
            }
            if size > 0 {
                self.to_send = OutputMessage::Plain((peer, size))
            } else {
                self.out.send(Message::HadshakeDone{peer}).await?;
            }
        }
        Ok(())
    }

    async fn process_command(&mut self, msg: String) -> Result<()> {
        if self.enc.is_connected() {
            let msg = msg.as_bytes();
            let size = msg.len();
            self.buf[..size].copy_from_slice(msg);
            self.to_send = OutputMessage::Encrypted((self.peer.ok_or("Peer is not known")?, size));
        } else {
            eprintln!("Encrypted channel is not connected");
        }
        Ok(())
    }

    pub async fn run(mut self) -> Result<()> {
        let mut sigint = signal(SignalKind::interrupt())?;
        let mut sigterm = signal(SignalKind::terminate())?;

        if let Some(peer) = self.peer {
            let len = self.enc.start_handshake(&mut self.buf)?;
            self.to_send = OutputMessage::Plain((peer, len));
            eprintln!("Encrypted channel initiated")
        }

        loop {
            // First we check to see if there's a message we need to echo back.
            // If so then we try to send it back to the original source, waiting
            // until it's writable and we're able to do so.
            match replace(&mut self.to_send, OutputMessage::None) {
                OutputMessage::Encrypted((peer, l)) => {
                    let len = self.enc.encrypt(&self.buf[..l], &mut self.buf2)?;
                    self.socket.send_to(&self.buf2[..len], peer).await?;
                    self.out.send(Message::Sent{peer}).await?;
                }
                OutputMessage::Plain((peer, l)) => {
                    if self.enc.is_connected() {
                        self.out.send(Message::HadshakeDone{peer}).await?;
                    };
                    self.socket.send_to(&self.buf[..l], peer).await?;
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
