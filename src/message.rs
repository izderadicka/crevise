use std::net::SocketAddr;

pub enum Message {
    Post { peer: SocketAddr, content: String },
    Sent { peer: SocketAddr },
    HadshakeDone { peer: SocketAddr },
    Cleared { peer: SocketAddr },
    NewLine, // TODO: This is temporary workaround
}
