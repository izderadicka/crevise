use std::{net::SocketAddr, fmt::Display};

use crate::PeerId;

pub struct PeerInfo {
    pub nick: Option<String>,
    pub peer_addr: SocketAddr,
    pub peer_id: Option<PeerId>,
}

impl Display for PeerInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PeerInfo{ nick: Some(nick), ..} => write!(f, "@{}", nick),
            PeerInfo{ peer_addr, peer_id: Some(id), ..} => write!(f,"<{}::{}>", id, peer_addr),
            PeerInfo {peer_addr, ..} => write!(f, "<{}>", peer_addr),
        }
    }
}

pub enum Message {
    Post { peer: PeerInfo, content: String },
    Sent { peer: PeerInfo },
    HadshakeDone { peer: PeerInfo },
    HandshakeCleared { peer: PeerInfo },
    HandshakeError { peer: PeerInfo },
    NewLine, // TODO: This is temporary workaround
}
