use crate::peers::PeerInfo;

#[derive(Debug)]
pub enum Message {
    Post { peer: PeerInfo, content: String },
    Sent { peer: PeerInfo },
    HadshakeDone { peer: PeerInfo },
    HandshakeCleared { peer: PeerInfo },
    HandshakeError { peer: PeerInfo },
    NewLine, // TODO: This is temporary workaround
}
