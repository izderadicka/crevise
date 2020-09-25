use crate::Result;
use crate::{
    encrypted::{EncryptedChannel, Keypair},
    Error,
};
use futures::{future, FutureExt};
use std::{collections::HashMap, fmt::Display, str::FromStr};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::{spawn, sync, time::timeout};
use blake2::VarBlake2s;
use blake2::digest::{Update, VariableOutput};
use crate::error::{new_error,ensure};
use known::SharedKnownPeers;

pub mod known;


const CAPACITY: usize = 1000; //initial capacity of map
const TIMEOUT: Duration = Duration::from_secs(10); // handshake timeout

const PEER_ID_SIZE:usize = 20;
#[derive(Debug, PartialEq,Eq, Clone, Copy, Hash)]
pub struct PeerId {
    id: [u8;PEER_ID_SIZE]
}

impl PeerId {

    fn empty() -> Self {
        PeerId{
            id: [0;PEER_ID_SIZE]
        }
    }

    pub fn from_public_key(public_key: &[u8]) -> Self {
        let mut hasher = VarBlake2s::new(PEER_ID_SIZE).expect("BUG: invalid hash size");
        hasher.update(public_key);
        let mut id = PeerId::empty();
        hasher.finalize_variable(|res|  {id.id.copy_from_slice(res); });
        id

    }
    
}

impl From<&Keypair> for PeerId {
    fn from(key: &Keypair) -> Self {
        PeerId::from_public_key(&key.public)
    }
}

impl Display for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let encoded = data_encoding::BASE32_NOPAD.encode(&self.id);
        f.write_str(&encoded)
    }
}

impl FromStr for PeerId {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        ensure!(s.len() == PEER_ID_SIZE * 8 / 5 ,"Invalid size of Peer ID {}", s.len());
        let mut peer_id = PeerId::empty();
        let size = data_encoding::BASE32_NOPAD.decode_mut(s.as_bytes(), &mut peer_id.id).map_err(|e| new_error!("Error decoding Peer ID: {:?}",e))?;
        ensure!(size == PEER_ID_SIZE, "Invalid size of Peer ID after decoding {}", size);
        Ok(peer_id)
    }
}

#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub nick: String,
    pub peer_addr: Option<SocketAddr>,
    pub peer_id: PeerId,
}

impl Display for PeerInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "@{}", self.nick)
    }
}

#[derive(Clone)]
pub struct PeersMap {
    inner: Arc<PeersMapInner>,
}

impl PeersMap {
    pub fn new(my_key: Keypair, known_peers: SharedKnownPeers) -> Self {
        PeersMap {
            inner: Arc::new(PeersMapInner::new(my_key, known_peers)),
        }
    }

    pub async fn start_handshake(
        &self,
        peer: SocketAddr,
        first_message: &mut [u8],
        expected_peer: PeerId
    ) -> Result<usize> {
        self.timeout_task(peer);
        self.inner.start_handshake(peer, first_message, expected_peer).await
    }

    fn timeout_task(&self, peer: SocketAddr) {
        let inner = self.inner.clone();
        let f = timeout(TIMEOUT, future::pending::<()>()).then(move |_| async move {
            if inner.remove_if_not_connected(&peer).await {
                eprintln!("Handshake timeout");
            }
        });
        spawn(f);
    }

    pub async fn continue_handshake(
        &self,
        peer: SocketAddr,
        in_message: &[u8],
        next_message: &mut [u8],
    ) -> Result<usize> {
        let (sz, start) = self
            .inner
            .continue_handshake(peer, in_message, next_message)
            .await?;
        if start {
            self.timeout_task(peer);
        }
        Ok(sz)
    }

    pub async fn encrypt(
        &self,
        peer: &SocketAddr,
        data: &[u8],
        encrypted: &mut [u8],
    ) -> Result<usize> {
        self.inner.encrypt(peer, data, encrypted).await
    }

    pub async fn decrypt(
        &self,
        peer: &SocketAddr,
        encrypted: &[u8],
        data: &mut [u8],
    ) -> Result<usize> {
        self.inner.decrypt(peer, encrypted, data).await
    }

    pub async fn is_connected(&self, peer: &SocketAddr) -> bool {
        self.inner.is_connected(peer).await
    }

    pub async fn peer_connected(&self, peer: &SocketAddr) -> Option<PeerInfo> {
        self.inner.peer_connected(peer).await
    }

    pub async fn remove(&self, peer: &SocketAddr) -> bool {
        self.inner.remove(peer).await
    }
}

struct PeersMapInner {
    map: sync::RwLock<HashMap<SocketAddr, sync::Mutex<EncryptedChannel>>>,
    key: Keypair,
    known_peers: SharedKnownPeers
}

impl PeersMapInner {
    fn new(my_key: Keypair, known_peers: SharedKnownPeers) -> Self {
        PeersMapInner {
            map: sync::RwLock::new(HashMap::with_capacity(CAPACITY)),
            key: my_key,
            known_peers
        }
    }

    fn key(&self) -> Keypair {
        Keypair {
            private: self.key.private.clone(),
            public: self.key.public.clone(),
        }
    }

    async fn start_handshake(&self, peer: SocketAddr, first_message: &mut [u8], expected_peer: PeerId) -> Result<usize> {
        let mut ch = EncryptedChannel::new(self.key(), self.known_peers.clone());
        let sz = ch.start_handshake(first_message, expected_peer).await?;
        self.map.write().await.insert(peer, sync::Mutex::new(ch));
        Ok(sz)
    }

    async fn continue_handshake(
        &self,
        peer: SocketAddr,
        in_message: &[u8],
        next_message: &mut [u8],
    ) -> Result<(usize, bool)> {
        //eprintln!("Processing handshake from peer {}", peer);
        let mut ch = match self.map.read().await.get(&peer) {
            Some(ch) => {
                return ch
                    .lock()
                    .await
                    .continue_handshake(in_message, next_message)
                    .await
                    .map(|sz| (sz, false))
            }
            None => EncryptedChannel::new(self.key(), self.known_peers.clone()),
        };
        // This is for first message in handshake
        let sz = ch.continue_handshake(in_message, next_message).await?;
        //eprintln!("Was first message from {}", peer);
        let mut m = self.map.write().await;
        match m.insert(peer, sync::Mutex::new(ch)) {
            Some(prev) => {
                //eprintln!("There was previous handshake!!!");
                m.insert(peer, prev);
                Err(new_error!("There was previous handshake!!!"))
            }
            None => {
                //eprintln!("Encrypted channel stored");
                Ok((sz, true))
            }
        }
    }

    /// returns false if connected, true otherwise - so if it does not exist or is not connected
    async fn remove_if_not_connected(&self, peer: &SocketAddr) -> bool {
        let mut map = self.map.write().await;
        if let Some(ch) = map.get(peer) {
            if !ch.lock().await.is_connected() {
                map.remove(peer);
            } else {
                return false;
            }
        }
        true
    }

    async fn is_connected(&self, peer: &SocketAddr) -> bool {
        if let Some(ch) = self.map.read().await.get(peer) {
            ch.lock().await.is_connected()
        } else {
            false
        }
    }

    async fn peer_connected(&self, peer: &SocketAddr) -> Option<PeerInfo> {
        if let Some(ch) = self.map.read().await.get(peer) {
            ch.lock().await.peer_connected().cloned()
        } else {
            None
        }
    }

    async fn remove(&self, peer: &SocketAddr) -> bool {
        self.map.write().await.remove(peer).is_some()
    }

    async fn encrypt(&self, peer: &SocketAddr, data: &[u8], encrypted: &mut [u8]) -> Result<usize> {
        self.map
            .read()
            .await
            .get(peer)
            .ok_or_else(|| new_error!("Peer not connected"))?
            .lock()
            .await
            .encrypt(data, encrypted)
    }

    async fn decrypt(&self, peer: &SocketAddr, encrypted: &[u8], data: &mut [u8]) -> Result<usize> {
        self.map
            .read()
            .await
            .get(peer)
            .ok_or_else(|| new_error!("Peer not connected"))?
            .lock()
            .await
            .decrypt(encrypted, data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generate_key;

    #[test]
    fn test_peer_id() -> Result<()> {
        let dummy_public = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24];
        let peer_id = PeerId::from_public_key(&dummy_public);
        let human_readable = peer_id.to_string();
        assert_eq!(32, human_readable.len());
        let peer_id2: PeerId = human_readable.parse()?;
        assert_eq!(peer_id, peer_id2);

        let key = generate_key();
        let peer_id: PeerId = (&key).into();
        let human_readable = peer_id.to_string();
        assert_eq!(32, human_readable.len());
        let peer_id2: PeerId = human_readable.parse()?;
        assert_eq!(peer_id, peer_id2);


        Ok(())
    }
}
