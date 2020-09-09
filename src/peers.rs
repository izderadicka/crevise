use crate::encrypted::{EncryptedChannel, Keypair};
use crate::Result;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync;

const CAPACITY: usize = 1000;

#[derive(Clone)]
pub struct PeersMap {
    inner: Arc<PeersMapInner>,
}

impl PeersMap {
    pub fn new(my_key: Keypair) -> Self {
        PeersMap {
            inner: Arc::new(PeersMapInner::new(my_key)),
        }
    }

    pub async fn start_handshake(
        &self,
        peer: SocketAddr,
        first_message: &mut [u8],
    ) -> Result<usize> {
        self.inner.start_handshake(peer, first_message).await
    }

    pub async fn continue_handshake(
        &self,
        peer: SocketAddr,
        in_message: &[u8],
        next_message: &mut [u8],
    ) -> Result<usize> {
        self.inner
            .continue_handshake(peer, in_message, next_message)
            .await
    }

    pub async fn encrypt(
        &mut self,
        peer: &SocketAddr,
        data: &[u8],
        encrypted: &mut [u8],
    ) -> Result<usize> {
        self.inner.encrypt(peer, data, encrypted).await
    }

    pub async fn decrypt(
        &mut self,
        peer: &SocketAddr,
        encrypted: &[u8],
        data: &mut [u8],
    ) -> Result<usize> {
        self.inner.decrypt(peer, encrypted, data).await
    }

    pub async fn is_connected(&self, peer: &SocketAddr) -> bool {
        self.inner.is_connected(peer).await
    }
}

struct PeersMapInner {
    map: sync::RwLock<HashMap<SocketAddr, sync::Mutex<EncryptedChannel>>>,
    key: Keypair,
}

impl PeersMapInner {
    fn new(my_key: Keypair) -> Self {
        PeersMapInner {
            map: sync::RwLock::new(HashMap::with_capacity(CAPACITY)),
            key: my_key,
        }
    }

    fn key(&self) -> Keypair {
        Keypair {
            private: self.key.private.clone(),
            public: self.key.public.clone(),
        }
    }

    async fn start_handshake(&self, peer: SocketAddr, first_message: &mut [u8]) -> Result<usize> {
        let mut ch = EncryptedChannel::new(self.key());
        let sz = ch.start_handshake(first_message)?;
        self.map.write().await.insert(peer, sync::Mutex::new(ch));
        Ok(sz)
    }

    async fn continue_handshake(
        &self,
        peer: SocketAddr,
        in_message: &[u8],
        next_message: &mut [u8],
    ) -> Result<usize> {
        eprintln!("Processing handshake from peer {}", peer);
        // TODO: is there better way to handle this - I was thinking about upgrading read lock to write lock, but it does not seem to be possible
        let mut ch = match self.map.read().await.get(&peer) {
            Some(ch) => return ch.lock().await.continue_handshake(in_message, next_message),
            None => EncryptedChannel::new(self.key()),
        };

        let sz = ch.continue_handshake(in_message, next_message)?;
        eprintln!("Was first message from {}", peer);
        let mut m = self.map.write().await;
        match m.insert(peer, sync::Mutex::new(ch)) {
            Some(prev) => {
                eprintln!("There was previous handshake!!!");
                m.insert(peer, prev);
                Err("There was previous handshake!!!".into())
            }
            None => {
                eprintln!("Encrypted channel stored");
                Ok(sz)
            }
        }
    }

    async fn remove_if_not_connected(&self, peer: &SocketAddr) {
        let mut map = self.map.write().await;
        if let Some(ch) = map.get(peer) {
            if !ch.lock().await.is_connected() {
                map.remove(peer);
            }
        }
    }

    async fn is_connected(&self, peer: &SocketAddr) -> bool {
        if let Some(ch) = self.map.read().await.get(peer) {
            ch.lock().await.is_connected()
        } else {
            false
        }
    }

    async fn remove(&self, peer: &SocketAddr) {
        self.map.write().await.remove(peer);
    }

    async fn encrypt(&self, peer: &SocketAddr, data: &[u8], encrypted: &mut [u8]) -> Result<usize> {
        self.map
            .read()
            .await
            .get(peer)
            .ok_or_else(|| "Peer not connected")?
            .lock()
            .await
            .encrypt(data, encrypted)
    }

    async fn decrypt(&self, peer: &SocketAddr, encrypted: &[u8], data: &mut [u8]) -> Result<usize> {
        self.map
            .read()
            .await
            .get(peer)
            .ok_or_else(|| "Peer not connected")?
            .lock()
            .await
            .decrypt(encrypted, data)
    }
}
