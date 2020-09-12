use crate::Result;
use crate::{
    encrypted::{EncryptedChannel, Keypair},
    Error,
};
use futures::{future, FutureExt};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::{spawn, sync, time::timeout};

const CAPACITY: usize = 1000; //initial capacity of map
const TIMEOUT: Duration = Duration::from_secs(10); // handshake timeout

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
        self.timeout_task(peer);
        self.inner.start_handshake(peer, first_message).await
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

    pub async fn remove(&self, peer: &SocketAddr) -> bool {
        self.inner.remove(peer).await
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
    ) -> Result<(usize, bool)> {
        //eprintln!("Processing handshake from peer {}", peer);
        let mut ch = match self.map.read().await.get(&peer) {
            Some(ch) => {
                return ch
                    .lock()
                    .await
                    .continue_handshake(in_message, next_message)
                    .map(|sz| (sz, false))
            }
            None => EncryptedChannel::new(self.key()),
        };
        // This is for first message in handshake
        let sz = ch.continue_handshake(in_message, next_message)?;
        //eprintln!("Was first message from {}", peer);
        let mut m = self.map.write().await;
        match m.insert(peer, sync::Mutex::new(ch)) {
            Some(prev) => {
                //eprintln!("There was previous handshake!!!");
                m.insert(peer, prev);
                Err(Error::msg("There was previous handshake!!!"))
            }
            None => {
                eprintln!("Encrypted channel stored");
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

    async fn remove(&self, peer: &SocketAddr) -> bool {
        self.map.write().await.remove(peer).is_some()
    }

    async fn encrypt(&self, peer: &SocketAddr, data: &[u8], encrypted: &mut [u8]) -> Result<usize> {
        self.map
            .read()
            .await
            .get(peer)
            .ok_or_else(|| Error::msg("Peer not connected"))?
            .lock()
            .await
            .encrypt(data, encrypted)
    }

    async fn decrypt(&self, peer: &SocketAddr, encrypted: &[u8], data: &mut [u8]) -> Result<usize> {
        self.map
            .read()
            .await
            .get(peer)
            .ok_or_else(|| Error::msg("Peer not connected"))?
            .lock()
            .await
            .decrypt(encrypted, data)
    }
}
