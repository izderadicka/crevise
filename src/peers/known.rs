use super::PeerId;
use crate::{
    error::{bail, ensure, new_error},
    Result,
};
use std::net::SocketAddr;
use std::{collections::HashMap, fs::File, io::Read, path::Path, sync::Arc};
use tokio::sync::RwLock;

pub fn load_peers_from_json<P: AsRef<Path>>(path: P) -> Result<SharedKnownPeers> {
    SharedKnownPeers::from_json(path)
}

#[derive(Clone, Debug)]
pub struct SharedKnownPeers {
    inner: Arc<RwLock<KnownPeers>>,
}

impl SharedKnownPeers {
    /// blocking
    pub fn from_json<P: AsRef<Path>>(path: P) -> Result<Self> {
        Ok(SharedKnownPeers {
            inner: Arc::new(RwLock::new(KnownPeers::from_json(path)?)),
        })
    }

    pub fn from_json_reader<I: Read>(inp: &mut I) -> Result<Self> {
        Ok(SharedKnownPeers {
            inner: Arc::new(RwLock::new(KnownPeers::from_json_reader(inp)?)),
        })
    }

    pub async fn get_by_nick(&self, nick: &str) -> Option<(PeerId, Option<SocketAddr>)> {
        self.inner
            .read()
            .await
            .get_by_nick(nick)
            .map(|x| (x.0.clone(), x.1.cloned()))
    }

    pub async fn get_by_addr(&self, addr: &SocketAddr) -> Option<(PeerId, String)> {
        self.inner
            .read()
            .await
            .get_by_addr(addr)
            .map(|x| (x.0.clone(), x.1.to_string()))
    }

    pub async fn get_by_peer_id(&self, peer: &PeerId) -> Option<(Option<SocketAddr>, String)> {
        self.inner
            .read()
            .await
            .get_by_peer_id(peer)
            .map(|x| (x.0.cloned(), x.1.to_string()))
    }

    pub async fn update_addr(&self, nick: &str, addr: SocketAddr) {
        self.inner.write().await.update_addr(nick, addr)
    }

    pub async fn len(&self) -> usize {
        self.inner.read().await.len()
    }
}

#[derive(Debug)]
struct KnownPeers {
    peers: HashMap<String, (PeerId, Option<SocketAddr>)>,
    index_peers: HashMap<PeerId, String>,
    index_addr: HashMap<SocketAddr, String>,
}

impl KnownPeers {
    fn from_json_reader<I: Read>(inp: &mut I) -> Result<Self> {
        use serde_json::Value;
        let json: Value = serde_json::from_reader(inp)?;
        let mut peers = KnownPeers {
            peers: HashMap::new(),
            index_peers: HashMap::new(),
            index_addr: HashMap::new(),
        };

        if let Value::Object(map) = json {
            for (nick, o) in map {
                let peer_id = o
                    .get("peer_id")
                    .ok_or_else(|| new_error!("peer_id is mandatory"))?;
                let peer_id: PeerId = if let Value::String(s) = peer_id {
                    s.parse()?
                } else {
                    bail!("peer_id must be string")
                };

                let addr = o.get("addr");
                let addr: Option<SocketAddr> = match addr {
                    Some(Value::String(a)) => Some(a.parse()?),
                    Some(_) => bail!("socket address must be string"),
                    None => None,
                };
                let prev = peers.peers.insert(nick.clone(), (peer_id, addr));
                ensure!(prev.is_none(), "nick is not unique");
                let prev = peers.index_peers.insert(peer_id, nick.clone());
                ensure!(prev.is_none(), "peer_id is not unique");
                if let Some(a) = addr {
                    let prev = peers.index_addr.insert(a, nick);
                    ensure!(prev.is_none(), "addr is not unique")
                }
            }
        } else {
            bail!("Expected JSON Object")
        }

        Ok(peers)
    }

    fn from_json<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut f = File::open(path)?;
        KnownPeers::from_json_reader(&mut f)
    }

    fn get_by_nick<'a>(&'a self, nick: &str) -> Option<(&'a PeerId, Option<&'a SocketAddr>)> {
        self.peers.get(nick).map(|t| (&t.0, t.1.as_ref()))
    }

    fn get_by_addr<'a>(&'a self, addr: &SocketAddr) -> Option<(&'a PeerId, &'a str)> {
        self.index_addr
            .get(addr)
            .and_then(|nick| self.peers.get(nick).map(|r| (&r.0, nick.as_str())))
    }

    fn get_by_peer_id<'a>(&'a self, peer: &PeerId) -> Option<(Option<&'a SocketAddr>, &'a str)> {
        self.index_peers
            .get(peer)
            .and_then(|nick| self.peers.get(nick).map(|r| (r.1.as_ref(), nick.as_str())))
    }

    fn update_addr(&mut self, nick: &str, addr: SocketAddr) {
        let idx = &mut self.index_addr; // splitting borrow
        self.peers
            .get_mut(nick)
            .and_then(|item| {
                let prev = item.1.take();
                item.1 = Some(addr);
                idx.insert(addr, nick.into());
                prev
            })
            .and_then(|prev| idx.remove(&prev));
    }

    fn len(&self) -> usize {
        self.peers.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_json_load() -> Result<()> {
        let json = r#"{"ivan": {"peer_id": "M5UWYJIGHIEYAZS3GLKTJFILA26J2FVD", "addr": "127.0.0.1:8080"},
            "test": {"peer_id": "IEIWYXBRARV5HHXQXC2DN2W3DN7IUBON","addr": "127.0.0.1:8081"},
            "kulisak": {"peer_id": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
        }"#;
        let mut inp = Cursor::new(json);
        let peers = KnownPeers::from_json_reader(&mut inp)?;

        assert_eq!(3, peers.len());
        let p1: PeerId = "M5UWYJIGHIEYAZS3GLKTJFILA26J2FVD".parse()?;
        let p2: PeerId = "IEIWYXBRARV5HHXQXC2DN2W3DN7IUBON".parse()?;
        let a1: SocketAddr = "127.0.0.1:8080".parse()?;
        let a2: SocketAddr = "127.0.0.1:8081".parse()?;
        assert_eq!(
            (&p1, Some(&a1)),
            peers.get_by_nick("ivan").expect("ivan nick to be found")
        );
        assert_eq!(
            (Some(&a2), "test"),
            peers
                .get_by_peer_id(&p2)
                .expect("test peer id is valid key")
        );
        assert_eq!(
            (&p2, "test"),
            peers.get_by_addr(&a2).expect("test addr is valid key")
        );

        assert!(
            peers.get_by_addr(&("127.0.0.1:6789".parse()?)).is_none(),
            "none of nonexisting addr"
        );
        assert!(peers
            .get_by_nick("kulisak")
            .expect("kulisak exists")
            .1
            .is_none());

        Ok(())
    }
}
