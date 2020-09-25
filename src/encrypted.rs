use std::{fs::File, fs::OpenOptions, io::Read, io::Write, path::Path};

use crate::{PeerId, Result, SharedKnownPeers, error::{ensure, new_error}, peers::PeerInfo};
use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::RngCore;
pub use snow::Keypair;
use snow::{params::NoiseParams, Builder, HandshakeState, TransportState};
use std::io::Cursor;

// trait MessageStream {
//     fn send();
//     fn receive();
// }

#[derive(Debug, Clone, Copy, PartialEq)]
enum Side {
    Initiator,
    Respondent,
}
#[derive(Debug)]
enum PeerState {
    Unconnected,
    Connecting {
        step: u8,
        handshake: Option<HandshakeState>,
        side: Side,
    },
    Connected {
        encryptor: TransportState,
        peer: PeerInfo
    },
}

pub struct EncryptedChannel {
    state: PeerState,
    key: Keypair,
    params: NoiseParams,
    buf: Vec<u8>,
    known_peers: SharedKnownPeers,
    expected_peer: Option<PeerId>
}

impl EncryptedChannel {
    #[allow(dead_code)]
    pub fn reset(&mut self) {
        self.state = PeerState::Unconnected;
    }

    pub async fn start_handshake(&mut self, first_message: &mut [u8], expected_peer: PeerId) -> Result<usize> {
        if let PeerState::Unconnected = self.state {
            let mut noise = Builder::new(self.params.clone())
                .local_private_key(&self.key.private)
                .build_initiator()?;

            // -> e
            let len = noise.write_message(&[], first_message)?;
            self.state = PeerState::Connecting {
                step: 1,
                side: Side::Initiator,
                handshake: Some(noise),
            };
            self.expected_peer = Some(expected_peer);
            Ok(len)
        } else {
            Err(new_error!("Invalid channel state, cannot start handshake"))
        }
    }

    pub async fn continue_handshake(
        &mut self,
        in_message: &[u8],
        next_message: &mut [u8],
    ) -> Result<usize> {
        match self.state {
            PeerState::Connecting {
                ref mut step,
                side,
                ref mut handshake,
            } => {
                let mut handshake = handshake
                    .take()
                    .expect("BUG: invalid state of handshake, HandshakeState is missing!");
                match (step, side) {
                    (1, Side::Initiator) => {
                        // <- e, ee, s, es
                        handshake.read_message(&in_message, &mut self.buf)?;

                        let peer = self.check_peer(&handshake).await?;

                        // -> s, se
                        let len = handshake.write_message(&[], next_message)?;
                        self.state = PeerState::Connected {
                            encryptor: handshake.into_transport_mode()?,
                            peer
                        };

                        Ok(len)
                    }

                    (1, Side::Respondent) => {
                        // <- s, se
                        let _l = handshake.read_message(&in_message, &mut self.buf)?;
                        let peer = self.check_peer(&handshake).await?;
                        self.state = PeerState::Connected {
                            encryptor: handshake.into_transport_mode()?,
                            peer
                        };
                        Ok(0)
                    }

                    _ => panic!("BUG: Invalid state of EncryptedMessage"),
                }
            }
            PeerState::Unconnected => {
                // if unconnected we are on responder side

                let mut noise = Builder::new(self.params.clone())
                    .local_private_key(&self.key.private)
                    .build_responder()?;

                // <- e
                let _l = noise.read_message(in_message, &mut self.buf)?;

                // -> e, ee, s, es
                let len = noise.write_message(&[], next_message).unwrap();

                self.state = PeerState::Connecting {
                    side: Side::Respondent,
                    step: 1,
                    handshake: Some(noise),
                };

                Ok(len)
            }
            PeerState::Connected { .. } => Err(new_error!(
                "Invalid channel state, cannot continue handshake",
            )),
        }
    }

    async fn check_peer(&self, handshake: &HandshakeState) -> Result<PeerInfo> {
        
            let pubkey = handshake
                .get_remote_static()
                .ok_or_else(|| new_error!("remote public key must be know"))?;
            let peer_id = PeerId::from_public_key(pubkey);
            if let Some(ep) = self.expected_peer {
                ensure!(ep == peer_id, "peer {} does not match expected peer {}", peer_id, ep);
            }
            self.known_peers
                .get_by_peer_id(&peer_id)
                .await
                .ok_or_else(|| new_error!("peer {} is not known", peer_id))
                .map(|(addr, nick)| PeerInfo{peer_id: peer_id, nick, peer_addr: addr})
        
    }

    pub fn encrypt(&mut self, data: &[u8], encrypted: &mut [u8]) -> Result<usize> {
        if let PeerState::Connected { ref mut encryptor , ..} = self.state {
            let len = encryptor.write_message(data, encrypted)?;
            Ok(len)
        } else {
            Err(new_error!("Invalid channel state, cannot encrypt"))
        }
    }

    pub fn decrypt(&mut self, encrypted: &[u8], data: &mut [u8]) -> Result<usize> {
        if let PeerState::Connected { ref mut encryptor, .. } = self.state {
            let len = encryptor.read_message(encrypted, data)?;
            Ok(len)
        } else {
            Err(new_error!("invalid channel state, cannot decrypt"))
        }
    }

    pub fn is_connected(&self) -> bool {
        if let PeerState::Connected { .. } = self.state {
            true
        } else {
            false
        }
    }

    pub fn peer_connected(&self) -> Option<&PeerInfo> {
        if let PeerState::Connected{ref peer, ..} = self.state {
            Some(peer)
        } else {
            None
        }
    }
}

impl EncryptedChannel {
    const NOISE_PARAMS: &'static str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
    const MAX_HANDSHAKE_MSG_SIZE: usize = 1024;
    //const MAX_MSG_SIZE: usize = 65_000;
    pub fn new(key: Keypair, known_peers: SharedKnownPeers) -> Self {
        EncryptedChannel {
            state: PeerState::Unconnected,
            key,
            params: EncryptedChannel::NOISE_PARAMS
                .parse()
                .expect("Invalid params"),

            buf: vec![0; EncryptedChannel::MAX_HANDSHAKE_MSG_SIZE],
            known_peers,
            expected_peer: None
        }
    }
}

pub fn generate_key() -> Keypair {
    Builder::new(
        EncryptedChannel::NOISE_PARAMS
            .parse()
            .expect("Invalid params"),
    )
    .generate_keypair()
    .expect("cannot generate keypair")
}

struct EncryptedKey {
    salt: Vec<u8>,
    nonce: Vec<u8>,
    enc_key: Vec<u8>,
}

impl<O: Write> SimpleSerialize<O> for EncryptedKey {
    fn write_to(&self, out: &mut O) -> Result<()> {
        write_vec(&self.salt, out)?;
        write_vec(&self.nonce, out)?;
        write_vec(&self.enc_key, out)
    }
}

impl<I: Read> SimpleDeserialize<I> for EncryptedKey {
    fn read_from(inp: &mut I) -> Result<Self> {
        Ok(EncryptedKey {
            salt: read_vec(inp)?,
            nonce: read_vec(inp)?,
            enc_key: read_vec(inp)?,
        })
    }
}

trait SimpleSerialize<O> {
    fn write_to(&self, out: &mut O) -> Result<()>;
}
trait SimpleDeserialize<I>: Sized {
    fn read_from(inp: &mut I) -> Result<Self>;
}

fn write_vec<O: Write>(vec: &Vec<u8>, out: &mut O) -> Result<()> {
    let l1 = vec.len();
    ensure!(l1 < 256, "Invalid vec length {}", l1);
    out.write_all(&[l1 as u8])?;
    out.write_all(vec)?;
    Ok(())
}

fn read_vec<I: Read>(inp: &mut I) -> Result<Vec<u8>> {
    let mut len_buf = [0; 1];
    inp.read_exact(&mut len_buf)?;
    let len = len_buf[0] as usize;
    let mut vec = vec![0; len];
    inp.read_exact(&mut vec[..len])?;
    Ok(vec)
}

impl<O: Write> SimpleSerialize<O> for Keypair {
    fn write_to(&self, out: &mut O) -> Result<()> {
        write_vec(&self.private, out)?;
        write_vec(&self.public, out)
    }
}

impl<I: Read> SimpleDeserialize<I> for Keypair {
    fn read_from(inp: &mut I) -> Result<Self> {
        Ok(Keypair {
            private: read_vec(inp)?,
            public: read_vec(inp)?,
        })
    }
}

fn rand_bytes(len: usize) -> Vec<u8> {
    let mut salt = vec![0; len];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

pub fn save_key<P: AsRef<Path>>(key: &Keypair, file: P, password: &str) -> Result<()> {
    let path: &Path = file.as_ref();
    let mut f = OpenOptions::new().create_new(true).write(true).open(path)?;
    let enc_key = encrypt_key(key, password)?;
    enc_key.write_to(&mut f)?;

    Ok(())
}

fn encrypt_key(keypair: &Keypair, password: &str) -> Result<EncryptedKey> {
    let salt = rand_bytes(32);
    let key = argon2::hash_raw(password.as_bytes(), &salt, &argon2::Config::default())?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));

    let nonce = rand_bytes(12);

    let mut plain_key = Vec::with_capacity(keypair.public.len() + keypair.public.len() + 2);
    keypair.write_to(&mut plain_key)?;
    let enc_key = cipher.encrypt(Nonce::from_slice(&nonce), &plain_key[..])?;

    Ok(EncryptedKey {
        salt,
        nonce,
        enc_key,
    })
}

fn decrypt_key(enc_key: EncryptedKey, password: &str) -> Result<Keypair> {
    let key = argon2::hash_raw(
        password.as_bytes(),
        &enc_key.salt,
        &argon2::Config::default(),
    )?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let decrypted_key = cipher.decrypt(Nonce::from_slice(&enc_key.nonce), &enc_key.enc_key[..])?;
    let mut io = Cursor::new(decrypted_key);
    Keypair::read_from(&mut io)
}

pub fn load_key<P: AsRef<Path>>(file: P, password: &str) -> Result<Keypair> {
    let mut f = File::open(file)?;
    let enc_key = EncryptedKey::read_from(&mut f)?;
    decrypt_key(enc_key, password)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::{
        io::{Cursor, Seek, SeekFrom},
    };

    #[test]
    fn test_key_creation() -> Result<()> {
        let key = generate_key();
        let known_peers = crate::peers::known::SharedKnownPeers::from_json_reader(
            &mut Cursor::new("{}"),
        )?;
        let _ec = EncryptedChannel::new(key, known_peers);
        Ok(())
    }

    #[test]
    fn test_serialization() -> Result<()> {
        let key = generate_key();
        let mut io = Cursor::new(vec![0; 256]);
        key.write_to(&mut io)?;
        io.seek(SeekFrom::Start(0))?;
        let key2 = Keypair::read_from(&mut io)?;
        assert_eq!(key.private, key2.private, "private");
        assert_eq!(key.public, key2.public, "public");

        Ok(())
    }

    #[test]

    fn test_key_encryption() -> Result<()> {
        let key = generate_key();
        let pass = "SedmLumpuSlohloPumpu";

        let enc_key = encrypt_key(&key, pass)?;
        let mut io = Cursor::new(Vec::new());
        enc_key.write_to(&mut io)?;
        io.seek(SeekFrom::Start(0))?;
        let enc_key = EncryptedKey::read_from(&mut io)?;
        let key2 = decrypt_key(enc_key, pass)?;
        assert_eq!(key.private, key2.private, "private");
        assert_eq!(key.public, key2.public, "public");
        Ok(())
    }
}
