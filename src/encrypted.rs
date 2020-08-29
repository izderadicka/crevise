use super::Result;
pub use snow::Keypair;
use snow::{params::NoiseParams, Builder, HandshakeState, TransportState};

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
    },
}

pub struct EncryptedChannel {
    state: PeerState,
    key: Keypair,
    params: NoiseParams,
    buf: Vec<u8>,
}

impl EncryptedChannel {
    #[allow(dead_code)]
    pub fn reset(&mut self) {
        self.state = PeerState::Unconnected;
    }

    pub fn start_handshake(&mut self, first_message: &mut [u8]) -> Result<usize> {
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
            Ok(len)
        } else {
            Err("Invalid channel state, cannot start handshake".into())
        }
    }

    pub fn continue_handshake(
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

                        // -> s, se
                        let len = handshake.write_message(&[], next_message)?;
                        self.state = PeerState::Connected {
                            encryptor: handshake.into_transport_mode()?,
                        };

                        Ok(len)
                    }

                    (1, Side::Respondent) => {
                        // <- s, se
                        let _l = handshake.read_message(&in_message, &mut self.buf)?;
                        self.state = PeerState::Connected { encryptor: handshake.into_transport_mode()? };
                        Ok(0)
                    }

                    _ => panic!("BUG: Invalid state of EncryptedMessage")
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
            PeerState::Connected { .. } => {
                Err("Invalid channel state, cannot continue handshake".into())
            }
        }
    }

    
    pub  fn encrypt(&mut self,  data: &[u8], encrypted: &mut [u8]) -> Result<usize> {
        if let PeerState::Connected { ref mut encryptor } = self.state {
            let len = encryptor.write_message(data, encrypted)?;
            Ok(len)
        } else {
            Err("Invalid channel state, cannot encrypt".into())
        }
    }

    pub  fn decrypt(&mut self, encrypted: &[u8], data : &mut [u8]) -> Result<usize> {
        if let PeerState::Connected { ref mut encryptor } = self.state {
            let len =  encryptor.read_message(encrypted, data)?;
            Ok(len)
        } else {
            Err("invalid channel state, cannot decrypt".into())
        }
    }

    pub fn is_connected(&self) -> bool {
        if let PeerState::Connected { .. } = self.state {
            true
        } else {
            false
        }
    }
}

pub fn generate_keypair() -> Keypair {
    Builder::new(
        EncryptedChannel::NOISE_PARAMS
            .parse()
            .expect("Invalid params"),
    )
    .generate_keypair()
    .expect("cannot generate keypair")
}

impl EncryptedChannel {
    const NOISE_PARAMS: &'static str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
    const MAX_HANDSHAKE_MSG_SIZE: usize = 1024;
    //const MAX_MSG_SIZE: usize = 65_000;
    pub fn new(key: Keypair) -> Self {
        EncryptedChannel {
            state: PeerState::Unconnected,
            key,
            params: EncryptedChannel::NOISE_PARAMS
                .parse()
                .expect("Invalid params"),

            buf: vec![0; EncryptedChannel::MAX_HANDSHAKE_MSG_SIZE],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_creation() {
        let key = generate_keypair();
        let _ec = EncryptedChannel::new(key);
    }
}
