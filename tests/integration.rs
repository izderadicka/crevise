use crevise::error::Result;
use crevise::{generate_key, Command, Keypair, MainLoop, Message, PeerId, SharedKnownPeers};
use futures::channel::mpsc;
use futures::{future, prelude::*};
use serde_json as json;
use std::io::Cursor;
use std::net::SocketAddr;

fn insert_peer(m: &mut json::Map<String, json::Value>, nick: &str, key: &Keypair, port: u16) {
    let mut v = json::Map::new();
    v.insert("nick".into(), json::Value::String(nick.to_string()));
    v.insert(
        "addr".into(),
        json::Value::String(SocketAddr::from(([127, 0, 0, 1], port)).to_string()),
    );
    m.insert(PeerId::from(key).to_string(), json::Value::Object(v));
}

async fn run_client(
    addr: SocketAddr,
    key: Keypair,
    known_peers: SharedKnownPeers,
) -> Result<(mpsc::Sender<Result<Command>>, impl Stream<Item = Message>)> {
    let (in_tx, in_rx) = mpsc::channel(10);
    let (out_tx, out_rx) = mpsc::channel(10);
    let out_tx = out_tx.sink_err_into();
    let client = MainLoop::new(addr, key, in_rx, out_tx, known_peers).await?;
    tokio::spawn(client.run());
    Ok((
        in_tx,
        out_rx.filter(|i| {
            future::ready(if let Message::NewLine = i {
                false
            } else {
                true
            })
        }),
    ))
}

#[tokio::test]
async fn run_two_clients() -> Result<()> {
    let a_key = generate_key();
    let a_addr: SocketAddr = "127.0.0.1:8080".parse()?;
    let a_id = PeerId::from(&a_key);
    let b_key = generate_key();
    let b_id = PeerId::from(&b_key);
    let b_addr: SocketAddr = "127.0.0.1:8081".parse()?;
    let mut m = json::Map::new();
    insert_peer(&mut m, "peer_a", &a_key, 8080);
    insert_peer(&mut m, "peer_b", &b_key, 8081);

    let kp1 = SharedKnownPeers::from_json_reader(&mut Cursor::new(json::to_vec(&m)?))?;
    let kp2 = SharedKnownPeers::from_json_reader(&mut Cursor::new(json::to_vec(&m)?))?;
    assert_eq!(2, kp1.len().await);
    let (mut a_in, mut a_out) = run_client(a_addr, a_key, kp1).await?;
    let (mut b_in, mut b_out) = run_client(b_addr, b_key, kp2).await?;

    a_in.send(Ok(Command::Connect {
        peer: "peer_b".into(),
    }))
    .await?;
    if let Some(Message::HadshakeDone { peer }) = b_out.next().await {
        assert_eq!(Some("peer_a".into()), peer.nick);
        assert_eq!(a_id, peer.peer_id);
        assert_eq!(Some(a_addr), peer.peer_addr);
    } else {
        panic!("Invalid message")
    }

    if let Some(Message::HadshakeDone { peer }) = a_out.next().await {
        assert_eq!(Some("peer_b".into()), peer.nick);
        assert_eq!(b_id, peer.peer_id);
        assert_eq!(Some(b_addr), peer.peer_addr);
    } else {
        panic!("Invalid message")
    }

    a_in.send(Ok(Command::Send {
        to: "peer_b".into(),
        text: "Hey".into(),
    }))
    .await?;
    if let Some(Message::Post { peer, content }) = b_out.next().await {
        assert_eq!(Some("peer_a".into()), peer.nick);
        assert_eq!(a_id, peer.peer_id);
        assert_eq!(Some(a_addr), peer.peer_addr);
        assert_eq!("Hey", content);
    } else {
        panic!("Invalid message")
    }

    b_in.send(Ok(Command::Send {
        to: "peer_a".into(),
        text: "How".into(),
    }))
    .await?;
    if let Some(Message::Sent { peer }) = a_out.next().await {
        assert_eq!(Some("peer_b".into()), peer.nick);
        assert_eq!(b_id, peer.peer_id);
        assert_eq!(Some(b_addr), peer.peer_addr);
    } else {
        panic!("Invalid message")
    }
    if let Some(Message::Post { peer, content }) = a_out.next().await {
        assert_eq!(Some("peer_b".into()), peer.nick);
        assert_eq!(b_id, peer.peer_id);
        assert_eq!(Some(b_addr), peer.peer_addr);
        assert_eq!("How", content);
    } else {
        panic!("Invalid message")
    }

    Ok(())
}
