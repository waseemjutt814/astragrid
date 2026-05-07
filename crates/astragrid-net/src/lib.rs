use std::{
    io::{BufRead, BufReader, Write},
    net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs},
    time::Duration,
};

use astragrid_core::{
    DetachedSignature, LedgerVerification, MissionEvent, MissionLedger, OperatorKeypair,
    OperatorRegistry, OperatorStatus,
};
use astragrid_sync::{SyncPlan, SyncStatus};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

const PROTOCOL: &str = "astragrid-peer-v1";
const PEER_AUTH_PURPOSE: &str = "astragrid-peer-authorization-v1";
const PEER_AUTH_DIGEST_ALGORITHM: &str = "blake3";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PeerSnapshot {
    pub protocol: String,
    pub events: Vec<MissionEvent>,
    pub verification: LedgerVerification,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerEndpoint {
    pub name: String,
    pub addr: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PeerSyncOutcome {
    pub peer: String,
    pub addr: String,
    pub status: Option<SyncStatus>,
    pub plan: Option<SyncPlan>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MultiPeerSyncReport {
    pub local_events: usize,
    pub peers: Vec<PeerSyncOutcome>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ClientHello {
    protocol: String,
    nonce: String,
    mac: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ServerHello {
    protocol: String,
    nonce: String,
    mac: String,
    #[serde(default)]
    auth_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ClientAuthorization {
    protocol: String,
    signature: DetachedSignature,
}

pub fn serve_ledger_once(
    bind: impl ToSocketAddrs,
    ledger: &MissionLedger,
    shared_key: &[u8],
) -> Result<SocketAddr, NetError> {
    let listener = TcpListener::bind(bind)?;
    let addr = listener.local_addr()?;
    let (stream, _) = listener.accept()?;
    handle_peer(stream, ledger, shared_key, None)?;
    Ok(addr)
}

pub fn serve_ledger_once_with_listener(
    listener: TcpListener,
    ledger: &MissionLedger,
    shared_key: &[u8],
) -> Result<(), NetError> {
    let (stream, _) = listener.accept()?;
    serve_ledger_connection(stream, ledger, shared_key)
}

pub fn serve_ledger_once_with_peer_registry(
    bind: impl ToSocketAddrs,
    ledger: &MissionLedger,
    shared_key: &[u8],
    peer_registry: &OperatorRegistry,
) -> Result<SocketAddr, NetError> {
    let listener = TcpListener::bind(bind)?;
    let addr = listener.local_addr()?;
    let (stream, _) = listener.accept()?;
    handle_peer(stream, ledger, shared_key, Some(peer_registry))?;
    Ok(addr)
}

pub fn serve_ledger_once_with_listener_and_peer_registry(
    listener: TcpListener,
    ledger: &MissionLedger,
    shared_key: &[u8],
    peer_registry: &OperatorRegistry,
) -> Result<(), NetError> {
    let (stream, _) = listener.accept()?;
    serve_ledger_connection_with_peer_registry(stream, ledger, shared_key, peer_registry)
}

pub fn serve_ledger_connection(
    stream: TcpStream,
    ledger: &MissionLedger,
    shared_key: &[u8],
) -> Result<(), NetError> {
    handle_peer(stream, ledger, shared_key, None)
}

pub fn serve_ledger_connection_with_peer_registry(
    stream: TcpStream,
    ledger: &MissionLedger,
    shared_key: &[u8],
    peer_registry: &OperatorRegistry,
) -> Result<(), NetError> {
    handle_peer(stream, ledger, shared_key, Some(peer_registry))
}

pub fn fetch_ledger_snapshot(
    addr: impl ToSocketAddrs,
    shared_key: &[u8],
) -> Result<PeerSnapshot, NetError> {
    fetch_ledger_snapshot_inner(addr, shared_key, None)
}

pub fn fetch_ledger_snapshot_with_identity(
    addr: impl ToSocketAddrs,
    shared_key: &[u8],
    identity: &OperatorKeypair,
) -> Result<PeerSnapshot, NetError> {
    fetch_ledger_snapshot_inner(addr, shared_key, Some(identity))
}

fn fetch_ledger_snapshot_inner(
    addr: impl ToSocketAddrs,
    shared_key: &[u8],
    identity: Option<&OperatorKeypair>,
) -> Result<PeerSnapshot, NetError> {
    let mut stream = TcpStream::connect(addr)?;
    stream.set_read_timeout(Some(Duration::from_secs(15)))?;
    stream.set_write_timeout(Some(Duration::from_secs(15)))?;

    let client_nonce = nonce_hex();
    let client_hello = ClientHello {
        protocol: PROTOCOL.to_owned(),
        mac: mac(shared_key, b"client", client_nonce.as_bytes()),
        nonce: client_nonce.clone(),
    };
    write_json_line(&mut stream, &client_hello)?;

    let mut reader = BufReader::new(stream.try_clone()?);
    let server_hello: ServerHello = read_json_line(&mut reader)?;
    if server_hello.protocol != PROTOCOL {
        return Err(NetError::ProtocolMismatch(server_hello.protocol));
    }
    let expected = mac(shared_key, b"server", server_hello.nonce.as_bytes());
    if server_hello.mac != expected {
        return Err(NetError::AuthenticationFailed);
    }
    if server_hello.auth_required {
        let Some(identity) = identity else {
            return Err(NetError::PeerAuthorizationRequired);
        };
        write_json_line(
            &mut stream,
            &ClientAuthorization {
                protocol: PROTOCOL.to_owned(),
                signature: identity.sign_digest(
                    PEER_AUTH_PURPOSE,
                    PEER_AUTH_DIGEST_ALGORITHM,
                    &peer_authorization_digest(&client_nonce, &server_hello.nonce),
                )?,
            },
        )?;
    }

    let snapshot: PeerSnapshot = read_json_line(&mut reader)?;
    if snapshot.protocol != PROTOCOL {
        return Err(NetError::ProtocolMismatch(snapshot.protocol));
    }
    if !snapshot.verification.valid {
        return Err(NetError::RemoteLedgerInvalid(snapshot.verification));
    }
    Ok(snapshot)
}

pub fn plan_peer_sync(
    local_events: &[MissionEvent],
    peer: &PeerEndpoint,
    shared_key: &[u8],
) -> PeerSyncOutcome {
    match fetch_ledger_snapshot(peer.addr.as_str(), shared_key).and_then(|snapshot| {
        SyncPlan::from_events(local_events, &snapshot.events).map_err(NetError::Sync)
    }) {
        Ok(plan) => PeerSyncOutcome {
            peer: peer.name.clone(),
            addr: peer.addr.clone(),
            status: Some(plan.status),
            plan: Some(plan),
            error: None,
        },
        Err(error) => PeerSyncOutcome {
            peer: peer.name.clone(),
            addr: peer.addr.clone(),
            status: None,
            plan: None,
            error: Some(error.to_string()),
        },
    }
}

pub fn plan_peer_sync_with_identity(
    local_events: &[MissionEvent],
    peer: &PeerEndpoint,
    shared_key: &[u8],
    identity: &OperatorKeypair,
) -> PeerSyncOutcome {
    match fetch_ledger_snapshot_with_identity(peer.addr.as_str(), shared_key, identity).and_then(
        |snapshot| SyncPlan::from_events(local_events, &snapshot.events).map_err(NetError::Sync),
    ) {
        Ok(plan) => PeerSyncOutcome {
            peer: peer.name.clone(),
            addr: peer.addr.clone(),
            status: Some(plan.status),
            plan: Some(plan),
            error: None,
        },
        Err(error) => PeerSyncOutcome {
            peer: peer.name.clone(),
            addr: peer.addr.clone(),
            status: None,
            plan: None,
            error: Some(error.to_string()),
        },
    }
}

pub fn plan_multi_peer_sync(
    local_events: &[MissionEvent],
    peers: &[PeerEndpoint],
    shared_key: &[u8],
) -> MultiPeerSyncReport {
    MultiPeerSyncReport {
        local_events: local_events.len(),
        peers: peers
            .iter()
            .map(|peer| plan_peer_sync(local_events, peer, shared_key))
            .collect(),
    }
}

pub fn plan_multi_peer_sync_with_identity(
    local_events: &[MissionEvent],
    peers: &[PeerEndpoint],
    shared_key: &[u8],
    identity: &OperatorKeypair,
) -> MultiPeerSyncReport {
    MultiPeerSyncReport {
        local_events: local_events.len(),
        peers: peers
            .iter()
            .map(|peer| plan_peer_sync_with_identity(local_events, peer, shared_key, identity))
            .collect(),
    }
}

fn handle_peer(
    mut stream: TcpStream,
    ledger: &MissionLedger,
    shared_key: &[u8],
    peer_registry: Option<&OperatorRegistry>,
) -> Result<(), NetError> {
    stream.set_read_timeout(Some(Duration::from_secs(15)))?;
    stream.set_write_timeout(Some(Duration::from_secs(15)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let client_hello: ClientHello = read_json_line(&mut reader)?;
    if client_hello.protocol != PROTOCOL {
        return Err(NetError::ProtocolMismatch(client_hello.protocol));
    }
    let expected = mac(shared_key, b"client", client_hello.nonce.as_bytes());
    if client_hello.mac != expected {
        return Err(NetError::AuthenticationFailed);
    }

    let server_nonce = nonce_hex();
    write_json_line(
        &mut stream,
        &ServerHello {
            protocol: PROTOCOL.to_owned(),
            mac: mac(shared_key, b"server", server_nonce.as_bytes()),
            nonce: server_nonce.clone(),
            auth_required: peer_registry.is_some(),
        },
    )?;
    if let Some(peer_registry) = peer_registry {
        let authorization: ClientAuthorization = read_json_line(&mut reader)?;
        if authorization.protocol != PROTOCOL {
            return Err(NetError::ProtocolMismatch(authorization.protocol));
        }
        authorize_peer_signature(
            &authorization.signature,
            &peer_authorization_digest(&client_hello.nonce, &server_nonce),
            peer_registry,
        )?;
    }

    let verification = ledger.verify()?;
    if !verification.valid {
        return Err(NetError::LocalLedgerInvalid(verification));
    }
    write_json_line(
        &mut stream,
        &PeerSnapshot {
            protocol: PROTOCOL.to_owned(),
            events: ledger.load_events()?,
            verification,
        },
    )
}

fn authorize_peer_signature(
    signature: &DetachedSignature,
    payload_digest: &str,
    peer_registry: &OperatorRegistry,
) -> Result<(), NetError> {
    signature
        .verify_digest(
            PEER_AUTH_PURPOSE,
            PEER_AUTH_DIGEST_ALGORITHM,
            payload_digest,
        )
        .map_err(|error| NetError::PeerAuthorizationFailed(error.to_string()))?;
    let identity = &signature.identity;
    let entry = peer_registry.get(&identity.id).ok_or_else(|| {
        NetError::PeerAuthorizationFailed(format!("operator {} is not enrolled", identity.id))
    })?;
    if entry.status == OperatorStatus::Revoked {
        return Err(NetError::PeerAuthorizationFailed(format!(
            "operator {} is revoked",
            identity.id
        )));
    }
    if entry.identity.public_key != identity.public_key {
        return Err(NetError::PeerAuthorizationFailed(format!(
            "operator {} public key does not match registry",
            identity.id
        )));
    }
    if entry.identity.name != identity.name {
        return Err(NetError::PeerAuthorizationFailed(format!(
            "operator {} name does not match registry",
            identity.id
        )));
    }
    if entry.identity.role != identity.role {
        return Err(NetError::PeerAuthorizationFailed(format!(
            "operator {} role does not match registry",
            identity.id
        )));
    }
    Ok(())
}

fn peer_authorization_digest(client_nonce: &str, server_nonce: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(PROTOCOL.as_bytes());
    hasher.update(PEER_AUTH_PURPOSE.as_bytes());
    hasher.update(b"client");
    hasher.update(client_nonce.as_bytes());
    hasher.update(b"server");
    hasher.update(server_nonce.as_bytes());
    hasher.finalize().to_hex().to_string()
}

fn nonce_hex() -> String {
    let mut nonce = [0_u8; 16];
    OsRng.fill_bytes(&mut nonce);
    hex::encode(nonce)
}

fn mac(shared_key: &[u8], role: &[u8], nonce: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(PROTOCOL.as_bytes());
    hasher.update(shared_key);
    hasher.update(role);
    hasher.update(nonce);
    hasher.finalize().to_hex().to_string()
}

fn write_json_line<T: Serialize>(stream: &mut TcpStream, value: &T) -> Result<(), NetError> {
    serde_json::to_writer(&mut *stream, value)?;
    stream.write_all(b"\n")?;
    stream.flush()?;
    Ok(())
}

fn read_json_line<T: for<'de> Deserialize<'de>, R: BufRead>(reader: &mut R) -> Result<T, NetError> {
    let mut line = String::new();
    let bytes = reader.read_line(&mut line)?;
    if bytes == 0 {
        return Err(NetError::ConnectionClosed);
    }
    Ok(serde_json::from_str(line.trim_end())?)
}

#[derive(Debug, thiserror::Error)]
pub enum NetError {
    #[error("network I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("network JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("ledger failed: {0}")]
    Ledger(#[from] astragrid_core::LedgerError),
    #[error("sync planning failed: {0}")]
    Sync(#[from] astragrid_sync::SyncError),
    #[error("authentication failed")]
    AuthenticationFailed,
    #[error("peer identity authorization required")]
    PeerAuthorizationRequired,
    #[error("peer identity authorization failed: {0}")]
    PeerAuthorizationFailed(String),
    #[error("peer identity signing failed: {0}")]
    PeerIdentity(#[from] astragrid_core::IdentityError),
    #[error("connection closed")]
    ConnectionClosed,
    #[error("protocol mismatch: {0}")]
    ProtocolMismatch(String),
    #[error("local ledger is invalid: {0:?}")]
    LocalLedgerInvalid(LedgerVerification),
    #[error("remote ledger is invalid: {0:?}")]
    RemoteLedgerInvalid(LedgerVerification),
}

#[cfg(test)]
mod tests {
    use std::{net::TcpListener, thread};

    use astragrid_core::{
        Action, Actor, CommandRequest, MissionLedger, OperatorKeypair, OperatorRegistry, Priority,
        Role,
    };
    use serde_json::json;
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn fetches_snapshot_over_authenticated_tcp() {
        let dir = tempdir().unwrap();
        let ledger = MissionLedger::open(dir.path().join("mission.agl"));
        ledger
            .append(CommandRequest::new(
                Actor::new("kernel", Role::System),
                Action::OpenMission,
                "mission-a",
                Priority::Elevated,
                json!({"mission": "mission-a"}),
            ))
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server_ledger = ledger.clone();
        let handle = thread::spawn(move || {
            serve_ledger_once_with_listener(listener, &server_ledger, b"shared").unwrap();
        });

        let snapshot = fetch_ledger_snapshot(addr, b"shared").unwrap();
        handle.join().unwrap();

        assert_eq!(snapshot.events.len(), 1);
        assert!(snapshot.verification.valid);
    }

    #[test]
    fn fetches_snapshot_with_registry_authorized_identity() {
        let dir = tempdir().unwrap();
        let ledger = MissionLedger::open(dir.path().join("mission.agl"));
        ledger
            .append(CommandRequest::new(
                Actor::new("kernel", Role::System),
                Action::OpenMission,
                "mission-a",
                Priority::Elevated,
                json!({"mission": "mission-a"}),
            ))
            .unwrap();
        let client_key = OperatorKeypair::generate("peer-a", Role::Operator);
        let mut registry = OperatorRegistry::new("local");
        registry
            .enroll(client_key.identity().clone(), "test")
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server_ledger = ledger.clone();
        let handle = thread::spawn(move || {
            serve_ledger_once_with_listener_and_peer_registry(
                listener,
                &server_ledger,
                b"shared",
                &registry,
            )
            .unwrap();
        });

        let snapshot = fetch_ledger_snapshot_with_identity(addr, b"shared", &client_key).unwrap();
        handle.join().unwrap();

        assert_eq!(snapshot.events.len(), 1);
        assert!(snapshot.verification.valid);
    }

    #[test]
    fn registry_required_server_rejects_unsigned_peer() {
        let dir = tempdir().unwrap();
        let ledger = MissionLedger::open(dir.path().join("mission.agl"));
        let registry = OperatorRegistry::new("local");
        ledger
            .append(CommandRequest::new(
                Actor::new("kernel", Role::System),
                Action::OpenMission,
                "mission-a",
                Priority::Elevated,
                json!({"mission": "mission-a"}),
            ))
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server_ledger = ledger.clone();
        let handle = thread::spawn(move || {
            serve_ledger_once_with_listener_and_peer_registry(
                listener,
                &server_ledger,
                b"shared",
                &registry,
            )
        });

        let error = fetch_ledger_snapshot(addr, b"shared").unwrap_err();
        let server_error = handle.join().unwrap().unwrap_err();

        assert!(matches!(error, NetError::PeerAuthorizationRequired));
        assert!(matches!(server_error, NetError::ConnectionClosed));
    }

    #[test]
    fn registry_required_server_rejects_unenrolled_identity() {
        let dir = tempdir().unwrap();
        let ledger = MissionLedger::open(dir.path().join("mission.agl"));
        let client_key = OperatorKeypair::generate("peer-a", Role::Operator);
        let registry = OperatorRegistry::new("local");
        ledger
            .append(CommandRequest::new(
                Actor::new("kernel", Role::System),
                Action::OpenMission,
                "mission-a",
                Priority::Elevated,
                json!({"mission": "mission-a"}),
            ))
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server_ledger = ledger.clone();
        let handle = thread::spawn(move || {
            serve_ledger_once_with_listener_and_peer_registry(
                listener,
                &server_ledger,
                b"shared",
                &registry,
            )
        });

        let client_error = fetch_ledger_snapshot_with_identity(addr, b"shared", &client_key)
            .expect_err("snapshot should be rejected");
        let server_error = handle.join().unwrap().unwrap_err();

        assert!(matches!(client_error, NetError::ConnectionClosed));
        assert!(matches!(server_error, NetError::PeerAuthorizationFailed(_)));
    }

    #[test]
    fn plans_multi_peer_sync_from_manifest() {
        let dir = tempdir().unwrap();
        let ledger = MissionLedger::open(dir.path().join("mission.agl"));
        ledger
            .append(CommandRequest::new(
                Actor::new("kernel", Role::System),
                Action::OpenMission,
                "mission-a",
                Priority::Elevated,
                json!({"mission": "mission-a"}),
            ))
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server_ledger = ledger.clone();
        let handle = thread::spawn(move || {
            serve_ledger_once_with_listener(listener, &server_ledger, b"shared").unwrap();
        });
        let peers = vec![PeerEndpoint {
            name: "peer-a".to_owned(),
            addr: addr.to_string(),
        }];

        let report = plan_multi_peer_sync(&ledger.load_events().unwrap(), &peers, b"shared");
        handle.join().unwrap();

        assert_eq!(report.peers.len(), 1);
        assert_eq!(report.peers[0].status, Some(SyncStatus::Identical));
        assert!(report.peers[0].error.is_none());
    }
}
