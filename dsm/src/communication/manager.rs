use crate::communication::async_trait;
use futures::future::{select_all, FutureExt};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, RwLock};
use tokio::time::timeout;
use uuid::Uuid;

use crate::communication::{
    protocol::{Message, Protocol, Session},
    transport::{Transport, TransportConnection},
    TransportType, DEFAULT_MAX_MESSAGE_SIZE,
};
use crate::types::error::DsmError;

/// Protocol hint for connection establishment
#[derive(Debug, Clone)]
pub struct ConnectionHints {
    /// Known address for the peer
    pub address: Option<SocketAddr>,
    /// Preferred transport types
    pub preferred_transports: Vec<TransportType>,
    /// Whether to enforce quantum resistance
    pub require_quantum_resistance: bool,
    /// Whether offline capability is required
    pub require_offline_capability: bool,
    /// Connection timeout in milliseconds
    pub timeout_ms: u64,
    /// Additional peer metadata for specialized transports
    pub peer_metadata: HashMap<String, String>,
}

impl ConnectionHints {
    /// Create new connection hints
    pub fn new() -> Self {
        Self {
            address: None,
            preferred_transports: vec![
                TransportType::Tls,
                TransportType::SecureUdp,
                #[cfg(feature = "bluetooth")]
                TransportType::Bluetooth,
            ],
            require_quantum_resistance: true,
            require_offline_capability: false,
            timeout_ms: 30000, // 30 seconds
            peer_metadata: HashMap::new(),
        }
    }

    /// Set peer address
    pub fn with_address(mut self, address: SocketAddr) -> Self {
        self.address = Some(address);
        self
    }

    /// Set preferred transport types
    pub fn with_preferred_transports(mut self, transports: Vec<TransportType>) -> Self {
        self.preferred_transports = transports;
        self
    }

    /// Set quantum resistance requirement
    pub fn with_quantum_resistance(mut self, required: bool) -> Self {
        self.require_quantum_resistance = required;
        self
    }

    /// Set offline capability requirement
    pub fn with_offline_capability(mut self, required: bool) -> Self {
        self.require_offline_capability = required;
        self
    }

    /// Set connection timeout
    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    /// Add peer metadata
    pub fn with_metadata(mut self, key: &str, value: &str) -> Self {
        self.peer_metadata
            .insert(key.to_string(), value.to_string());
        self
    }
}

impl Default for ConnectionHints {
    fn default() -> Self {
        Self::new()
    }
}

/// Connection manager trait
#[async_trait]
pub trait ConnectionManager: Send + Sync {
    /// Connect to a peer
    async fn connect(
        &self,
        peer_id: &str,
        hints: ConnectionHints,
    ) -> Result<Box<dyn Session>, DsmError>;

    /// Listen for incoming connections
    async fn listen(&self, addr: SocketAddr) -> Result<(), DsmError>;

    /// Get active sessions
    async fn get_active_sessions(&self) -> Vec<SessionInfo>;

    /// Disconnect from a peer
    async fn disconnect(&self, peer_id: &str) -> Result<(), DsmError>;

    /// Check if a peer is connected
    async fn is_connected(&self, peer_id: &str) -> bool;

    /// Get peer information by session ID
    async fn get_peer_by_session(&self, session_id: &str) -> Option<String>;
}

/// Session information
#[derive(Debug, Clone)]
pub struct SessionInfo {
    /// Session ID
    pub session_id: String,
    /// Peer ID
    pub peer_id: String,
    /// Remote address
    pub remote_addr: SocketAddr,
    /// Transport type
    pub transport_type: TransportType,
    /// Whether the session is quantum resistant
    pub is_quantum_resistant: bool,
    /// Creation time
    pub creation_time: Instant,
    /// Last activity time
    pub last_activity_time: Instant,
    /// Session state
    pub state: SessionState,
}

/// Session state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Session is being established
    Establishing,
    /// Session is active
    Active,
    /// Session is in the process of closing
    Closing,
    /// Session has been closed
    Closed,
}

/// Transport connection attempt result
enum ConnectionAttemptResult {
    /// Connection attempt succeeded
    Success(Box<dyn TransportConnection>),
    /// Connection attempt failed
    Failure(DsmError),
}

/// Network manager implementation
pub struct NetworkManager {
    /// Available transports
    transports: Arc<RwLock<HashMap<TransportType, Arc<dyn Transport>>>>,
    /// Protocol implementation
    protocol: Arc<dyn Protocol>,
    /// Active sessions
    active_sessions: Arc<RwLock<HashMap<String, Arc<dyn Session>>>>,
    /// Peer-to-session mapping
    peer_sessions: Arc<RwLock<HashMap<String, Vec<String>>>>,
    /// Session-to-peer mapping
    session_peers: Arc<RwLock<HashMap<String, String>>>,
    /// Session state
    session_states: Arc<RwLock<HashMap<String, SessionState>>>,
    /// Preferred transport order
    preferred_transports: Arc<RwLock<Vec<TransportType>>>,
    /// Connection lock to prevent concurrent connection attempts to the same peer
    connection_locks: Arc<RwLock<HashMap<String, Arc<Mutex<()>>>>>,
    /// Whether to enforce quantum resistance for all connections
    require_quantum_resistance: Arc<RwLock<bool>>,
}

impl NetworkManager {
    /// Create a new network manager
    pub fn new(protocol: Arc<dyn Protocol>) -> Self {
        Self {
            transports: Arc::new(RwLock::new(HashMap::new())),
            protocol,
            active_sessions: Arc::new(RwLock::new(HashMap::new())),
            peer_sessions: Arc::new(RwLock::new(HashMap::new())),
            session_peers: Arc::new(RwLock::new(HashMap::new())),
            session_states: Arc::new(RwLock::new(HashMap::new())),
            preferred_transports: Arc::new(RwLock::new(Vec::new())),
            connection_locks: Arc::new(RwLock::new(HashMap::new())),
            require_quantum_resistance: Arc::new(RwLock::new(false)),
        }
    }

    /// Register a transport
    pub fn register_transport(&mut self, transport: Arc<dyn Transport>) {
        let transport_type = transport.transport_type();
        let mut transports = futures::executor::block_on(self.transports.write());
        transports.insert(transport_type, transport);
    }

    /// Get a transport by type
    pub async fn get_transport(&self, transport_type: TransportType) -> Option<Arc<dyn Transport>> {
        let transports = self.transports.read().await;
        transports.get(&transport_type).cloned()
    }

    /// Set preferred transport order
    pub fn set_transport_preferences(&self, transports: Vec<TransportType>) {
        let mut prefs = futures::executor::block_on(self.preferred_transports.write());
        *prefs = transports;
    }

    /// Set quantum resistance requirement
    pub fn set_quantum_resistance_required(&self, required: bool) {
        let mut qr = futures::executor::block_on(self.require_quantum_resistance.write());
        *qr = required;
    }

    /// Check if any transport matches the given requirements
    async fn find_suitable_transports(&self, hints: &ConnectionHints) -> Vec<Arc<dyn Transport>> {
        let transports = self.transports.read().await;
        let preferred = self.preferred_transports.read().await;
        let global_qr_required = *self.require_quantum_resistance.read().await;

        let mut suitable = Vec::new();
        let qr_required = global_qr_required || hints.require_quantum_resistance;

        // First, try to use the preferred order
        let transport_order = if !hints.preferred_transports.is_empty() {
            &hints.preferred_transports
        } else if !preferred.is_empty() {
            &preferred
        } else {
            // Default order based on availability
            #[cfg(feature = "bluetooth")]
            static DEFAULT_ORDER: [TransportType; 3] = [
                TransportType::Tls,
                TransportType::SecureUdp,
                TransportType::Bluetooth,
            ];

            #[cfg(not(feature = "bluetooth"))]
            static DEFAULT_ORDER: [TransportType; 2] =
                [TransportType::Tls, TransportType::SecureUdp];
            DEFAULT_ORDER.as_slice()
        };

        for transport_type in transport_order {
            if let Some(transport) = transports.get(transport_type) {
                // Check quantum resistance requirement
                if qr_required && !transport.is_quantum_resistant() {
                    continue;
                }

                // Check offline capability requirement
                if hints.require_offline_capability && !transport.supports_offline() {
                    continue;
                }

                suitable.push(transport.clone());
            }
        }

        suitable
    }

    /// Try to connect using a specific transport
    async fn try_connect_with_transport(
        &self,
        transport: Arc<dyn Transport>,
        addr: SocketAddr,
        timeout_ms: u64,
    ) -> ConnectionAttemptResult {
        match timeout(Duration::from_millis(timeout_ms), transport.connect(addr)).await {
            Ok(result) => match result {
                Ok(connection) => ConnectionAttemptResult::Success(connection),
                Err(e) => ConnectionAttemptResult::Failure(e),
            },
            Err(_) => ConnectionAttemptResult::Failure(DsmError::network(
                format!("Connection timeout using {:?}", transport.transport_type()),
                None::<std::io::Error>,
            )),
        }
    }

    /// Get a connection lock for a peer
    async fn get_connection_lock(&self, peer_id: &str) -> Arc<Mutex<()>> {
        let mut locks = self.connection_locks.write().await;
        locks
            .entry(peer_id.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    /// Get a session by peer ID
    async fn get_session_by_peer(&self, peer_id: &str) -> Option<Arc<dyn Session>> {
        let peer_sessions = self.peer_sessions.read().await;
        let session_ids = peer_sessions.get(peer_id)?;

        if session_ids.is_empty() {
            return None;
        }

        // Try to find an active session
        let session_states = self.session_states.read().await;
        let active_sessions = self.active_sessions.read().await;

        for session_id in session_ids {
            if let Some(state) = session_states.get(session_id) {
                if (*state) == SessionState::Active {
                    return active_sessions.get(session_id).cloned();
                }
            }
        }

        // If no active session found, return the first one
        let session_id = &session_ids[0];
        active_sessions.get(session_id).cloned()
    }

    /// Add a new session
    async fn add_session(
        &self,
        peer_id: &str,
        session: impl Session + 'static,
    ) -> Result<Arc<dyn Session>, DsmError> {
        let session_id = session.session_id().to_string();
        let session_arc = Arc::new(session);

        // Store session info
        {
            let mut active_sessions = self.active_sessions.write().await;
            active_sessions.insert(session_id.clone(), session_arc.clone());

            let mut peer_sessions = self.peer_sessions.write().await;
            peer_sessions
                .entry(peer_id.to_string())
                .or_insert_with(Vec::new)
                .push(session_id.clone());

            let mut session_peers = self.session_peers.write().await;
            session_peers.insert(session_id.clone(), peer_id.to_string());

            let mut session_states = self.session_states.write().await;
            session_states.insert(session_id.clone(), SessionState::Active);
        }

        Ok(session_arc)
    }
    /// Remove a session    
    async fn remove_session(&self, session_id: &str) -> Result<(), DsmError> {
        // Get peer ID
        let peer_id = {
            let session_peers = self.session_peers.read().await;
            session_peers
                .get(session_id)
                .ok_or_else(|| {
                    DsmError::internal(
                        format!("Session not found for ID {}", session_id),
                        None::<std::convert::Infallible>,
                    )
                })?
                .clone()
        };
        // Remove session
        {
            let mut active_sessions = self.active_sessions.write().await;
            active_sessions.remove(session_id);

            let mut peer_sessions = self.peer_sessions.write().await;
            if let Some(sessions) = peer_sessions.get_mut(&peer_id) {
                sessions.retain(|id| id != session_id);

                // Remove peer mapping if no sessions remain
                if sessions.is_empty() {
                    peer_sessions.remove(&peer_id);
                }
            }

            let mut session_peers = self.session_peers.write().await;
            session_peers.remove(session_id);

            let mut session_states = self.session_states.write().await;
            session_states.insert(session_id.to_string(), SessionState::Closed);
        }

        Ok(())
    }

    /// Update session state
    async fn update_session_state(&self, session_id: &str, state: SessionState) {
        let mut session_states = self.session_states.write().await;
        session_states.insert(session_id.to_string(), state);
    }

    /// Accept connections loop
    async fn accept_connections(
        listener: Box<dyn crate::communication::transport::TransportListener>,
        transport_type: TransportType,
        protocol: Arc<dyn Protocol>,
        manager: Arc<NetworkManager>,
    ) {
        loop {
            match listener.accept().await {
                Ok(connection) => {
                    let remote_addr = connection.remote_addr();
                    let protocol_clone = protocol.clone();
                    let manager_clone = manager.clone();

                    // Spawn a task to handle the connection
                    tokio::spawn(async move {
                        match protocol_clone.accept_session(connection).await {
                            Ok(session) => {
                                // Generate peer ID based on remote address
                                let peer_id = format!("peer-{}", remote_addr);

                                // Convert Box to Arc and wrap session
                                let session_arc = Arc::from(session);
                                let wrapped_session = SessionWrapper(session_arc);

                                // Add session
                                match manager_clone.add_session(&peer_id, wrapped_session).await {
                                    Ok(session_arc) => {
                                        let session_id = session_arc.session_id().to_string();
                                        tracing::info!(
                                            "Accepted {:?} connection from {} (session: {}, peer: {})",
                                            transport_type, remote_addr, session_id, peer_id
                                        );
                                    }
                                    Err(e) => {
                                        tracing::error!(
                                            "Failed to add session for {:?} connection from {}: {}",
                                            transport_type,
                                            remote_addr,
                                            e
                                        );
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "Failed to accept {:?} session from {}: {}",
                                    transport_type,
                                    remote_addr,
                                    e
                                );
                            }
                        }
                    });
                }
                Err(e) => {
                    if !e.is_recoverable() {
                        tracing::error!("Fatal error in {:?} listener: {}", transport_type, e);
                        break;
                    }
                    tracing::warn!("Transient error in {:?} listener: {}", transport_type, e);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }
}
/// Session wrapper to implement Send + Sync for Box<dyn Session>
struct SessionWrapper(Arc<dyn Session>);

#[async_trait]
impl Session for SessionWrapper {
    async fn send_message(&self, message: Message) -> Result<(), DsmError> {
        self.0.send_message(message).await
    }

    async fn receive_message(&self) -> Result<Message, DsmError> {
        self.0.receive_message().await
    }

    async fn close(&self) -> Result<(), DsmError> {
        self.0.close().await
    }

    fn remote_addr(&self) -> SocketAddr {
        self.0.remote_addr()
    }

    fn session_id(&self) -> &str {
        self.0.session_id()
    }

    fn transport_type(&self) -> TransportType {
        self.0.transport_type()
    }

    fn is_quantum_resistant(&self) -> bool {
        self.0.is_quantum_resistant()
    }

    fn is_active(&self) -> bool {
        self.0.is_active()
    }

    fn creation_time(&self) -> Instant {
        self.0.creation_time()
    }

    fn last_activity_time(&self) -> Instant {
        self.0.last_activity_time()
    }
}

/// Network interface adapter for backward compatibility
pub struct NetworkInterfaceAdapter {
    /// Connection manager
    connection_manager: Arc<dyn ConnectionManager>,
    /// Maximum message size
    max_message_size: usize,
}

impl NetworkInterfaceAdapter {
    /// Create a new network interface adapter
    pub fn new(connection_manager: Arc<dyn ConnectionManager>, max_message_size: usize) -> Self {
        Self {
            connection_manager,
            max_message_size,
        }
    }

    /// Initialize with default settings
    pub fn init(connection_manager: Arc<dyn ConnectionManager>) -> Self {
        Self::new(connection_manager, DEFAULT_MAX_MESSAGE_SIZE)
    }

    /// Get the configured maximum message size
    pub fn get_max_message_size(&self) -> usize {
        self.max_message_size
    }

    /// Get a reference to the connection manager
    pub fn get_connection_manager(&self) -> &Arc<dyn ConnectionManager> {
        &self.connection_manager
    }
}

impl NetworkManager {
    // Private implementation methods
    async fn get_session_by_id(&self, session_id: &str) -> Option<Arc<dyn Session>> {
        let active_sessions = self.active_sessions.read().await;
        active_sessions.get(session_id).cloned()
    }

    /// Start listening on a specific transport
    async fn listen_on_transport(
        transport: Arc<dyn Transport>,
        protocol: Arc<dyn Protocol>,
        manager: Arc<NetworkManager>,
        addr: SocketAddr,
    ) {
        // Call the transport's bind method to get a listener
        match transport.bind(addr).await {
            Ok(listener) => {
                tracing::info!(
                    "Started {:?} listener on {}",
                    transport.transport_type(),
                    addr
                );

                // Hand off to the accept loop
                Self::accept_connections(listener, transport.transport_type(), protocol, manager)
                    .await;
            }
            Err(e) => {
                tracing::error!(
                    "Failed to start {:?} listener on {}: {}",
                    transport.transport_type(),
                    addr,
                    e
                );
            }
        }
    }

    #[cfg(test)]
    #[allow(dead_code)]
    async fn cleanup_expired_sessions(&self, expiry_time: Duration) {
        let now = Instant::now();
        let mut sessions_to_close = Vec::new();

        // Find expired sessions
        {
            let active_sessions = self.active_sessions.read().await;
            for (session_id, session) in &*active_sessions {
                if now.duration_since(session.last_activity_time()) > expiry_time {
                    sessions_to_close.push(session_id.clone());
                }
            }
        }

        // Close expired sessions
        for session_id in sessions_to_close {
            if let Some(session) = self.get_session_by_id(&session_id).await {
                let _ = session.close().await;
                let _ = self.remove_session(&session_id).await;

                // Log expired session
                tracing::info!("Closed expired session {}", session_id);
            }
        }
    }
}

#[async_trait]
impl ConnectionManager for NetworkManager {
    async fn connect(
        &self,
        peer_id: &str,
        hints: ConnectionHints,
    ) -> Result<Box<dyn Session>, DsmError> {
        // Acquire connection lock to prevent concurrent connection attempts
        let lock = self.get_connection_lock(peer_id).await;
        let _guard = lock.lock().await;

        // Check if we already have an active session for this peer
        if let Some(session) = self.get_session_by_peer(peer_id).await {
            // Check session state
            let session_id = session.session_id().to_string();
            let session_states = self.session_states.read().await;

            if let Some(state) = session_states.get(&session_id) {
                match state {
                    SessionState::Active => {
                        // Reuse active session
                        return Ok(Box::new(SessionWrapper(session)));
                    }
                    SessionState::Establishing => {
                        // Retry with backoff
                        for i in 0..5 {
                            tokio::time::sleep(Duration::from_millis(100 * (1 << i))).await;

                            let session_states = self.session_states.read().await;
                            if let Some(state) = session_states.get(&session_id) {
                                if *state == SessionState::Active {
                                    return Ok(Box::new(SessionWrapper(session)));
                                }

                                if *state == SessionState::Closed {
                                    break;
                                }
                            }
                        }
                        // If we get here, return the session anyway
                        return Ok(Box::new(SessionWrapper(session)));
                    }
                    SessionState::Closing | SessionState::Closed => {
                        // Continue with new connection
                    }
                }
            }
        }

        // Get peer address
        let addr = hints.address.ok_or_else(|| {
            DsmError::network("Peer address not provided", None::<std::io::Error>)
        })?;

        // Find suitable transports
        let suitable_transports = self.find_suitable_transports(&hints).await;
        if suitable_transports.is_empty() {
            return Err(DsmError::network(
                "No suitable transport found",
                None::<std::io::Error>,
            ));
        }

        // Generate a temporary session ID for tracking
        let temp_session_id = Uuid::new_v4().to_string();

        // Set session state to establishing
        self.update_session_state(&temp_session_id, SessionState::Establishing)
            .await;

        // Try each transport until one succeeds
        let per_transport_timeout = hints.timeout_ms / suitable_transports.len() as u64;

        // Create a set of concurrent connection attempts
        let mut connection_attempts = Vec::new();
        for transport in &suitable_transports {
            let transport_clone = transport.clone();
            let attempt = self
                .try_connect_with_transport(transport_clone, addr, per_transport_timeout)
                .boxed();

            connection_attempts.push(attempt);
        }

        // Wait for the first successful connection or all failures
        let mut successful_connection = None;
        let mut errors = Vec::new();

        while !connection_attempts.is_empty() {
            let (result, _index, remaining) = select_all(connection_attempts).await;
            connection_attempts = remaining;

            match result {
                ConnectionAttemptResult::Success(connection) => {
                    successful_connection = Some(connection);
                    break;
                }
                ConnectionAttemptResult::Failure(e) => {
                    errors.push(e);
                }
            }
        }

        // If no successful connection, return the last error
        let connection = match successful_connection {
            Some(conn) => conn,
            None => {
                // Update session state to closed
                self.update_session_state(&temp_session_id, SessionState::Closed)
                    .await;

                return Err(errors.pop().unwrap_or_else(|| {
                    DsmError::network(
                        "Failed to connect using any available transport",
                        None::<std::io::Error>,
                    )
                }));
            }
        };

        // Create session
        let session = self.protocol.create_session(connection).await?;
        let session_arc = Arc::from(session);

        // Add session to internal state
        let session_wrapper = SessionWrapper(session_arc);
        let session_id = session_wrapper.session_id().to_string();
        let session_arc = self.add_session(peer_id, session_wrapper).await?;

        // Update session state
        self.update_session_state(&session_id, SessionState::Active)
            .await;

        // Return a boxed Session trait object
        Ok(Box::new(SessionWrapper(session_arc)))
    }
    async fn listen(&self, addr: SocketAddr) -> Result<(), DsmError> {
        let transports = self.transports.read().await;
        let protocol = self.protocol.clone();
        let self_ref = Arc::new(self.clone());

        for (transport_type, transport) in transports.iter() {
            let transport_clone = transport.clone();
            let protocol_clone = protocol.clone();
            let self_ref_clone = self_ref.clone();

            let bind_addr = match transport_type {
                TransportType::Tls => addr,
                TransportType::SecureUdp => addr,
                #[cfg(feature = "bluetooth")]
                TransportType::Bluetooth => addr,
            };

            tokio::spawn(async move {
                Self::listen_on_transport(
                    transport_clone,
                    protocol_clone,
                    self_ref_clone,
                    bind_addr,
                )
                .await;
            });
        }

        Ok(())
    }

    async fn get_active_sessions(&self) -> Vec<SessionInfo> {
        let active_sessions = self.active_sessions.read().await;
        let session_states = self.session_states.read().await;
        let session_peers = self.session_peers.read().await;
        let mut result = Vec::new();

        for (session_id, session) in active_sessions.iter() {
            if let Some(state) = session_states.get(session_id) {
                if *state == SessionState::Active || *state == SessionState::Establishing {
                    let peer_id = session_peers
                        .get(session_id)
                        .cloned()
                        .unwrap_or_else(|| "unknown".to_string());

                    result.push(SessionInfo {
                        session_id: session_id.clone(),
                        peer_id,
                        remote_addr: session.remote_addr(),
                        transport_type: session.transport_type(),
                        is_quantum_resistant: session.is_quantum_resistant(),
                        creation_time: session.creation_time(),
                        last_activity_time: session.last_activity_time(),
                        state: *state,
                    });
                }
            }
        }

        result
    }

    async fn disconnect(&self, peer_id: &str) -> Result<(), DsmError> {
        // Find sessions for the peer
        let session_ids = {
            let peer_sessions = self.peer_sessions.read().await;
            match peer_sessions.get(peer_id) {
                Some(sessions) => sessions.clone(),
                None => {
                    return Err(DsmError::network(
                        format!("No active sessions for peer {}", peer_id),
                        None::<std::io::Error>,
                    ))
                }
            }
        };

        // Close each session
        for session_id in &session_ids {
            // Mark session as closing
            self.update_session_state(session_id, SessionState::Closing)
                .await;

            // Get and close the session
            if let Some(session) = self.get_session_by_id(session_id).await {
                if let Err(e) = session.close().await {
                    tracing::warn!("Error closing session {}: {}", session_id, e);
                }
            }

            // Remove session
            if let Err(e) = self.remove_session(session_id).await {
                tracing::warn!("Error removing session {}: {}", session_id, e);
            }
        }

        Ok(())
    }

    async fn is_connected(&self, peer_id: &str) -> bool {
        // Check if peer has any active sessions
        if let Some(session) = self.get_session_by_peer(peer_id).await {
            let session_id = session.session_id().to_string();
            let session_states = self.session_states.read().await;

            if let Some(state) = session_states.get(&session_id) {
                return *state == SessionState::Active;
            }
        }

        false
    }

    async fn get_peer_by_session(&self, session_id: &str) -> Option<String> {
        let session_peers = self.session_peers.read().await;
        session_peers.get(session_id).cloned()
    }
}

impl std::fmt::Debug for NetworkManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetworkManager")
            .field("peer_sessions", &self.peer_sessions)
            .field("session_peers", &self.session_peers)
            .field("session_states", &self.session_states)
            .field("preferred_transports", &self.preferred_transports)
            .field(
                "require_quantum_resistance",
                &self.require_quantum_resistance,
            )
            .finish()
    }
}

impl Clone for NetworkManager {
    fn clone(&self) -> Self {
        Self {
            transports: self.transports.clone(),
            protocol: self.protocol.clone(),
            active_sessions: self.active_sessions.clone(),
            peer_sessions: self.peer_sessions.clone(),
            session_peers: self.session_peers.clone(),
            session_states: self.session_states.clone(),
            preferred_transports: self.preferred_transports.clone(),
            connection_locks: self.connection_locks.clone(),
            require_quantum_resistance: self.require_quantum_resistance.clone(),
        }
    }
}
