use super::{Transport, TransportConnection, TransportListener};
use crate::communication::generate_self_signed_cert;
use crate::communication::TransportType;
use crate::types::error::DsmError;
use async_trait::async_trait;
use rustls::{Certificate, ClientConfig, PrivateKey, ServerConfig};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{
    client::TlsStream as ClientTlsStream, server::TlsStream as ServerTlsStream, TlsAcceptor,
    TlsConnector,
};

/// TLS over TCP transport implementation
#[derive(Debug)]
pub struct TlsTransport {
    server_config: Option<Arc<ServerConfig>>,
    client_config: Arc<ClientConfig>,
}

impl TlsTransport {
    /// Create a new TLS transport
    pub fn new(cert_der: Vec<u8>, key_der: Vec<u8>) -> Result<Self, DsmError> {
        // Create a server config if key is provided
        let server_config = if !key_der.is_empty() {
            let server_config = Self::create_server_config(cert_der.clone(), key_der)?;
            Some(Arc::new(server_config))
        } else {
            None
        };

        // Always create a client config
        let client_config = Self::create_client_config(cert_der)?;

        Ok(Self {
            server_config,
            client_config: Arc::new(client_config),
        })
    }

    /// Initialize with self-signed certificate
    pub fn init() -> Result<Self, DsmError> {
        let cert = generate_self_signed_cert().map_err(|e| {
            DsmError::crypto(
                format!("Failed to generate certificate: {}", e),
                None::<std::io::Error>,
            )
        })?;

        let key_der = cert.serialize_private_key_der();
        let cert_der = cert.serialize_der().map_err(|e| {
            DsmError::crypto(
                format!("Failed to serialize certificate: {}", e),
                None::<std::io::Error>,
            )
        })?;

        Self::new(cert_der, key_der)
    }

    /// Create a rustls ServerConfig
    fn create_server_config(cert_der: Vec<u8>, key_der: Vec<u8>) -> Result<ServerConfig, DsmError> {
        let cert = Certificate(cert_der);
        let key = PrivateKey(key_der);

        // Create certificate chain
        let cert_chain = vec![cert];

        // Create server config with modern cipher suites
        let server_config = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .map_err(|e| {
                DsmError::crypto(
                    format!("Failed to create TLS server config: {}", e),
                    Some(e),
                )
            })?;

        Ok(server_config)
    }

    /// Create a rustls ClientConfig
    fn create_client_config(cert_der: Vec<u8>) -> Result<ClientConfig, DsmError> {
        // Create certificate store
        let mut root_cert_store = rustls::RootCertStore::empty();

        // Add certificate to trust store
        let cert = Certificate(cert_der.clone());
        root_cert_store.add(&cert).map_err(|e| {
            DsmError::crypto(
                format!("Failed to add certificate to trust store: {}", e),
                Some(e),
            )
        })?;

        // Create client config with modern cipher suites
        let client_config = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_cert_store)
            .with_no_client_auth();

        Ok(client_config)
    }
}

#[async_trait]
impl Transport for TlsTransport {
    async fn connect(&self, addr: SocketAddr) -> Result<Box<dyn TransportConnection>, DsmError> {
        // Connect with TCP with timeout
        let tcp_stream = TcpStream::connect(addr).await.map_err(|e| {
            DsmError::network(format!("Failed to connect TCP socket: {}", e), Some(e))
        })?;

        let local_addr = tcp_stream.local_addr().map_err(|e| {
            DsmError::network(format!("Failed to get local address: {}", e), Some(e))
        })?;

        // Set socket options for better performance
        tcp_stream
            .set_nodelay(true)
            .map_err(|e| DsmError::network(format!("Failed to set TCP_NODELAY: {}", e), Some(e)))?;

        // Convert address to DNS name (using synthetic name for IP addresses)
        let server_name = rustls::ServerName::try_from("dsm.local")
            .map_err(|_| DsmError::validation("Invalid server name", None::<std::io::Error>))?;

        // Create TLS connector
        let connector = TlsConnector::from(self.client_config.clone());

        // Perform TLS handshake
        let tls_stream = connector
            .connect(server_name, tcp_stream)
            .await
            .map_err(|e| DsmError::network(format!("TLS handshake failed: {}", e), Some(e)))?;

        // Create TLS connection
        Ok(Box::new(TlsConnection {
            stream: Arc::new(tokio::sync::Mutex::new(tls_stream)),
            remote_addr: addr,
            local_addr,
        }))
    }

    async fn bind(&self, addr: SocketAddr) -> Result<Box<dyn TransportListener>, DsmError> {
        // Ensure server config is available
        let server_config = self.server_config.clone().ok_or_else(|| {
            DsmError::validation(
                "Server certificate and key required for TLS listener",
                None::<std::io::Error>,
            )
        })?;

        // Create TCP listener
        let tcp_listener = TcpListener::bind(addr)
            .await
            .map_err(|e| DsmError::network(format!("Failed to bind to address: {}", e), Some(e)))?;

        let local_addr = tcp_listener.local_addr().map_err(|e| {
            DsmError::network(format!("Failed to get local address: {}", e), Some(e))
        })?;

        // Create TLS acceptor
        let tls_acceptor = TlsAcceptor::from(server_config);

        // Create TLS listener
        Ok(Box::new(TlsListener {
            listener: tcp_listener,
            acceptor: tls_acceptor,
            local_addr,
        }))
    }

    fn transport_type(&self) -> TransportType {
        TransportType::Tls
    }

    fn is_quantum_resistant(&self) -> bool {
        // TLS 1.3 with standard ciphersuites is not quantum resistant
        false
    }

    fn supports_offline(&self) -> bool {
        // TLS requires an active network connection
        false
    }
}

/// TLS connection implementation for client-side connections
/// Uses ClientTlsStream for the underlying tokio-rustls stream
#[derive(Debug)]
pub struct TlsConnection {
    stream: Arc<tokio::sync::Mutex<ClientTlsStream<TcpStream>>>,
    remote_addr: SocketAddr,
    local_addr: SocketAddr,
}

#[async_trait]
impl TransportConnection for TlsConnection {
    async fn send(&self, data: &[u8]) -> Result<(), DsmError> {
        // First send the length as u32 BE
        let len = data.len() as u32;
        let len_bytes = len.to_be_bytes();

        // Get mutable reference to the stream
        let mut stream = self.stream.lock().await;

        // Write length
        stream.write_all(&len_bytes).await.map_err(|e| {
            DsmError::network(format!("Failed to send data length: {}", e), Some(e))
        })?;

        // Write data
        stream
            .write_all(data)
            .await
            .map_err(|e| DsmError::network(format!("Failed to send data: {}", e), Some(e)))?;

        Ok(())
    }

    async fn receive(&self) -> Result<Vec<u8>, DsmError> {
        // Get mutable reference to the stream
        let mut stream = self.stream.lock().await;

        // Read length (u32 BE)
        let mut len_bytes = [0u8; 4];
        stream.read_exact(&mut len_bytes).await.map_err(|e| {
            if e.kind() == io::ErrorKind::UnexpectedEof {
                return DsmError::network("Connection closed", Some(e));
            }
            DsmError::network(format!("Failed to read data length: {}", e), Some(e))
        })?;

        let len = u32::from_be_bytes(len_bytes) as usize;

        // Sanity check for message size
        if len > 16 * 1024 * 1024 {
            // 16 MB hard limit
            return Err(DsmError::validation(
                format!("Message too large: {} bytes", len),
                None::<std::io::Error>,
            ));
        }

        // Read data
        let mut buffer = vec![0u8; len];
        stream
            .read_exact(&mut buffer)
            .await
            .map_err(|e| DsmError::network(format!("Failed to read data: {}", e), Some(e)))?;

        Ok(buffer)
    }

    async fn close(&self) -> Result<(), DsmError> {
        // Get mutable reference to the stream
        let mut stream = self.stream.lock().await;

        // Attempt a clean shutdown
        match stream.shutdown().await {
            Ok(_) => Ok(()),
            Err(e) => {
                // Log but don't fail on shutdown errors
                tracing::warn!("Error shutting down TLS connection: {}", e);
                Ok(())
            }
        }
    }

    fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    fn transport_type(&self) -> TransportType {
        TransportType::Tls
    }
}

impl Clone for TlsConnection {
    fn clone(&self) -> Self {
        Self {
            stream: self.stream.clone(),
            remote_addr: self.remote_addr,
            local_addr: self.local_addr,
        }
    }
}

/// TLS server connection implementation for server-side connections
/// Uses ServerTlsStream for the underlying tokio-rustls stream
#[derive(Debug)]
pub struct TlsServerConnection {
    stream: Arc<tokio::sync::Mutex<ServerTlsStream<TcpStream>>>,
    remote_addr: SocketAddr,
    local_addr: SocketAddr,
}

#[async_trait]
impl TransportConnection for TlsServerConnection {
    async fn send(&self, data: &[u8]) -> Result<(), DsmError> {
        // First send the length as u32 BE
        let len = data.len() as u32;
        let len_bytes = len.to_be_bytes();

        // Get mutable reference to inner TCP stream
        let mut stream = self.stream.lock().await;

        // Write length
        stream.write_all(&len_bytes).await.map_err(|e| {
            DsmError::network(format!("Failed to send data length: {}", e), Some(e))
        })?;

        // Write data
        stream
            .write_all(data)
            .await
            .map_err(|e| DsmError::network(format!("Failed to send data: {}", e), Some(e)))?;

        Ok(())
    }

    async fn receive(&self) -> Result<Vec<u8>, DsmError> {
        // Get mutable reference to the TLS stream
        let mut stream = self.stream.lock().await;

        // Read length (u32 BE)
        let mut len_bytes = [0u8; 4];
        stream.read_exact(&mut len_bytes).await.map_err(|e| {
            if e.kind() == io::ErrorKind::UnexpectedEof {
                return DsmError::network("Connection closed", Some(e));
            }
            DsmError::network(format!("Failed to read data length: {}", e), Some(e))
        })?;

        let len = u32::from_be_bytes(len_bytes) as usize;

        // Sanity check for message size
        if len > 16 * 1024 * 1024 {
            // 16 MB hard limit
            return Err(DsmError::validation(
                format!("Message too large: {} bytes", len),
                None::<std::io::Error>,
            ));
        }

        // Read data
        let mut buffer = vec![0u8; len];
        stream
            .read_exact(&mut buffer)
            .await
            .map_err(|e| DsmError::network(format!("Failed to read data: {}", e), Some(e)))?;

        Ok(buffer)
    }

    async fn close(&self) -> Result<(), DsmError> {
        // Get mutable reference to underlying TCP stream
        let mut stream = self.stream.lock().await;

        // Attempt a clean shutdown
        match stream.shutdown().await {
            Ok(_) => Ok(()),
            Err(e) => {
                // Log but don't fail on shutdown errors
                tracing::warn!("Error shutting down TLS connection: {}", e);
                Ok(())
            }
        }
    }

    fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    fn transport_type(&self) -> TransportType {
        TransportType::Tls
    }
}

impl Clone for TlsServerConnection {
    fn clone(&self) -> Self {
        Self {
            stream: self.stream.clone(),
            remote_addr: self.remote_addr,
            local_addr: self.local_addr,
        }
    }
}

/// TLS listener implementation
pub struct TlsListener {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    local_addr: SocketAddr,
}

impl std::fmt::Debug for TlsListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsListener")
            .field("local_addr", &self.local_addr)
            .field("acceptor", &"TlsAcceptor { ... }")
            .finish()
    }
}

#[async_trait]
impl TransportListener for TlsListener {
    async fn accept(&self) -> Result<Box<dyn TransportConnection>, DsmError> {
        // Accept TCP connection
        let (tcp_stream, remote_addr) = self.listener.accept().await.map_err(|e| {
            DsmError::network(format!("Failed to accept TCP connection: {}", e), Some(e))
        })?;

        let local_addr = tcp_stream.local_addr().map_err(|e| {
            DsmError::network(format!("Failed to get local address: {}", e), Some(e))
        })?;

        // Set socket options for better performance
        tcp_stream
            .set_nodelay(true)
            .map_err(|e| DsmError::network(format!("Failed to set TCP_NODELAY: {}", e), Some(e)))?;

        // Perform TLS handshake
        let tls_stream = self
            .acceptor
            .accept(tcp_stream)
            .await
            .map_err(|e| DsmError::network(format!("TLS handshake failed: {}", e), Some(e)))?;

        // Create TLS connection
        Ok(Box::new(TlsServerConnection {
            stream: Arc::new(tokio::sync::Mutex::new(tls_stream)),
            remote_addr,
            local_addr,
        }))
    }

    fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    async fn close(&self) -> Result<(), DsmError> {
        // No explicit close method for TcpListener, it will be closed when dropped
        Ok(())
    }

    fn transport_type(&self) -> TransportType {
        TransportType::Tls
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::runtime::Runtime;

    /// Helper function to generate test certificates with proper key usage extensions
    fn generate_test_certificates() -> (Vec<u8>, Vec<u8>) {
        // Create a server certificate with appropriate parameters
        let mut params = rcgen::CertificateParams::default();
        params.subject_alt_names = vec![
            rcgen::SanType::DnsName("localhost".to_string()),
            rcgen::SanType::DnsName("dsm.local".to_string()),
            rcgen::SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))),
        ];

        // Set appropriate certificate fields
        let mut distinguished_name = rcgen::DistinguishedName::new();
        distinguished_name.push(rcgen::DnType::CommonName, "dsm.local");
        distinguished_name.push(rcgen::DnType::OrganizationName, "DSM Test");
        params.distinguished_name = distinguished_name;

        // Set key usage for server certificate
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::KeyEncipherment,
        ];

        // Set extended key usage for server and client authentication
        params.extended_key_usages = vec![
            rcgen::ExtendedKeyUsagePurpose::ServerAuth,
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
        ];

        // Set certificate validity period using time crate
        use time::{Duration, OffsetDateTime};
        let now = OffsetDateTime::now_utc();
        params.not_before = now - Duration::days(1);
        params.not_after = now + Duration::days(365);

        // Generate self-signed certificate (no need for CA in tests)
        let cert = rcgen::Certificate::from_params(params).unwrap();

        let cert_der = cert.serialize_der().unwrap();
        let key_der = cert.serialize_private_key_der();

        (cert_der, key_der)
    }

    #[test]
    fn test_tls_transport() {
        let rt = Runtime::new().unwrap();

        rt.block_on(async {
            // Generate certificates (server cert and private key)
            let (server_cert_der, server_key_der) = generate_test_certificates();

            // Create server-side transport with the server certificate and key
            let server_transport = TlsTransport::new(
                server_cert_der.clone(), // Server certificate
                server_key_der,          // Server private key
            )
            .expect("Failed to create server transport");

            // Bind the server to a local address
            let server = server_transport
                .bind(([127, 0, 0, 1], 0).into())
                .await
                .expect("Failed to bind server transport");

            let server_addr = server.local_addr();

            // Spawn server accept task
            let server_handle = tokio::spawn(async move {
                match server.accept().await {
                    Ok(conn) => {
                        println!("Server accepted connection");
                        Some(conn)
                    }
                    Err(e) => {
                        eprintln!("Server accept error: {:?}", e);
                        None
                    }
                }
            });

            // Allow time for server to start
            tokio::time::sleep(Duration::from_millis(100)).await;

            // Create client transport using the server cert as the trusted root
            // Don't provide a key since the client doesn't need one for this test
            let client_transport = TlsTransport::new(
                server_cert_der.clone(), // Use server certificate as trusted root
                Vec::new(),              // Empty key for client-only mode
            )
            .expect("Failed to create client transport");

            // Connect to server
            println!("Client connecting to {}...", server_addr);
            let client_conn = match client_transport.connect(server_addr).await {
                Ok(conn) => {
                    println!("Client connection established");
                    conn
                }
                Err(e) => {
                    panic!("Client connection failed: {:?}", e);
                }
            };

            // Wait for server to accept
            let server_conn = match server_handle.await {
                Ok(Some(conn)) => {
                    println!("Server connection available");
                    conn
                }
                Ok(None) => panic!("Server failed to accept connection"),
                Err(e) => panic!("Server task panicked: {}", e),
            };

            // Test sending data from client to server
            let test_data = b"Hello, secure world!";
            client_conn
                .send(test_data)
                .await
                .expect("Failed to send data");

            // Receive data on server
            let received = server_conn.receive().await.expect("Failed to receive data");
            assert_eq!(received, test_data);

            // Test bidirectional communication
            let test_data_client = b"Hello from client!";
            client_conn
                .send(test_data_client)
                .await
                .expect("Failed to send client data");

            let received_by_server = server_conn
                .receive()
                .await
                .expect("Failed to receive client data");
            assert_eq!(&received_by_server, test_data_client);

            // Test server to client communication
            let test_data_server = b"Hello from server!";
            server_conn
                .send(test_data_server)
                .await
                .expect("Failed to send server data");

            let received_by_client = client_conn
                .receive()
                .await
                .expect("Failed to receive server data");
            assert_eq!(&received_by_client, test_data_server);

            // Clean up
            client_conn
                .close()
                .await
                .expect("Failed to close client connection");
            server_conn
                .close()
                .await
                .expect("Failed to close server connection");
        });
    }

    // Add a stress test for multiple simultaneous connections
    #[test]
    #[ignore] // Only run manually with --ignored flag
    fn test_tls_multiple_connections() {
        let rt = Runtime::new().unwrap();

        rt.block_on(async {
            // Generate certificates
            let (server_cert_der, server_key_der) = generate_test_certificates();

            // Create server transport
            let server_transport = TlsTransport::new(server_cert_der.clone(), server_key_der)
                .expect("Failed to create server transport");

            // Bind server
            let server = server_transport
                .bind(([127, 0, 0, 1], 0).into())
                .await
                .expect("Failed to bind server");

            let server_addr = server.local_addr();

            // Number of clients to test
            let client_count = 5;

            // Spawn server handler
            let server_handle = tokio::spawn(async move {
                let mut handles = Vec::new();

                for _ in 0..client_count {
                    let connection = match server.accept().await {
                        Ok(conn) => conn,
                        Err(e) => {
                            eprintln!("Server accept error: {:?}", e);
                            continue;
                        }
                    };

                    let handle = tokio::spawn(async move {
                        // Echo server
                        let data = connection.receive().await.expect("Failed to receive data");
                        connection.send(&data).await.expect("Failed to send data");
                    });

                    handles.push(handle);
                }

                futures::future::join_all(handles).await;
            });

            // Create and connect multiple clients
            let mut client_handles = Vec::new();
            for i in 0..client_count {
                let cert_der = server_cert_der.clone();

                let client_handle = tokio::spawn(async move {
                    // Create client transport
                    let client_transport = TlsTransport::new(cert_der, Vec::new())
                        .expect("Failed to create client transport");

                    // Connect to server
                    let client_conn = client_transport
                        .connect(server_addr)
                        .await
                        .expect("Failed to connect to server");

                    // Test data specific to this client
                    let test_data = format!("Hello from client {}!", i).into_bytes();

                    // Send data
                    client_conn
                        .send(&test_data)
                        .await
                        .expect("Failed to send data");

                    // Receive echo
                    let echo_data = client_conn.receive().await.expect("Failed to receive data");

                    // Verify echo
                    assert_eq!(echo_data, test_data);

                    // Close connection
                    client_conn
                        .close()
                        .await
                        .expect("Failed to close connection");
                });

                client_handles.push(client_handle);
            }

            // Wait for all clients to complete
            futures::future::join_all(client_handles).await;

            // Cancel server handle - it might be waiting for more connections
            server_handle.abort();
        });
    }
}
