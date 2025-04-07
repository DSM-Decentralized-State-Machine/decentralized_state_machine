use crate::communication::TransportType;
use crate::types::error::DsmError;
use async_trait::async_trait;
use std::net::SocketAddr;

/// Core transport abstraction for underlying network connection
#[async_trait]
pub trait Transport: Send + Sync {
    /// Connect to a remote peer
    async fn connect(&self, addr: SocketAddr) -> Result<Box<dyn TransportConnection>, DsmError>;

    /// Create a listener to accept incoming connections
    async fn bind(&self, addr: SocketAddr) -> Result<Box<dyn TransportListener>, DsmError>;

    /// Get the transport type
    fn transport_type(&self) -> TransportType;

    /// Check if transport supports quantum resistance
    fn is_quantum_resistant(&self) -> bool;

    /// Check if transport supports offline operation
    fn supports_offline(&self) -> bool;
}

/// Connection abstraction for peer-to-peer communication
#[async_trait]
pub trait TransportConnection: Send + Sync + TransportConnectionClone + std::fmt::Debug {
    /// Send raw bytes to the peer
    async fn send(&self, data: &[u8]) -> Result<(), DsmError>;

    /// Receive raw bytes from the peer
    async fn receive(&self) -> Result<Vec<u8>, DsmError>;

    /// Close the connection
    async fn close(&self) -> Result<(), DsmError>;

    /// Get the remote peer's address
    fn remote_addr(&self) -> SocketAddr;

    /// Get the local address for this connection
    fn local_addr(&self) -> SocketAddr;

    /// Get the transport type
    fn transport_type(&self) -> TransportType;
}

/// Extension trait for cloning transport connections
pub trait TransportConnectionClone {
    /// Create a boxed clone of this connection
    fn clone_box(&self) -> Box<dyn TransportConnection>;
}

impl<T> TransportConnectionClone for T
where
    T: 'static + TransportConnection + Clone,
{
    fn clone_box(&self) -> Box<dyn TransportConnection> {
        Box::new(self.clone())
    }
}

/// Allow cloning of boxed transport connections via the extension trait
impl Clone for Box<dyn TransportConnection> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}

/// Listener abstraction for accepting incoming connections
#[async_trait]
pub trait TransportListener: Send + Sync {
    /// Accept an incoming connection
    async fn accept(&self) -> Result<Box<dyn TransportConnection>, DsmError>;

    /// Get the local address this listener is bound to
    fn local_addr(&self) -> SocketAddr;

    /// Close the listener
    async fn close(&self) -> Result<(), DsmError>;

    /// Get the transport type
    fn transport_type(&self) -> TransportType;
}

// Export optimized transport implementations
pub mod secure_udp;
pub mod tls;

// Optional transport modules
#[cfg(feature = "bluetooth")]
pub mod bluetooth_connect;

// Re-export transport implementations
pub use secure_udp::SecureUdpTransport;
pub use tls::TlsTransport;

#[cfg(feature = "bluetooth")]
pub use bluetooth_connect::BluetoothTransport;

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    struct MockTransport {}
    #[derive(Debug, Clone)]
    struct MockConnection {}
    struct MockListener {}

    #[async_trait]
    impl Transport for MockTransport {
        async fn connect(
            &self,
            _addr: SocketAddr,
        ) -> Result<Box<dyn TransportConnection>, DsmError> {
            Ok(Box::new(MockConnection {}))
        }

        async fn bind(&self, _addr: SocketAddr) -> Result<Box<dyn TransportListener>, DsmError> {
            Ok(Box::new(MockListener {}))
        }

        fn transport_type(&self) -> TransportType {
            TransportType::Tls
        }

        fn is_quantum_resistant(&self) -> bool {
            false
        }

        fn supports_offline(&self) -> bool {
            false
        }
    }

    #[async_trait]
    impl TransportConnection for MockConnection {
        async fn send(&self, _data: &[u8]) -> Result<(), DsmError> {
            Ok(())
        }

        async fn receive(&self) -> Result<Vec<u8>, DsmError> {
            Ok(vec![1, 2, 3])
        }

        async fn close(&self) -> Result<(), DsmError> {
            Ok(())
        }

        fn remote_addr(&self) -> SocketAddr {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080)
        }

        fn local_addr(&self) -> SocketAddr {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8081)
        }

        fn transport_type(&self) -> TransportType {
            TransportType::Tls
        }
    }

    #[async_trait]
    impl TransportListener for MockListener {
        async fn accept(&self) -> Result<Box<dyn TransportConnection>, DsmError> {
            Ok(Box::new(MockConnection {}))
        }

        fn local_addr(&self) -> SocketAddr {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8081)
        }

        async fn close(&self) -> Result<(), DsmError> {
            Ok(())
        }

        fn transport_type(&self) -> TransportType {
            TransportType::Tls
        }
    }

    #[tokio::test]
    async fn test_transport_connect() {
        let transport = MockTransport {};
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);

        let conn = transport.connect(addr).await.unwrap();
        assert_eq!(conn.remote_addr(), addr);
        assert_eq!(conn.transport_type(), TransportType::Tls);
    }

    #[tokio::test]
    async fn test_transport_bind() {
        let transport = MockTransport {};
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8081);

        let listener = transport.bind(addr).await.unwrap();
        assert_eq!(listener.local_addr(), addr);
        assert_eq!(listener.transport_type(), TransportType::Tls);
    }

    #[tokio::test]
    async fn test_connection_clone() {
        let transport = MockTransport {};
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);

        let conn = transport.connect(addr).await.unwrap();
        let cloned = conn.clone();

        assert_eq!(conn.remote_addr(), cloned.remote_addr());
        assert_eq!(conn.transport_type(), cloned.transport_type());
    }
}
