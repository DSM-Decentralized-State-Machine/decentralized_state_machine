use crate::communication::transport::TransportConnection;
use crate::communication::TransportType;
use crate::types::error::DsmError;
use async_trait::async_trait;
use std::net::SocketAddr;

/// Protocol message types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    /// Handshake initialization
    Handshake = 0,
    /// Handshake response
    HandshakeResponse = 1,
    /// Regular data message
    Data = 2,
    /// Ping request
    Ping = 3,
    /// Pong response
    Pong = 4,
    /// Session closure
    Close = 5,
    /// Acknowledgment
    Ack = 6,
    /// Multi-part message (fragment)
    Fragment = 7,
    /// Error notification
    Error = 8,
}

/// Protocol message structure
#[derive(Debug, Clone)]
pub struct Message {
    /// Message type
    message_type: MessageType,
    /// Sequence number for ordering and deduplication
    sequence_number: u64,
    /// Message flags
    flags: u16,
    /// Message timestamp (milliseconds since Unix epoch)
    timestamp: u64,
    /// Message payload
    data: Vec<u8>,
}

impl Message {
    /// Create a new message
    pub fn new(message_type: MessageType, data: Vec<u8>) -> Self {
        Self {
            message_type,
            sequence_number: 0, // Will be set by session
            data,
            flags: 0,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
        }
    }

    /// Get the message type
    pub fn message_type(&self) -> MessageType {
        self.message_type
    }

    /// Get the sequence number
    pub fn sequence_number(&self) -> u64 {
        self.sequence_number
    }

    /// Set the sequence number
    pub fn set_sequence_number(&mut self, seq: u64) {
        self.sequence_number = seq;
    }

    /// Get the message flags
    pub fn flags(&self) -> u16 {
        self.flags
    }

    /// Set the message flags
    pub fn set_flags(&mut self, flags: u16) {
        self.flags = flags;
    }

    /// Get the message timestamp
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    /// Get the message data
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Consume the message and return its data
    pub fn into_data(self) -> Vec<u8> {
        self.data
    }

    /// Serialize message to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(
            1 + // message type
            8 + // sequence number
            2 + // flags
            8 + // timestamp
            4 + // data length
            self.data.len(),
        );

        buffer.push(self.message_type as u8);
        buffer.extend_from_slice(&self.sequence_number.to_be_bytes());
        buffer.extend_from_slice(&self.flags.to_be_bytes());
        buffer.extend_from_slice(&self.timestamp.to_be_bytes());
        buffer.extend_from_slice(&(self.data.len() as u32).to_be_bytes());
        buffer.extend_from_slice(&self.data);

        buffer
    }

    /// Deserialize message from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DsmError> {
        if bytes.len() < 23 {
            // 1 + 8 + 2 + 8 + 4
            return Err(DsmError::serialization(
                "Message too short for header",
                None::<std::convert::Infallible>,
            ));
        }

        let message_type = match bytes[0] {
            0 => MessageType::Handshake,
            1 => MessageType::HandshakeResponse,
            2 => MessageType::Data,
            3 => MessageType::Ping,
            4 => MessageType::Pong,
            5 => MessageType::Close,
            6 => MessageType::Ack,
            7 => MessageType::Fragment,
            8 => MessageType::Error,
            _ => {
                return Err(DsmError::serialization(
                    format!("Unknown message type: {}", bytes[0]),
                    None::<std::convert::Infallible>,
                ))
            }
        };

        let sequence_number = u64::from_be_bytes([
            bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8],
        ]);

        let flags = u16::from_be_bytes([bytes[9], bytes[10]]);

        let timestamp = u64::from_be_bytes([
            bytes[11], bytes[12], bytes[13], bytes[14], bytes[15], bytes[16], bytes[17], bytes[18],
        ]);

        let data_len = u32::from_be_bytes([bytes[19], bytes[20], bytes[21], bytes[22]]) as usize;

        if bytes.len() < 23 + data_len {
            return Err(DsmError::serialization(
                "Message too short for data",
                None::<std::convert::Infallible>,
            ));
        }

        let data = bytes[23..23 + data_len].to_vec();

        Ok(Self {
            message_type,
            sequence_number,
            flags,
            timestamp,
            data,
        })
    }
}

/// Session configuration
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Maximum inactive time before session is considered expired (ms)
    pub session_timeout_ms: u64,
    /// Keep-alive interval (ms)
    pub keepalive_interval_ms: u64,
    /// Maximum message size
    pub max_message_size: usize,
    /// Whether to enable reliability features for unreliable transports
    pub enable_reliability: bool,
    /// Maximum retransmission attempts
    pub max_retries: u32,
    /// Retry interval (ms)
    pub retry_interval_ms: u64,
    /// Maximum number of tracked sequence numbers for deduplication
    pub max_tracked_sequences: usize,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            session_timeout_ms: 60000,     // 1 minute
            keepalive_interval_ms: 30000,  // 30 seconds
            max_message_size: 1024 * 1024, // 1MB
            enable_reliability: true,
            max_retries: 5,
            retry_interval_ms: 500, // 500ms
            max_tracked_sequences: 1000,
        }
    }
}

/// Session trait for active communication channels
#[async_trait]
pub trait Session: Send + Sync {
    /// Send a message to the remote peer
    async fn send_message(&self, message: Message) -> Result<(), DsmError>;

    /// Receive a message from the remote peer
    /// Returns None if no message is immediately available
    async fn receive_message(&self) -> Result<Message, DsmError>;

    /// Close the session
    async fn close(&self) -> Result<(), DsmError>;

    /// Get the remote peer's address
    fn remote_addr(&self) -> SocketAddr;

    /// Get the session ID
    fn session_id(&self) -> &str;

    /// Get the transport type
    fn transport_type(&self) -> TransportType;

    /// Check if the session supports quantum resistance
    fn is_quantum_resistant(&self) -> bool;

    /// Check if the session is active
    fn is_active(&self) -> bool;

    /// Get the session creation time
    fn creation_time(&self) -> std::time::Instant;

    /// Get the last activity time
    fn last_activity_time(&self) -> std::time::Instant;
}

/// Protocol trait for session establishment and management
#[async_trait]
pub trait Protocol: Send + Sync {
    /// Create a session using the provided transport connection
    async fn create_session(
        &self,
        transport: Box<dyn TransportConnection>,
    ) -> Result<Box<dyn Session>, DsmError>;

    /// Accept an incoming session from the provided transport connection
    async fn accept_session(
        &self,
        transport: Box<dyn TransportConnection>,
    ) -> Result<Box<dyn Session>, DsmError>;

    /// Get the protocol identifier
    fn protocol_id(&self) -> &'static str;

    /// Check if the protocol supports quantum resistance
    fn is_quantum_resistant(&self) -> bool;
}

/// Reliable messaging implementation for unreliable transports
pub struct ReliabilityLayer {
    /// Session configuration parameters that influence reliability behavior
    ///
    /// Contains timing parameters, retry policies, and protocol-specific settings
    /// that govern the communication reliability mechanisms. This field is part of
    /// the reliability layer's state model even when not directly accessed in
    /// certain code paths.
    #[allow(dead_code)]
    config: SessionConfig,
}

impl ReliabilityLayer {
    /// Create a new reliability layer with the given configuration
    pub fn new(config: SessionConfig) -> Self {
        Self { config }
    }

    /// Prepare a message for reliable transmission
    pub fn prepare_message(&self, mut message: Message, sequence_number: u64) -> Message {
        message.set_sequence_number(sequence_number);
        message
    }

    /// Create an acknowledgment message for the given sequence number
    pub fn create_ack(&self, sequence_number: u64) -> Message {
        let mut ack_data = vec![0u8; 8];
        ack_data.copy_from_slice(&sequence_number.to_be_bytes());
        Message::new(MessageType::Ack, ack_data)
    }

    /// Extract the acknowledged sequence number from an ack message
    pub fn extract_ack_sequence(&self, ack: &Message) -> Result<u64, DsmError> {
        if ack.message_type() != MessageType::Ack {
            return Err(DsmError::validation(
                "Not an acknowledgment message",
                None::<std::convert::Infallible>,
            ));
        }

        if ack.data().len() < 8 {
            return Err(DsmError::validation(
                "Ack message too short",
                None::<std::convert::Infallible>,
            ));
        }

        let seq = u64::from_be_bytes([
            ack.data()[0],
            ack.data()[1],
            ack.data()[2],
            ack.data()[3],
            ack.data()[4],
            ack.data()[5],
            ack.data()[6],
            ack.data()[7],
        ]);

        Ok(seq)
    }
}

// Export protocol implementations
pub mod dsm_protocol;

// Re-export protocol implementations
pub use dsm_protocol::DsmProtocol;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_serialization() {
        let data = vec![1, 2, 3, 4];
        let mut msg = Message::new(MessageType::Data, data.clone());
        msg.set_sequence_number(42);
        msg.set_flags(0x1234);

        let bytes = msg.to_bytes();
        let deserialized = Message::from_bytes(&bytes).unwrap();

        assert_eq!(deserialized.message_type(), MessageType::Data);
        assert_eq!(deserialized.sequence_number(), 42);
        assert_eq!(deserialized.flags(), 0x1234);
        assert_eq!(deserialized.data(), &data);
    }

    #[test]
    fn test_message_invalid_type() {
        let mut invalid = vec![255u8]; // Invalid message type
        invalid.extend_from_slice(&[0u8; 22]); // Add dummy header data
        assert!(Message::from_bytes(&invalid).is_err());
    }

    #[test]
    fn test_message_too_short() {
        let short_msg = vec![0u8; 10];
        assert!(Message::from_bytes(&short_msg).is_err());
    }

    #[test]
    fn test_reliability_layer() {
        let config = SessionConfig::default();
        let reliability = ReliabilityLayer::new(config);

        let msg = Message::new(MessageType::Data, vec![1, 2, 3]);
        let prepared = reliability.prepare_message(msg, 123);
        assert_eq!(prepared.sequence_number(), 123);

        let ack = reliability.create_ack(456);
        assert_eq!(ack.message_type(), MessageType::Ack);
        assert_eq!(reliability.extract_ack_sequence(&ack).unwrap(), 456);
    }

    #[test]
    fn test_invalid_ack() {
        let config = SessionConfig::default();
        let reliability = ReliabilityLayer::new(config);

        let invalid_msg = Message::new(MessageType::Data, vec![]);
        assert!(reliability.extract_ack_sequence(&invalid_msg).is_err());

        let short_ack = Message::new(MessageType::Ack, vec![1, 2, 3]);
        assert!(reliability.extract_ack_sequence(&short_ack).is_err());
    }

    #[test]
    fn test_session_config_defaults() {
        let config = SessionConfig::default();
        assert_eq!(config.session_timeout_ms, 60000);
        assert_eq!(config.keepalive_interval_ms, 30000);
        assert_eq!(config.max_message_size, 1024 * 1024);
        assert!(config.enable_reliability);
        assert_eq!(config.max_retries, 5);
        assert_eq!(config.retry_interval_ms, 500);
        assert_eq!(config.max_tracked_sequences, 1000);
    }
}
