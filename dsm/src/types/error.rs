use std::{error::Error, fmt::Display};

/// Comprehensive error type for DSM operations
///
/// This enumeration encapsulates all possible error conditions that may arise during
/// the operation of the Decentralized State Machine. It represents a unified error
/// handling strategy across all modules, ensuring consistency and facilitating
/// proper error propagation throughout the application architecture.
#[derive(Debug)]
pub enum DsmError {
    /// Cryptographic operation errors
    ///
    /// Represents errors occurring during cryptographic operations such as hashing,
    /// signing, verification, or key management.
    Crypto {
        /// Contextual description of the error
        context: String,
        /// Optional source error that caused this error
        source: Option<Box<dyn Error + Send + Sync>>,
    },
    /// Integrity check failures
    ///
    /// Occurs when data integrity verification fails
    Integrity {
        /// Description of the integrity error
        context: String,
        /// Optional source error that caused this error
        source: Option<Box<dyn Error + Send + Sync>>,
    },
    /// Invalid public key error
    ///
    /// Occurs when an operation receives or attempts to use an invalid public key.
    InvalidPublicKey,

    /// Invalid secret/private key error
    ///
    /// Occurs when an operation attempts to use an invalid secret or private key.
    InvalidSecretKey,

    /// Storage-related errors
    ///
    /// Represents errors related to persistent storage operations.
    Storage {
        /// Description of the storage error
        context: String,
        /// Optional source error that caused this error
        source: Option<Box<dyn Error + Send + Sync>>,
    },

    /// Network-related errors
    ///
    /// Represents errors occurring during network operations or communications.
    Network {
        /// Description of the network error
        context: String,
        /// Optional source error that caused this error
        source: Option<Box<dyn Error + Send + Sync>>,
        entity: String,
        details: Option<String>,
    },
    /// Ivalid key length error
    /// Occurs when an operation receives or attempts to use an invalid key length.
    InvalidKeyLength,
    /// State machine errors
    ///
    /// Represents errors related to state transitions or state validation.
    StateMachine(String),

    /// Entity not found errors
    ///
    /// Occurs when attempting to access or operate on an entity that does not exist.
    NotFound {
        /// The type of entity that was not found
        entity: String,
        /// Additional details about the lookup
        details: Option<String>,
        /// Context of the error
        context: String,
        /// Optional source error
        source: Option<Box<dyn Error + Send + Sync>>,
    },

    /// Internal implementation errors
    ///
    /// Represents errors due to internal implementation issues such as mutex failures,
    /// unexpected conditions, or implementation inconsistencies.
    Internal {
        /// Description of the internal error
        context: String,
        /// Optional source error that caused this error
        source: Option<Box<dyn Error + Send + Sync>>,
    },

    /// Validation errors
    ///
    /// Represents errors related to validation of input, parameters, or state.
    Validation {
        /// Description of the validation error
        context: String,
        /// Optional source error that caused this error
        source: Option<Box<dyn Error + Send + Sync>>,
    },

    /// Invalid parameter errors
    ///
    /// Occurs when an operation receives an invalid parameter.
    InvalidParameter(String),

    /// Serialization/deserialization errors
    ///
    /// Represents errors occurring during serialization or deserialization of data.
    Serialization {
        /// Description of the serialization error
        context: String,
        /// Optional source error that caused this error
        source: Option<Box<dyn Error + Send + Sync>>,
        entity: String,
        details: Option<String>,
    },

    /// Verification failures
    ///
    /// Occurs when a verification operation fails, such as hash chain or signature verification.
    Verification(String),

    /// State-specific errors
    ///
    /// Represents errors related to state operations or state integrity.
    State(String),

    /// Merkle tree operation errors
    ///
    /// Represents errors occurring during Merkle tree operations or proof verification.
    Merkle(String),

    /// Hash chain specific errors
    ///
    /// Represents errors related to hash chain operations or validation.
    HashChain(String),

    /// Transaction errors
    ///
    /// Represents errors occurring during transaction processing.
    Transaction(String),

    /// Pre-commitment errors
    ///
    /// Represents errors related to pre-commitment operations or verification.
    PreCommitment(String),

    /// Genesis errors
    ///
    /// Represents errors related to genesis state creation or validation.
    Genesis(String),

    /// Device hierarchy errors
    ///
    /// Represents errors related to device hierarchy management or validation.
    DeviceHierarchy(String),

    /// Forward commitment errors
    ///
    /// Represents errors related to forward commitment operations or verification.
    ForwardCommitment(String),

    /// Relationship errors
    ///
    /// Represents errors related to relationship management or validation.
    Relationship(String),

    /// External commitment errors
    ///
    /// Represents errors related to external commitment operations or verification.
    ExternalCommitment(String),

    /// Identity errors
    ///
    /// Represents errors related to identity operations or verification.
    Identity(String),

    /// Invalid ciphertext error
    InvalidCiphertext,

    /// Lock acquisition error
    ///
    /// Occurs when failing to acquire a mutex or other lock.
    LockError,

    /// Generic error with optional source
    ///
    /// A general-purpose error type for cases that don't fit other categories.
    Generic {
        /// Description of the error
        message: String,
        /// Optional source error that caused this error
        source: Option<Box<dyn Error + Send + Sync>>,
    },

    /// Invalid index error
    ///
    /// Occurs when an operation tries to access an invalid index or out-of-bounds position
    InvalidIndex,

    /// Invalid operation error
    ///
    /// Occurs when attempting an operation that is invalid in the current context
    InvalidOperation(String),

    /// System error
    ///
    /// Represents errors from the underlying system/runtime
    SystemError(String),

    /// Token error
    ///
    /// Represents errors related to token operations
    TokenError {
        /// Description of the token error
        context: String,
        /// Optional source error that caused this error
        source: Option<Box<dyn Error + Send + Sync>>,
    },

    /// Invalid token error
    ///
    /// Occurs when a token is invalid or cannot be processed
    InvalidToken {
        /// Description of the invalid token error
        context: String,
        /// Optional source error that caused this error
        source: Option<Box<dyn Error + Send + Sync>>,
    },

    /// Unauthorized access error
    ///
    /// Occurs when an operation is attempted without proper authorization
    Unauthorized {
        /// Description of what was unauthorized
        context: String,
        /// Optional source error
        source: Option<Box<dyn Error + Send + Sync>>,
    },

    /// Insufficient balance error
    ///
    /// Occurs when a transaction attempts to spend more tokens than are available
    InsufficientBalance {
        /// Token ID that has insufficient balance
        token_id: String,
        /// Current available balance
        available: u64,
        /// Attempted transaction amount
        requested: u64,
    },

    /// Feature not available error
    ///
    /// Occurs when attempting to use a feature that is not implemented or available
    /// in the current version or configuration
    FeatureNotAvailable {
        /// Description of the feature that is not available
        feature: String,
        /// Optional additional details about the feature or why it's unavailable
        details: Option<String>,
    },

    /// Token Policy Violation error
    ///
    /// Occurs when a token operation violates its Content-Addressed Token Policy Anchor (CTPA)
    PolicyViolation {
        /// Token ID that has the policy violation
        token_id: String,
        /// Description of the policy violation
        message: String,
        /// Optional source error that caused this error
        source: Option<Box<dyn Error + Send + Sync>>,
    },
}

impl DsmError {
    /// Creates a new cryptographic error
    ///
    /// # Arguments
    /// * `context` - Descriptive context for the error
    /// * `source` - Optional source error that caused this error
    pub fn crypto<E>(context: impl Into<String>, source: Option<E>) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        DsmError::Crypto {
            context: context.into(),
            source: source.map(|e| Box::new(e) as Box<dyn Error + Send + Sync>),
        }
    }

    /// Creates a new storage error
    ///
    /// # Arguments
    /// * `context` - Descriptive context for the error
    /// * `source` - Optional source error that caused this error
    pub fn storage<E>(context: impl Into<String>, source: Option<E>) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        DsmError::Storage {
            context: context.into(),
            source: source.map(|e| Box::new(e) as Box<dyn Error + Send + Sync>),
        }
    }

    /// Creates a new network error
    ///
    /// # Arguments
    /// * `context` - Descriptive context for the error
    /// * `source` - Optional source error that caused this error
    pub fn network<E>(context: impl Into<String>, source: Option<E>) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        DsmError::Network {
            context: context.into(),
            source: source.map(|e| Box::new(e) as Box<dyn Error + Send + Sync>),
            entity: String::new(),
            details: None,
        }
    }

    /// Creates a new state machine error
    ///
    /// # Arguments
    /// * `message` - Error message
    pub fn state_machine(message: impl Into<String>) -> Self {
        DsmError::StateMachine(message.into())
    }

    /// Creates a new "not found" error
    ///
    /// # Arguments
    pub fn not_found(entity: impl Into<String>, details: Option<impl Into<String>>) -> Self {
        DsmError::NotFound {
            entity: entity.into(),
            details: details.map(|d| d.into()),
            context: String::from("Entity not found"),
            source: None,
        }
    }

    /// Creates a not found error specifically for tokens
    ///
    /// # Arguments
    /// * `token_id` - The ID of the token that wasn't found
    pub fn token_not_found(token_id: String) -> Self {
        Self::not_found("Token", Some(token_id))
    }

    /// Creates a new internal error
    ///
    /// # Arguments
    /// * `context` - Descriptive context for the error
    /// * `source` - Optional source error that caused this error
    pub fn internal<E>(context: impl Into<String>, source: Option<E>) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        DsmError::Internal {
            context: context.into(),
            source: source.map(|e| Box::new(e) as Box<dyn Error + Send + Sync>),
        }
    }

    /// Creates a new validation error
    ///
    /// # Arguments
    /// * `context` - Descriptive context for the error
    /// * `source` - Optional source error that caused this error
    pub fn validation<E>(context: impl Into<String>, source: Option<E>) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        DsmError::Validation {
            context: context.into(),
            source: source.map(|e| Box::new(e) as Box<dyn Error + Send + Sync>),
        }
    }

    /// Creates a new invalid parameter error
    ///
    /// # Arguments
    /// * `message` - Description of the invalid parameter
    pub fn invalid_parameter(message: impl Into<String>) -> Self {
        DsmError::InvalidParameter(message.into())
    }

    /// Creates a new serialization error
    ///
    /// # Arguments
    /// * `context` - Descriptive context for the error
    /// * `source` - Optional source error that caused this error
    pub fn serialization<E>(context: impl Into<String>, source: Option<E>) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        DsmError::Serialization {
            context: context.into(),
            source: source.map(|e| Box::new(e) as Box<dyn Error + Send + Sync>),
            entity: "Data".to_string(),
            details: None,
        }
    }

    /// Creates a new verification error
    ///
    /// # Arguments
    /// * `message` - Description of the verification error
    pub fn verification(message: impl Into<String>) -> Self {
        DsmError::Verification(message.into())
    }

    /// Creates a new state error
    ///
    /// # Arguments
    /// * `message` - Description of the state error
    pub fn state(message: impl Into<String>) -> Self {
        DsmError::State(message.into())
    }

    /// Creates a new Merkle tree error
    ///
    /// # Arguments
    /// * `message` - Description of the Merkle error
    pub fn merkle(message: impl Into<String>) -> Self {
        DsmError::Merkle(message.into())
    }

    /// Creates a new hash chain error
    ///
    /// # Arguments
    /// * `message` - Description of the hash chain error
    pub fn hash_chain(message: impl Into<String>) -> Self {
        DsmError::HashChain(message.into())
    }

    /// Creates a new transaction error
    ///
    /// # Arguments
    /// * `message` - Description of the transaction error
    pub fn transaction(message: impl Into<String>) -> Self {
        DsmError::Transaction(message.into())
    }

    /// Creates a new pre-commitment error
    ///
    /// # Arguments
    /// * `message` - Description of the pre-commitment error
    pub fn pre_commitment(message: impl Into<String>) -> Self {
        DsmError::PreCommitment(message.into())
    }

    /// Creates a new genesis error
    ///
    /// # Arguments
    /// * `message` - Description of the genesis error
    pub fn genesis(message: impl Into<String>) -> Self {
        DsmError::Genesis(message.into())
    }

    /// Creates a new device hierarchy error
    ///
    /// # Arguments
    /// * `message` - Description of the device hierarchy error
    pub fn device_hierarchy(message: impl Into<String>) -> Self {
        DsmError::DeviceHierarchy(message.into())
    }

    /// Creates a new forward commitment error
    ///
    /// # Arguments
    /// * `message` - Description of the forward commitment error
    pub fn forward_commitment(message: impl Into<String>) -> Self {
        DsmError::ForwardCommitment(message.into())
    }

    /// Creates a new relationship error
    ///
    /// # Arguments
    /// * `message` - Description of the relationship error
    pub fn relationship(message: impl Into<String>) -> Self {
        DsmError::Relationship(message.into())
    }

    /// Creates a new external commitment error
    ///
    /// # Arguments
    /// * `message` - Description of the external commitment error
    pub fn external_commitment(message: impl Into<String>) -> Self {
        DsmError::ExternalCommitment(message.into())
    }

    /// Creates a new identity error
    ///
    /// # Arguments
    /// * `message` - Description of the identity error
    pub fn identity(message: impl Into<String>) -> Self {
        DsmError::Identity(message.into())
    }

    /// Creates a new feature not available error
    ///
    /// # Arguments
    /// * `feature` - Description of the feature that isn't available
    /// * `details` - Optional additional details about why the feature is unavailable
    pub fn feature_not_available(
        feature: impl Into<String>,
        details: Option<impl Into<String>>,
    ) -> Self {
        DsmError::FeatureNotAvailable {
            feature: feature.into(),
            details: details.map(|d| d.into()),
        }
    }

    /// Creates a new generic error
    ///
    /// # Arguments
    /// * `message` - Error message
    /// * `source` - Optional source error that caused this error
    pub fn generic<E>(message: impl Into<String>, source: Option<E>) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        DsmError::Generic {
            message: message.into(),
            source: source.map(|e| Box::new(e) as Box<dyn Error + Send + Sync>),
        }
    }

    /// Creates a new invalid index error
    pub fn invalid_index() -> Self {
        Self::InvalidIndex
    }

    /// Creates a new invalid operation error
    ///
    /// # Arguments
    /// * `message` - Description of the invalid operation
    pub fn invalid_operation(message: impl Into<String>) -> Self {
        DsmError::InvalidOperation(message.into())
    }

    /// Creates a new system error
    ///
    /// # Arguments
    /// * `message` - Description of the system error
    pub fn system_error(message: impl Into<String>) -> Self {
        DsmError::SystemError(message.into())
    }

    /// Creates a new token error
    ///
    /// # Arguments
    /// * `context` - Descriptive context for the error
    /// * `source` - Optional source error that caused this error
    pub fn token_error<E>(context: impl Into<String>, source: Option<E>) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        DsmError::TokenError {
            context: context.into(),
            source: source.map(|e| Box::new(e) as Box<dyn Error + Send + Sync>),
        }
    }

    /// Creates a new invalid token error
    ///
    /// # Arguments
    /// * `context` - Descriptive context for the error
    /// * `source` - Optional source error that caused this error
    pub fn invalid_token<E>(context: impl Into<String>, source: Option<E>) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        DsmError::InvalidToken {
            context: context.into(),
            source: source.map(|e| Box::new(e) as Box<dyn Error + Send + Sync>),
        }
    }

    /// Creates a new lock acquisition error
    ///
    /// # Arguments
    /// * `message` - Description of the lock acquisition error
    pub fn lock(_message: impl Into<String>) -> Self {
        DsmError::LockError
    }

    /// Creates a new unauthorized access error
    ///
    /// # Arguments
    /// * `context` - Description of what was unauthorized
    /// * `source` - Optional source error that caused this error
    pub fn unauthorized<E>(context: impl Into<String>, source: Option<E>) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        DsmError::Unauthorized {
            context: context.into(),
            source: source.map(|e| Box::new(e) as Box<dyn Error + Send + Sync>),
        }
    }

    /// Creates a new insufficient balance error
    ///
    /// # Arguments
    /// * `token_id` - ID of the token with insufficient balance
    /// * `available` - Currently available balance
    /// * `requested` - Requested transaction amount
    pub fn insufficient_balance(token_id: String, available: u64, requested: u64) -> Self {
        DsmError::InsufficientBalance {
            token_id,
            available,
            requested,
        }
    }

    /// Creates a new timeout error
    ///
    /// # Arguments
    /// * `message` - Description of the timeout error
    pub fn timeout(message: impl Into<String>) -> Self {
        DsmError::Network {
            context: format!("Timeout: {}", message.into()),
            source: None,
            entity: "Network".to_string(),
            details: None,
        }
    }

    /// Creates a new coordination error
    ///
    /// # Arguments
    /// * `message` - Description of the coordination error
    pub fn coordination(message: impl Into<String>) -> Self {
        DsmError::Internal {
            context: format!("Coordination error: {}", message.into()),
            source: None,
        }
    }

    /// Creates a new fatal error
    ///
    /// # Arguments
    /// * `message` - Description of the fatal error
    pub fn fatal(message: impl Into<String>) -> Self {
        DsmError::Internal {
            context: format!("Fatal error: {}", message.into()),
            source: None,
        }
    }

    /// Returns true if this error represents a recoverable condition
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            DsmError::Network { .. } | DsmError::Serialization { .. } | DsmError::LockError
        )
    }

    /// Returns true if this error is related to security
    pub fn is_security_related(&self) -> bool {
        matches!(
            self,
            DsmError::InvalidCiphertext
                | DsmError::Crypto { .. }
                | DsmError::InvalidPublicKey
                | DsmError::InvalidSecretKey
                | DsmError::Verification(_)
                | DsmError::HashChain(_)
        )
    }

    /// Returns true if this error is related to state validity
    pub fn is_state_validity_error(&self) -> bool {
        matches!(
            self,
            DsmError::StateMachine(_)
                | DsmError::State(_)
                | DsmError::Verification(_)
                | DsmError::HashChain(_)
                | DsmError::Merkle(_)
        )
    }

    /// Creates a new policy violation error
    ///
    /// # Arguments
    /// * `token_id` - ID of the token with policy violation
    /// * `message` - Description of the policy violation
    /// * `source` - Optional source error that caused this error
    pub fn policy_violation<E>(
        token_id: String,
        message: impl Into<String>,
        source: Option<E>,
    ) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        DsmError::PolicyViolation {
            token_id,
            message: message.into(),
            source: source.map(|e| Box::new(e) as Box<dyn Error + Send + Sync>),
        }
    }

    /// Creates a new authorization error
    ///
    /// # Arguments
    /// * `context` - Description of what was unauthorized
    pub fn authorization(context: impl Into<String>) -> Self {
        DsmError::Unauthorized {
            context: context.into(),
            source: None,
        }
    }

    /// Creates a new cryptographic error with a more convenient alias
    ///
    /// # Arguments
    /// * `context` - Description of the cryptographic error
    /// * `source` - Optional source error that caused this error
    pub fn cryptographic<E>(context: impl Into<String>, source: Option<E>) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        Self::crypto(context, source)
    }
}

impl Display for DsmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DsmError::Crypto { context, source } => {
                write!(f, "Cryptographic error: {}", context)?;
                if let Some(s) = source {
                    write!(f, " - caused by: {}", s)?;
                }
                Ok(())
            }
            DsmError::InvalidPublicKey => write!(f, "Invalid public key"),
            DsmError::InvalidSecretKey => write!(f, "Invalid secret key"),
            DsmError::Storage { context, source } => {
                write!(f, "Storage error: {}", context)?;
                if let Some(s) = source {
                    write!(f, " - caused by: {}", s)?;
                }
                Ok(())
            }
            DsmError::Network {
                context,
                source,
                entity: _,
                details: _,
            } => {
                write!(f, "Network error: {}", context)?;
                if let Some(s) = source {
                    write!(f, " - caused by: {}", s)?;
                }
                Ok(())
            }
            DsmError::StateMachine(msg) => write!(f, "State machine error: {}", msg),
            DsmError::NotFound {
                entity,
                details,
                context,
                source: _,
            } => {
                write!(f, "{} not found", entity)?;
                if let Some(d) = details {
                    write!(f, ": {}", d)?;
                }
                write!(f, " ({})", context)?;
                Ok(())
            }
            DsmError::Internal { context, source } => {
                write!(f, "Internal error: {}", context)?;
                if let Some(s) = source {
                    write!(f, " - caused by: {}", s)?;
                }
                Ok(())
            }
            DsmError::Validation { context, source } => {
                write!(f, "Validation error: {}", context)?;
                if let Some(s) = source {
                    write!(f, " - caused by: {}", s)?;
                }
                Ok(())
            }
            DsmError::InvalidParameter(msg) => write!(f, "Invalid parameter: {}", msg),
            DsmError::Serialization {
                context,
                source,
                entity: _,
                details: _,
            } => {
                write!(f, "Serialization error: {}", context)?;
                if let Some(s) = source {
                    write!(f, " - caused by: {}", s)?;
                }
                Ok(())
            }
            DsmError::Verification(msg) => write!(f, "Verification error: {}", msg),
            DsmError::State(msg) => write!(f, "State error: {}", msg),
            DsmError::Merkle(msg) => write!(f, "Merkle tree error: {}", msg),
            DsmError::HashChain(msg) => write!(f, "Hash chain error: {}", msg),
            DsmError::Transaction(msg) => write!(f, "Transaction error: {}", msg),
            DsmError::PreCommitment(msg) => write!(f, "Pre-commitment error: {}", msg),
            DsmError::Genesis(msg) => write!(f, "Genesis error: {}", msg),
            DsmError::DeviceHierarchy(msg) => write!(f, "Device hierarchy error: {}", msg),
            DsmError::ForwardCommitment(msg) => write!(f, "Forward commitment error: {}", msg),
            DsmError::Relationship(msg) => write!(f, "Relationship error: {}", msg),
            DsmError::ExternalCommitment(msg) => write!(f, "External commitment error: {}", msg),
            DsmError::Identity(msg) => write!(f, "Identity error: {}", msg),
            DsmError::InvalidCiphertext => write!(f, "Invalid ciphertext"),
            DsmError::LockError => write!(f, "Failed to acquire lock"),
            DsmError::Generic { message, source } => {
                write!(f, "{}", message)?;
                if let Some(s) = source {
                    write!(f, " - caused by: {}", s)?;
                }
                Ok(())
            }
            DsmError::InvalidIndex => write!(f, "Invalid or out-of-bounds index"),
            DsmError::InvalidOperation(msg) => write!(f, "Invalid operation: {}", msg),
            DsmError::SystemError(msg) => write!(f, "System error: {}", msg),
            DsmError::TokenError { context, source } => {
                write!(f, "Token error: {}", context)?;
                if let Some(s) = source {
                    write!(f, " - caused by: {}", s)?;
                }
                Ok(())
            }
            DsmError::InvalidToken { context, source } => {
                write!(f, "Invalid token: {}", context)?;
                if let Some(s) = source {
                    write!(f, " - caused by: {}", s)?;
                }
                Ok(())
            }
            DsmError::InvalidKeyLength => write!(f, "Invalid key length"),
            DsmError::Unauthorized { context, source } => {
                write!(f, "Unauthorized access: {}", context)?;
                if let Some(s) = source {
                    write!(f, " - caused by: {}", s)?;
                }
                Ok(())
            }
            DsmError::InsufficientBalance {
                token_id,
                available,
                requested,
            } => {
                write!(
                    f,
                    "Insufficient balance for token {}: available {}, requested {}",
                    token_id, available, requested
                )
            }
            DsmError::Integrity { context, source } => {
                write!(f, "Integrity error: {}", context)?;
                if let Some(s) = source {
                    write!(f, " - caused by: {}", s)?;
                }
                Ok(())
            }
            DsmError::FeatureNotAvailable { feature, details } => {
                write!(f, "Feature not available: {}", feature)?;
                if let Some(d) = details {
                    write!(f, " - details: {}", d)?;
                }
                Ok(())
            }
            DsmError::PolicyViolation {
                token_id,
                message,
                source,
            } => {
                write!(f, "Token policy violation for {}: {}", token_id, message)?;
                if let Some(s) = source {
                    write!(f, " - caused by: {}", s)?;
                }
                Ok(())
            }
        }
    }
}

impl Error for DsmError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            DsmError::Crypto { source, .. } => source.as_ref().map(|s| s.as_ref() as &(dyn Error)),
            DsmError::Storage { source, .. } => source.as_ref().map(|s| s.as_ref() as &(dyn Error)),
            DsmError::Network { source, .. } => source.as_ref().map(|s| s.as_ref() as &(dyn Error)),
            DsmError::Internal { source, .. } => {
                source.as_ref().map(|s| s.as_ref() as &(dyn Error))
            }
            DsmError::Validation { source, .. } => {
                source.as_ref().map(|s| s.as_ref() as &(dyn Error))
            }
            DsmError::Serialization { source, .. } => {
                source.as_ref().map(|s| s.as_ref() as &(dyn Error))
            }
            DsmError::Generic { source, .. } => source.as_ref().map(|s| s.as_ref() as &(dyn Error)),
            DsmError::TokenError { source, .. } => {
                source.as_ref().map(|s| s.as_ref() as &(dyn Error))
            }
            DsmError::InvalidToken { source, .. } => {
                source.as_ref().map(|s| s.as_ref() as &(dyn Error))
            }
            DsmError::Unauthorized { source, .. } => {
                source.as_ref().map(|s| s.as_ref() as &(dyn Error))
            }
            DsmError::PolicyViolation { source, .. } => {
                source.as_ref().map(|s| s.as_ref() as &(dyn Error))
            }
            _ => None,
        }
    }
}

// Implementation of common From traits for convenient error conversion

impl From<std::io::Error> for DsmError {
    fn from(error: std::io::Error) -> Self {
        match error.kind() {
            std::io::ErrorKind::NotFound => {
                DsmError::not_found("Resource", Some(error.to_string()))
            }
            std::io::ErrorKind::PermissionDenied => {
                DsmError::storage("Permission denied", Some(error))
            }
            std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::NotConnected
            | std::io::ErrorKind::AddrInUse
            | std::io::ErrorKind::AddrNotAvailable
            | std::io::ErrorKind::TimedOut => DsmError::network(error.to_string(), Some(error)),
            _ => DsmError::generic(format!("I/O error: {}", error), Some(error)),
        }
    }
}

impl From<std::fmt::Error> for DsmError {
    fn from(error: std::fmt::Error) -> Self {
        DsmError::generic("Formatting error", Some(error))
    }
}

impl From<std::str::Utf8Error> for DsmError {
    fn from(error: std::str::Utf8Error) -> Self {
        DsmError::serialization("UTF-8 decoding error", Some(error))
    }
}

impl From<std::string::FromUtf8Error> for DsmError {
    fn from(error: std::string::FromUtf8Error) -> Self {
        DsmError::serialization("UTF-8 string conversion error", Some(error))
    }
}

impl From<std::num::ParseIntError> for DsmError {
    fn from(error: std::num::ParseIntError) -> Self {
        DsmError::validation("Integer parsing error", Some(error))
    }
}

impl From<std::num::ParseFloatError> for DsmError {
    fn from(error: std::num::ParseFloatError) -> Self {
        DsmError::validation("Float parsing error", Some(error))
    }
}

impl From<std::convert::Infallible> for DsmError {
    fn from(_: std::convert::Infallible) -> Self {
        // This should never happen, but we need to handle the conversion
        DsmError::internal(
            "Infallible error occurred",
            None::<std::convert::Infallible>,
        )
    }
}

impl From<bincode::Error> for DsmError {
    fn from(error: bincode::Error) -> Self {
        DsmError::serialization("Bincode serialization error", Some(error))
    }
}

impl From<serde_json::Error> for DsmError {
    fn from(error: serde_json::Error) -> Self {
        DsmError::serialization("JSON serialization error", Some(error))
    }
}

// Add From implementation for PoisonError after the other From implementations

// Add From implementations for PoisonError to handle poisoned locks
// Add From implementations for PoisonError to handle poisoned locks
impl<T> From<std::sync::PoisonError<T>> for DsmError {
    fn from(_err: std::sync::PoisonError<T>) -> Self {
        DsmError::LockError
    }
}

// Add From implementation for token_api::DsmError
impl From<crate::api::token_api::DsmError> for DsmError {
    fn from(err: crate::api::token_api::DsmError) -> Self {
        DsmError::TokenError {
            context: format!("Token API error: {:?}", err),
            source: None,
        }
    }
}

// For backward compatibility with existing code
impl DsmError {
    #[deprecated(since = "0.1.0", note = "Use DsmError::crypto instead")]
    pub fn new_crypto<E>(context: String, source: Option<E>) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        Self::crypto(context, source)
    }

    #[deprecated(since = "0.1.0", note = "Use DsmError::storage instead")]
    pub fn new_storage(msg: String) -> Self {
        Self::storage(msg, None::<std::io::Error>)
    }

    #[deprecated(since = "0.1.0", note = "Use DsmError::network instead")]
    pub fn new_network(msg: String) -> Self {
        Self::network(msg, None::<std::io::Error>)
    }

    #[deprecated(since = "0.1.0", note = "Use DsmError::state_machine instead")]
    pub fn new_state_machine(msg: String) -> Self {
        Self::state_machine(msg)
    }

    #[deprecated(since = "0.1.0", note = "Use DsmError::not_found instead")]
    pub fn new_not_found(entity: &str, details: Option<String>) -> Self {
        Self::not_found(entity, details)
    }

    #[deprecated(since = "0.1.0", note = "Use DsmError::generic instead")]
    pub fn new_std<E>(msg: String, source: Option<E>) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        Self::generic(msg, source)
    }
}
