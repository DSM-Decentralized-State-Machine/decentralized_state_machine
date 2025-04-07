use std::error::Error;
use crate::types::error::DsmError;

pub trait SecureStorage: Send + Sync {
    fn store(&mut self, key: &str, data: Vec<u8>) -> Result<(), DsmError> {
        if key.is_empty() {
            return Err(DsmError::validation(
                "Storage key cannot be empty".to_string(),
                None::<Box<dyn Error + Send + Sync>>
            ));
        }
        
        self.store_internal(key, data)
    }

    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, DsmError> {
        if key.is_empty() {
            return Err(DsmError::validation(
                "Storage key cannot be empty".to_string(), 
                None::<Box<dyn Error + Send + Sync>>
            ));
        }
        
        self.get_internal(key)
    }

    fn delete(&mut self, key: &str) -> Result<(), DsmError> {
        if key.is_empty() {
            return Err(DsmError::validation(
                "Storage key cannot be empty".to_string(),
                None::<Box<dyn Error + Send + Sync>> 
            ));
        }
        
        self.delete_internal(key)
    }

    // Internal methods to be implemented by concrete storage backends
    fn store_internal(&mut self, key: &str, data: Vec<u8>) -> Result<(), DsmError>;
    fn get_internal(&self, key: &str) -> Result<Option<Vec<u8>>, DsmError>;
    fn delete_internal(&mut self, key: &str) -> Result<(), DsmError>;
}