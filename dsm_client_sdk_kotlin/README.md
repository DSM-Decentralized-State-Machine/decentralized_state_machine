# DSM Client SDK for Android

This is the official client SDK for integrating Android applications with the Decentralized State Machine (DSM) backend. The SDK provides easy access to DSM functionality including identity management, vault operations, state machine operations, and Bluetooth device-to-device communication.

## Features

- Connect to a standalone DSM backend service
- Create and manage identities
- Create and access vaults for secure data storage
- Apply operations to the state machine
- Direct device-to-device communication via Bluetooth
- Support for isolated application namespaces

## Installation

### Gradle

Add the DSM client SDK to your app's build.gradle file:

```gradle
dependencies {
    implementation 'dsm:client-sdk:1.0.0'
}
```

For Kotlin DSL (build.gradle.kts):

```kotlin
dependencies {
    implementation("dsm:client-sdk:1.0.0")
}
```

### Required Permissions

Add the following permissions to your AndroidManifest.xml:

```xml
<!-- Required permissions -->
<uses-permission android:name="android.permission.INTERNET" />
<uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />

<!-- For Bluetooth functionality (optional) -->
<uses-permission android:name="android.permission.BLUETOOTH" android:maxSdkVersion="30" />
<uses-permission android:name="android.permission.BLUETOOTH_ADMIN" android:maxSdkVersion="30" />
<uses-permission android:name="android.permission.BLUETOOTH_CONNECT" />
<uses-permission android:name="android.permission.BLUETOOTH_SCAN" />
```

Additionally, for Android 8+ (API 26+), you need to enable cleartext traffic to localhost for local connections:

```xml
<!-- In res/xml/network_security_config.xml -->
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <domain-config cleartextTrafficPermitted="true">
        <domain includeSubdomains="true">localhost</domain>
        <domain includeSubdomains="true">127.0.0.1</domain>
    </domain-config>
</network-security-config>
```

Then reference this configuration in your AndroidManifest.xml:

```xml
<application
    android:networkSecurityConfig="@xml/network_security_config"
    ...>
    <!-- ... -->
</application>
```

## Quick Start

### Initialize the Client

```kotlin
// Create a client with default settings (shared state)
val dsmClient = DsmClient.createWithDefaults(context)

// Or create a client with a namespace for isolated state
val dsmClient = DsmClient.createWithNamespace(context, "my-app-namespace")

// Or create a fully customized client
val dsmClient = DsmClient.create(
    context = context,
    backendUrl = "http://127.0.0.1:7545",
    apiVersion = "v1",
    namespace = "my-app-namespace"
)
```

### Ensure the Backend Service is Available

```kotlin
lifecycleScope.launch {
    try {
        val isAvailable = dsmClient.ensureServiceAvailable()
        if (isAvailable) {
            // Backend is available and ready to use
        } else {
            // Backend is not available
            // Guide the user to install the DSM backend
        }
    } catch (e: Exception) {
        // Handle connection errors
    }
}
```

### Check Connection Status

```kotlin
lifecycleScope.launch {
    try {
        val isConnected = dsmClient.checkConnection()
        if (isConnected) {
            // Connected to DSM backend
        } else {
            // Not connected
        }
    } catch (e: Exception) {
        // Handle connection errors
    }
}
```

### Identity Management

```kotlin
// Create an identity
lifecycleScope.launch {
    try {
        val identityId = dsmClient.createIdentity("device-123")
        // Identity created successfully
    } catch (e: Exception) {
        // Handle errors
    }
}

// Get all identities
lifecycleScope.launch {
    try {
        val identities = dsmClient.getIdentities()
        // Process the list of identities
    } catch (e: Exception) {
        // Handle errors
    }
}

// Get a specific identity
lifecycleScope.launch {
    try {
        val identity = dsmClient.getIdentity("identity-id")
        // Process the identity
    } catch (e: Exception) {
        // Handle errors
    }
}
```

### Vault Operations

```kotlin
// Create a vault
lifecycleScope.launch {
    try {
        val vaultId = dsmClient.createVault(
            identityId = "identity-id",
            name = "My Vault"
        )
        // Vault created successfully
    } catch (e: Exception) {
        // Handle errors
    }
}

// Get all vaults
lifecycleScope.launch {
    try {
        val vaults = dsmClient.getVaults()
        // Process the list of vaults
    } catch (e: Exception) {
        // Handle errors
    }
}

// Get a specific vault
lifecycleScope.launch {
    try {
        val vault = dsmClient.getVault("vault-id")
        // Process the vault
    } catch (e: Exception) {
        // Handle errors
    }
}

// Update a vault's data
lifecycleScope.launch {
    try {
        val vaultData = JSONObject().apply {
            put("key1", "value1")
            put("key2", "value2")
        }
        
        val success = dsmClient.updateVault("vault-id", vaultData)
        // Vault updated successfully
    } catch (e: Exception) {
        // Handle errors
    }
}
```

### State Machine Operations

```kotlin
// Apply an operation
lifecycleScope.launch {
    try {
        val operationData = JSONObject().apply {
            put("key1", "value1")
            put("key2", "value2")
        }
        
        val operation = dsmClient.applyOperation(
            operationType = "example_operation",
            message = "This is an example operation",
            data = operationData
        )
        
        // Operation applied successfully
        val nextState = operation.nextState
    } catch (e: Exception) {
        // Handle errors
    }
}

// Get recent operations
lifecycleScope.launch {
    try {
        val (operations, currentState) = dsmClient.getOperations()
        // Process the operations and current state
    } catch (e: Exception) {
        // Handle errors
    }
}
```

### Namespaces

```kotlin
// Create a namespace
lifecycleScope.launch {
    try {
        val namespaceId = dsmClient.createNamespace(
            name = "my-namespace",
            description = "A namespace for my app"
        )
        // Namespace created successfully
    } catch (e: Exception) {
        // Handle errors
    }
}

// Get all namespaces
lifecycleScope.launch {
    try {
        val namespaces = dsmClient.getNamespaces()
        // Process the list of namespaces
    } catch (e: Exception) {
        // Handle errors
    }
}
```

### Bluetooth Communication

```kotlin
// Create a Bluetooth client
val bluetoothClient = DsmBluetoothClient(context)

// Check if Bluetooth is available
if (bluetoothClient.isBluetoothAvailable()) {
    // Bluetooth is available
}

// Discover DSM backend services on nearby devices
lifecycleScope.launch {
    try {
        val devices = bluetoothClient.discoverDsmServices()
        // Process the list of devices
    } catch (e: Exception) {
        // Handle errors
    }
}

// Connect to a device and get identities
lifecycleScope.launch {
    try {
        val device = devices[0] // Get a device from the discovered list
        val connection = bluetoothClient.connectToDevice(device)
        
        // Use the connection to interact with the remote DSM backend
        val identities = connection.getIdentities()
        
        // Don't forget to close the connection when done
        connection.close()
    } catch (e: Exception) {
        // Handle errors
    }
}
```

## Data Model

The SDK provides the following data classes for working with DSM entities:

- `Identity`: Represents an identity in the DSM system
  - `id`: The identity ID
  - `deviceId`: The device ID
  - `createdAt`: The creation timestamp

- `Vault`: Represents a vault in the DSM system
  - `id`: The vault ID
  - `identityId`: The identity ID that owns this vault
  - `name`: The vault name
  - `createdAt`: The creation timestamp
  - `data`: The vault data as a JSONObject

- `Operation`: Represents an operation in the DSM system
  - `type`: The operation type
  - `message`: The operation message
  - `data`: The operation data as a JSONObject
  - `timestamp`: The timestamp when the operation was applied
  - `previousState`: The previous state hash
  - `nextState`: The next state hash

- `Namespace`: Represents a namespace in the DSM system
  - `id`: The namespace ID
  - `name`: The namespace name
  - `description`: The namespace description
  - `createdAt`: The creation timestamp

## Configuration

The client can be configured with various options:

```kotlin
// Set connection timeout
dsmClient.setConnectionTimeout(15000) // 15 seconds

// Set retry attempts
dsmClient.setRetryAttempts(5)

// Enable or disable Bluetooth
dsmClient.setBluetoothEnabled(true)

// Set auto sync interval
dsmClient.setAutoSyncInterval(120000) // 2 minutes

// Save configuration
dsmClient.saveConfig()
```

## Error Handling

All methods that communicate with the DSM backend can throw exceptions when errors occur. It's important to handle these exceptions properly:

```kotlin
lifecycleScope.launch {
    try {
        // Call a method that may throw an exception
        val identities = dsmClient.getIdentities()
        // Process the result
    } catch (e: IOException) {
        // Handle network errors
    } catch (e: SecurityException) {
        // Handle permission errors
    } catch (e: Exception) {
        // Handle other errors
    }
}
```

## Best Practices

1. **Initialize the client early**: Initialize the DSM client in your Application class to ensure it's available throughout your app.

2. **Check connection before important operations**: Always check if the connection to the DSM backend is available before performing important operations.

3. **Handle errors gracefully**: Wrap all SDK method calls in try-catch blocks to handle errors gracefully.

4. **Use coroutines or other async patterns**: All SDK methods are suspend functions that should be called from a coroutine or other asynchronous context.

5. **Close resources**: Close Bluetooth connections when done to avoid resource leaks.

6. **Consider using a namespace**: If your app doesn't need to share state with other apps, use a namespace to isolate your app's state.

## License

This SDK is licensed under the same license as the DSM project (Apache 2.0 / MIT).
