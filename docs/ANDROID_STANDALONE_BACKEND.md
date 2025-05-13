# Android Standalone DSM Backend Architecture

This document provides a comprehensive overview of the Android Standalone DSM Backend architecture, explaining how it works and how applications can integrate with it.

## Overview

The Android Standalone DSM Backend is designed to provide a centralized Decentralized State Machine (DSM) implementation that multiple Android applications can share. Instead of each application embedding its own copy of the DSM code, they connect to a shared backend service that runs as a standalone Android application.

![Android Standalone Backend Architecture](https://raw.githubusercontent.com/dsm-project/dsm/main/docs/images/android_backend_architecture.png)

## Key Benefits

1. **Shared State**: All applications can access the same state machine, enabling seamless data sharing and interaction.
2. **Reduced Resource Usage**: A single shared service uses fewer system resources than multiple embedded instances.
3. **Consistent Identity Management**: Identities are managed centrally, allowing users to maintain a consistent identity across applications.
4. **Better Battery Life**: Optimization in a single service leads to improved battery performance.
5. **Simplified Updates**: Updates to the DSM implementation only need to be made in one place.
6. **Enhanced Security**: Centralized credential management and reduced attack surface.

## Architecture Components

### 1. Android Service

The `DsmBackendService` runs as a foreground service with the following characteristics:

- Started automatically when an application attempts to connect
- Maintains a persistent notification to prevent system termination
- Acquires a wake lock to ensure continuous operation
- Implements lifecycle management for clean startup and shutdown

### 2. HTTP Server

The `DsmHttpServer` component:

- Provides a RESTful API on localhost (127.0.0.1)
- Listens on a configurable port (default: 7545)
- Handles requests asynchronously using coroutines
- Implements API endpoints for all DSM functionality
- Supports application namespaces for state isolation

### 3. DSM Core

The `DsmCore` component:

- Implements the core DSM functionality in Kotlin
- Manages persistent storage of identities, vaults, and state
- Handles cryptographic operations for state transitions
- Implements push notification management
- Ensures thread safety with mutex locks

### 4. Bluetooth Service

The `DsmBluetoothService` component:

- Enables direct device-to-device communication
- Exposes DSM functionality over Bluetooth
- Implements secure pairing and communication
- Allows offline state exchange between devices

### 5. Management UI

The `DsmServiceManagerActivity` provides:

- Manual service start and stop controls
- Configuration options
- Status monitoring
- Diagnostic information

## Installation Models

The Android Standalone Backend can be installed in several ways:

### Automatic Installation

When an application that depends on the DSM backend is launched, it checks if the backend service is installed and running. If not, it can automatically install and start it (with user permission).

### Manual Installation

Users can manually install the DSM Backend Service app from:
- Google Play Store
- Direct APK download
- F-Droid repository

### OEM Pre-installation

For device manufacturers (OEMs) wishing to integrate DSM technology, the backend service can be pre-installed as a system app.

## Integration for Application Developers

### Client SDK Integration

Android applications connect to the standalone backend using the DSM Client SDK:

```kotlin
// Create a client with default settings
val dsmClient = DsmClient.createWithDefaults(context)

// Ensure the service is available
lifecycleScope.launch {
    val isAvailable = dsmClient.ensureServiceAvailable()
    if (isAvailable) {
        // Service is available, you can now use the client
    }
}
```

### Required Permissions

Applications need the following permissions in their manifest:

```xml
<uses-permission android:name="android.permission.INTERNET" />
<uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
```

For Bluetooth functionality, additional permissions are required:

```xml
<uses-permission android:name="android.permission.BLUETOOTH" android:maxSdkVersion="30" />
<uses-permission android:name="android.permission.BLUETOOTH_ADMIN" android:maxSdkVersion="30" />
<uses-permission android:name="android.permission.BLUETOOTH_CONNECT" />
<uses-permission android:name="android.permission.BLUETOOTH_SCAN" />
```

### Network Security Configuration

For Android 9+ (API level 28+), applications need a network security configuration to allow cleartext traffic to localhost:

```xml
<!-- res/xml/network_security_config.xml -->
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <domain-config cleartextTrafficPermitted="true">
        <domain includeSubdomains="true">localhost</domain>
        <domain includeSubdomains="true">127.0.0.1</domain>
    </domain-config>
</network-security-config>
```

Referenced in the manifest:

```xml
<application
    android:networkSecurityConfig="@xml/network_security_config"
    ...>
</application>
```

## State Isolation vs. Sharing

### Shared State (Default)

By default, all applications connected to the same DSM backend instance share state. This means:

- Identities are accessible to all connected applications
- Vaults and their data are shared across applications
- State transitions affect all applications

This is ideal for application ecosystems that need to share data and functionality.

### Isolated State (Namespaces)

Applications that require isolated state can use "application namespaces":

```kotlin
// Create a client with a namespace for isolated state
val dsmClient = DsmClient.createWithNamespace(context, "my-app-namespace")
```

When using a namespace:

- Identities, vaults, and operations are isolated to that namespace
- Applications in different namespaces cannot access each other's data
- State transitions only affect applications in the same namespace

## Push Notifications

The backend service can notify applications about state changes:

1. Applications register for push notifications with specific topics of interest
2. When state changes occur, the backend sends notifications to registered applications
3. Applications handle the notifications to update their UI or perform actions

```kotlin
// Register for push notifications
val registrationId = dsmClient.registerForNotifications(
    appId = "com.example.app",
    deviceToken = fcmToken,
    topics = listOf("vault_updates", "identity_changes")
)
```

## Security Considerations

### Trust Boundary

The DSM backend service establishes a trust boundary:

- Only the backend service has access to sensitive keys and data
- Applications must authenticate to access data through the API
- Each application can only access data within its permissions

### Hardware-Backed Security

When available, the backend uses hardware-backed security features:

- Android Keystore for secure key storage
- Hardware-backed key attestation
- Biometric authentication integration

### Permission Model

Applications require specific permissions to access different types of data:

- Basic access requires minimal permissions
- Advanced features require additional permissions
- Sensitive operations require user confirmation

## Performance Optimization

### Lazy Loading

The backend implements lazy loading mechanisms:

- State is loaded on demand
- Large data structures are paged
- Resources are released when not in use

### Connection Pooling

The HTTP server uses connection pooling:

- Persistent connections reduce overhead
- Connection reuse improves response time
- Intelligent connection management based on load

### Asynchronous Processing

All operations are performed asynchronously:

- Non-blocking I/O with coroutines
- Parallel processing where possible
- Background thread usage for CPU-intensive tasks

## Diagnostic and Debugging

### Logging

The backend implements comprehensive logging:

- Configurable log levels (ERROR, WARN, INFO, DEBUG, VERBOSE)
- Rotation to prevent storage exhaustion
- Sensitive information is redacted from logs

### Monitoring

The service provides monitoring endpoints:

- Health check API
- Resource usage statistics
- Performance metrics

### Debugging Tools

For developers, debugging tools are available:

- ADB commands for service management
- Logging commands for diagnostic information
- Testing utilities for simulating state transitions

## Roadmap

Future development plans include:

1. **External Storage Nodes**: Integration with external DSM storage nodes
2. **Multi-Device Sync**: Improved synchronization across user devices
3. **Enhanced Bluetooth Mesh**: P2P communication through Bluetooth mesh networking
4. **WebRTC Integration**: Direct browser connectivity for web applications
5. **Custom Authentication Providers**: Support for OAuth, SAML, and other authentication mechanisms

## Conclusion

The Android Standalone DSM Backend provides a robust, efficient, and secure foundation for decentralized applications on Android. By centralizing the DSM implementation in a shared service, it enables sophisticated multi-application ecosystems while minimizing resource usage and maximizing security.

For application developers, it offers a simple integration path through the client SDK, allowing them to focus on their application features rather than the underlying state machine mechanics.
