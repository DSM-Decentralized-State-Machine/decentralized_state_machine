# DSM Android Standalone Backend

This is the Android implementation of the Decentralized State Machine (DSM) standalone backend service. This service runs in the background on Android devices and provides DSM functionality to multiple applications through a standardized API.

## Features

- **Full DSM Functionality**: Implements the complete DSM core functionality including identity management, state machine operations, and vault operations.
- **Shared State**: Enables multiple applications to share state through a single backend instance.
- **Reduced Resource Usage**: Minimizes resource usage by running a single shared service instead of embedding the DSM logic in each application.
- **Consistent Identity Management**: Provides a unified identity system across applications.
- **Better Battery Life**: Optimizes battery usage through a single centralized service.
- **Simplified Updates**: Updates the backend once rather than requiring updates to multiple applications.
- **Bluetooth Communication**: Enables device-to-device communication over Bluetooth.
- **Application Namespaces**: Supports isolated application namespaces for applications that don't need to share state.
- **Push Notifications**: Implements a system for notifying applications of state changes.

## Architecture

The DSM Android Standalone Backend consists of the following components:

1. **Android Service (DsmBackendService)**: The main Android service that runs in the background and provides DSM functionality.
2. **HTTP Server (DsmHttpServer)**: A lightweight HTTP server that exposes the DSM API to client applications.
3. **DSM Core (DsmCore)**: The core implementation of the DSM functionality.
4. **Bluetooth Service (DsmBluetoothService)**: A service for direct device-to-device communication over Bluetooth.
5. **Service Manager (DsmServiceManagerActivity)**: A simple UI for managing the service.

### Service Lifecycle

1. The service is automatically started when an application attempts to connect to it.
2. It runs in the foreground with a persistent notification to prevent it from being killed by the system.
3. It acquires a wake lock to ensure it continues running even when the device is idle.
4. It can be manually started and stopped through the Service Manager UI.

### Persistent Storage

The service uses the following directory structure for persistent storage:

```
/data/data/dsm.service/files/dsm_service/
├── config.json          # Service configuration
├── identities/          # Identity data
├── namespaces/          # Namespace data
├── state.json           # Current state and operations
├── vaults/              # Vault data
├── tokens/              # Token data
├── commitments/         # Commitment data
├── unilateral/          # Unilateral transaction data
├── push_tokens/         # Push notification tokens
└── logs/                # Service logs
```

## Installation

### Prerequisites

- Android 6.0 (API level 23) or higher
- At least 50MB of free storage space

### Installation Options

1. **From Google Play (Recommended)**:
   - Search for "DSM Backend Service" on Google Play
   - Install the app
   - Launch it once to complete setup

2. **From APK File**:
   - Download the APK from [github.com/dsm-project/dsm-android-backend/releases](https://github.com/dsm-project/dsm-android-backend/releases)
   - Enable installation from unknown sources in your device settings
   - Install the APK

3. **Automatic Installation via Client App**:
   - Any app that uses the DSM Client SDK can automatically install the backend service if it's not already installed

## Configuration

The service can be configured through the Service Manager UI or by editing the configuration file directly.

### Configuration File

The configuration file is located at `/data/data/dsm.service/files/dsm_service/config.json` and has the following structure:

```json
{
  "server": {
    "host": "127.0.0.1",
    "port": 7545
  },
  "storage": {
    "data_dir": "/data/data/dsm.service/files/dsm_service"
  },
  "network": {
    "enable_p2p": false,
    "bootstrap_nodes": []
  },
  "vault": {
    "auto_expire_check_interval": 3600
  },
  "unilateral": {
    "max_transaction_size": 1048576
  },
  "bluetooth": {
    "enabled": true,
    "service_uuid": "00001101-0000-1000-8000-00805F9B34FB"
  }
}
```

### Service Manager UI

The Service Manager UI provides the following configuration options:

- **Server Port**: The port on which the HTTP server listens for connections (default: 7545)
- **Bluetooth**: Enable or disable Bluetooth device-to-device communication
- **P2P Network**: Enable or disable peer-to-peer network communication (not implemented yet)
- **Log Level**: Set the log level for the service (ERROR, WARN, INFO, DEBUG, VERBOSE)

## Using the Service

### Required Permissions

Applications that use the DSM backend service need the following permissions:

```xml
<uses-permission android:name="android.permission.INTERNET" />
<uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
```

For Bluetooth functionality, these additional permissions are needed:

```xml
<uses-permission android:name="android.permission.BLUETOOTH" android:maxSdkVersion="30" />
<uses-permission android:name="android.permission.BLUETOOTH_ADMIN" android:maxSdkVersion="30" />
<uses-permission android:name="android.permission.BLUETOOTH_CONNECT" />
<uses-permission android:name="android.permission.BLUETOOTH_SCAN" />
```

### Connecting to the Service

Applications connect to the service using the DSM Client SDK. See the [DSM Client SDK documentation](../dsm_client_sdk_kotlin/README.md) for details.

Basic connection example:

```kotlin
// Create a client with default settings
val dsmClient = DsmClient.createWithDefaults(context)

// Ensure the service is available
lifecycleScope.launch {
    val isAvailable = dsmClient.ensureServiceAvailable()
    if (isAvailable) {
        // Service is available, you can now use the client
        val identities = dsmClient.getIdentities()
        // ...
    }
}
```

### HTTP API

The service exposes a RESTful HTTP API on `http://127.0.0.1:7545` with the following endpoints:

#### Health Check

```
GET /health
```

Response:
```json
{
  "status": "running",
  "version": "1.0.0",
  "timestamp": 1698152400
}
```

#### Identities

```
POST /api/v1/identities
{
  "device_id": "my-device-id",  // Optional
  "namespace": "my-namespace"    // Optional
}
```

```
GET /api/v1/identities?namespace=my-namespace  // namespace is optional
```

```
GET /api/v1/identities/{identity_id}?namespace=my-namespace  // namespace is optional
```

#### Vaults

```
POST /api/v1/vaults
{
  "identity_id": "identity-id",
  "name": "My Vault",           // Optional
  "namespace": "my-namespace"    // Optional
}
```

```
GET /api/v1/vaults?namespace=my-namespace  // namespace is optional
```

```
GET /api/v1/vaults/{vault_id}?namespace=my-namespace  // namespace is optional
```

```
POST /api/v1/vaults/{vault_id}/update
{
  "data": { ... },
  "namespace": "my-namespace"    // Optional
}
```

#### Operations

```
POST /api/v1/operations
{
  "operation_type": "example_operation",
  "message": "Example message",  // Optional
  "data": { ... },               // Optional
  "namespace": "my-namespace"    // Optional
}
```

```
GET /api/v1/operations?namespace=my-namespace  // namespace is optional
```

#### Namespaces

```
POST /api/v1/namespaces
{
  "name": "my-namespace",
  "description": "My namespace"  // Optional
}
```

```
GET /api/v1/namespaces
```

#### Push Notifications

```
POST /api/v1/notifications/register
{
  "app_id": "com.example.app",
  "device_token": "fcm-token",
  "platform": "android",
  "namespace": "my-namespace",   // Optional
  "topics": ["topic1", "topic2"] // Optional
}
```

### Bluetooth API

The service also exposes a Bluetooth API for direct device-to-device communication. See the [DsmBluetoothClient](../dsm_client_sdk_kotlin/src/main/kotlin/dsm/client/DsmBluetoothClient.kt) class in the DSM Client SDK for details.

## Service Management

### Starting the Service

The service can be started in the following ways:

1. **Automatic Start**:
   - The service automatically starts when an application attempts to connect to it using the client SDK.

2. **Manual Start via Service Manager**:
   - Launch the DSM Service Manager app and tap the "Start Service" button.

3. **Manual Start via ADB**:
   ```bash
   adb shell am startservice -n dsm.service/.DsmBackendService
   ```

### Stopping the Service

The service can be stopped in the following ways:

1. **Manual Stop via Service Manager**:
   - Launch the DSM Service Manager app and tap the "Stop Service" button.

2. **Manual Stop via ADB**:
   ```bash
   adb shell am stopservice -n dsm.service/.DsmBackendService
   ```

### Checking Service Status

The service status can be checked in the following ways:

1. **Via Service Manager**:
   - Launch the DSM Service Manager app to see the service status.

2. **Via ADB**:
   ```bash
   adb shell ps -ef | grep dsm.service
   ```

### Viewing Logs

Service logs can be viewed in the following ways:

1. **Via ADB**:
   ```bash
   adb shell logcat -s DsmBackendService DsmHttpServer DsmCore DsmBluetoothService
   ```

2. **Via Log File**:
   ```bash
   adb shell cat /data/data/dsm.service/files/dsm_service/logs/dsm.log
   ```

## Troubleshooting

### Common Issues

#### Service Not Starting

If the service fails to start:

1. Check if the device has sufficient storage space.
2. Ensure the app has all the necessary permissions.
3. Check the logs for error messages:
   ```bash
   adb shell logcat -s DsmBackendService
   ```

#### Connection Refused

If applications can't connect to the service:

1. Ensure the service is running.
2. Check if the service is listening on the expected port:
   ```bash
   adb shell netstat -an | grep 7545
   ```
3. Ensure the application has the INTERNET permission.

#### Permission Denied

If you see permission denied errors:

1. Ensure the app has the necessary permissions (INTERNET, ACCESS_NETWORK_STATE).
2. For Bluetooth operations, ensure the app has the Bluetooth permissions.

#### Service Crashes

If the service crashes:

1. Check the logs for stack traces:
   ```bash
   adb shell logcat -s DsmBackendService
   ```
2. Ensure the device has sufficient memory available.
3. Check if the storage is full or corrupted.

### Backup and Restore

To backup the service data:
```bash
adb exec-out "tar -czf - /data/data/dsm.service/files/dsm_service" > dsm_backup.tar.gz
```

To restore from a backup:
```bash
adb push dsm_backup.tar.gz /sdcard/
adb shell "cat /sdcard/dsm_backup.tar.gz | tar -xzf - -C /"
```

## Building from Source

### Prerequisites

- Android Studio 2022.1 or later
- Android SDK with API level 33 or higher
- Kotlin 1.8.10 or later
- Gradle 7.5 or later

### Build Steps

1. Clone the repository:
   ```bash
   git clone https://github.com/dsm-project/dsm-android-backend.git
   cd dsm-android-backend
   ```

2. Open the project in Android Studio.

3. Build the project:
   ```bash
   ./gradlew assembleRelease
   ```

4. The APK will be located at `app/build/outputs/apk/release/app-release.apk`.

## Contributing

Contributions are welcome! Please see the [CONTRIBUTING.md](../CONTRIBUTING.md) file for guidelines.

## License

This project is licensed under the same license as the DSM project (Apache 2.0 / MIT).

## Acknowledgments

- The DSM Project team for the core DSM implementation
- The Android community for inspiration and support
