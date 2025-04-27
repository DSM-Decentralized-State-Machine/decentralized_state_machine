# Standalone DSM Backend Guide

This guide explains how to install and use the standalone DSM backend with Android applications.

## Overview

The standalone DSM backend architecture allows multiple applications to share a single DSM backend instance, providing several benefits:

- Shared state between applications
- Reduced resource usage
- Consistent identity management
- Better battery life
- Simplified updates

## Installation

### Installing on Android

1. **Automated Installation**:
   The DSM backend can be automatically installed by any application that uses it. When an app that depends on the DSM backend is launched, it will check if the backend service is installed and running. If not, it will automatically install and start it.

2. **Manual Installation**:
   You can also manually install the DSM backend by downloading the DSM Installer app from our website.

### Installation Locations

- **Android**: `/data/data/dsm.vaulthunter/dsm_service/`
- **Linux**: `/opt/dsm/`
- **macOS**: `/Applications/DSM/`
- **Windows**: `C:\Program Files\DSM\`

## Connecting Applications to the Backend

### Android Applications

Android applications can connect to the standalone DSM backend using the client SDK:

```java
// Initialize the DSM client
DsmClient client = DsmClient.createWithDefaults(context);

// Check if the backend is available
client.checkConnection()
    .thenAccept(isConnected -> {
        if (isConnected) {
            // Use the DSM client to interact with the backend
            client.createIdentity("my-device")
                .thenAccept(identityId -> {
                    // Identity created
                })
                .exceptionally(e -> {
                    // Handle error
                    return null;
                });
        }
    });
```

### Configuration

Applications can customize their connection to the DSM backend by modifying the client configuration file:

**Android**: `/data/data/[packageName]/shared_prefs/dsm_client_config.xml`

Example configuration:
```json
{
  "backend_url": "http://127.0.0.1:7545",
  "api_version": "v1",
  "connection_timeout_ms": 10000,
  "retry_attempts": 3,
  "bluetooth_enabled": true,
  "auto_sync_interval_ms": 60000,
  "log_level": "INFO"
}
```

## Service Management

### Starting the Service

The service is automatically started when an application attempts to connect to it. It can also be started manually:

```bash
# Android
am startservice -n dsm.service/.DsmBackendService

# Linux/macOS
systemctl start dsm

# Windows
net start DSMService
```

### Checking Service Status

```bash
# Android
ps -ef | grep dsm-server

# Linux/macOS
systemctl status dsm

# Windows
sc query DSMService
```

### Stopping the Service

```bash
# Android
am stopservice -n dsm.service/.DsmBackendService

# Linux/macOS
systemctl stop dsm

# Windows
net stop DSMService
```

## Shared vs. Isolated State

By default, all applications connected to the same DSM backend instance share state. This means identities, vaults, and other data are accessible to all connected applications.

For applications that require isolated state, the DSM backend supports "application namespaces":

```java
// Initialize the DSM client with an application namespace
DsmClient client = new DsmClient(backendUrl, apiVersion, "my-app-namespace");
```

## Troubleshooting

### Service Not Starting

If the DSM service fails to start:

1. Check logs: `/data/data/dsm.vaulthunter/dsm_service/dsm.log`
2. Ensure the device has sufficient storage space
3. Verify permissions are granted for the application

### Connection Issues

If applications can't connect to the running service:

1. Check if the service is running using the commands above
2. Verify network permissions are granted
3. Check firewall settings
4. Restart the service

### Data Synchronization Problems

If data isn't synchronizing properly between apps:

1. Check if both apps are using the same namespace
2. Verify both apps have the same identity credentials
3. Restart the DSM service

## Security Considerations

The standalone DSM backend improves security through:

1. Reduced attack surface (only one process with access to sensitive data)
2. Centralized updates for security patches
3. Consistent credential management
4. Hardware-backed key storage (when available)

For enterprise deployments, additional security measures can be configured.

## Advanced Topics

### Custom Authentication Providers

The DSM backend can be configured to use custom authentication providers:

```java
client.setAuthProvider(new OAuthProvider("my-oauth-provider"));
```

### External Storage Nodes

For applications that need distributed storage beyond the local device:

```java
client.addStorageNode("https://storage-node.example.com");
```

### Backup and Restore

To backup DSM state:

```bash
# Android
adb exec-out "tar -czf - /data/data/dsm.vaulthunter/dsm_service/data" > dsm_backup.tar.gz

# Linux/macOS
tar -czf dsm_backup.tar.gz /var/lib/dsm

# Windows
"C:\Program Files\DSM\bin\dsm-cli.exe" backup -o dsm_backup.zip
```

To restore:

```bash
# Android
adb push dsm_backup.tar.gz /sdcard/
adb shell "cat /sdcard/dsm_backup.tar.gz | tar -xzf - -C /"

# Linux/macOS
tar -xzf dsm_backup.tar.gz -C /

# Windows
"C:\Program Files\DSM\bin\dsm-cli.exe" restore -i dsm_backup.zip
```