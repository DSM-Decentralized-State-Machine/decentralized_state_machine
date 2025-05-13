package dsm.service;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Build;
import android.os.IBinder;
import android.os.PowerManager;
import android.util.Log;

import androidx.annotation.Nullable;
import androidx.core.app.NotificationCompat;

import java.io.File;
import java.io.IOException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * The main Android service for the DSM standalone backend.
 * This service runs in the background and provides DSM functionality
 * to multiple applications through various interfaces.
 */
public class DsmBackendService extends Service {
    private static final String TAG = "DsmBackendService";
    private static final String CHANNEL_ID = "dsm_service_channel";
    private static final int NOTIFICATION_ID = 1;
    
    // Service lifecycle state
    private boolean isRunning = false;
    
    // Wake lock to keep the service running in the background
    private PowerManager.WakeLock wakeLock;
    
    // Executor for background tasks
    private ExecutorService executorService;
    
    // The HTTP server
    private DsmHttpServer httpServer;
    
    // DSM Core components
    private DsmCore dsmCore;
    
    @Override
    public void onCreate() {
        super.onCreate();
        Log.i(TAG, "DSM Backend Service onCreate");
        
        // Initialize the executor service
        executorService = Executors.newCachedThreadPool();
        
        // Create the notification channel (required for Android 8.0+)
        createNotificationChannel();
        
        // Initialize DSM data directories
        initializeDataDirectories();
        
        // Initialize the DSM core
        dsmCore = new DsmCore(this);
        
        // Create the HTTP server
        httpServer = new DsmHttpServer(this, dsmCore);
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Log.i(TAG, "DSM Backend Service onStartCommand");
        
        // Start in the foreground with a notification
        startForeground(NOTIFICATION_ID, createNotification());
        
        // Acquire wake lock to keep the service running
        acquireWakeLock();
        
        if (!isRunning) {
            Log.i(TAG, "Starting DSM backend components");
            
            // Start the DSM core
            executorService.execute(() -> {
                try {
                    dsmCore.start();
                    Log.i(TAG, "DSM Core started successfully");
                } catch (Exception e) {
                    Log.e(TAG, "Failed to start DSM Core", e);
                }
            });
            
            // Start the HTTP server
            executorService.execute(() -> {
                try {
                    httpServer.start();
                    Log.i(TAG, "HTTP Server started successfully");
                } catch (Exception e) {
                    Log.e(TAG, "Failed to start HTTP Server", e);
                }
            });
            
            isRunning = true;
        } else {
            Log.i(TAG, "DSM Backend Service already running");
        }
        
        // Return START_STICKY to ensure the service restarts if it's killed
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        Log.i(TAG, "DSM Backend Service onDestroy");
        
        isRunning = false;
        
        // Stop the HTTP server
        if (httpServer != null) {
            executorService.execute(() -> {
                try {
                    httpServer.stop();
                    Log.i(TAG, "HTTP Server stopped successfully");
                } catch (Exception e) {
                    Log.e(TAG, "Failed to stop HTTP Server", e);
                }
            });
        }
        
        // Stop the DSM core
        if (dsmCore != null) {
            executorService.execute(() -> {
                try {
                    dsmCore.stop();
                    Log.i(TAG, "DSM Core stopped successfully");
                } catch (Exception e) {
                    Log.e(TAG, "Failed to stop DSM Core", e);
                }
            });
        }
        
        // Shutdown the executor service
        if (executorService != null && !executorService.isShutdown()) {
            executorService.shutdown();
        }
        
        // Release the wake lock
        releaseWakeLock();
        
        super.onDestroy();
    }

    @Nullable
    @Override
    public IBinder onBind(Intent intent) {
        // This service does not support binding
        return null;
    }
    
    /**
     * Creates the notification channel required for Android 8.0 and above
     */
    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            String name = "DSM Backend Service";
            String description = "Notification channel for the DSM Backend Service";
            int importance = NotificationManager.IMPORTANCE_LOW;
            
            NotificationChannel channel = new NotificationChannel(CHANNEL_ID, name, importance);
            channel.setDescription(description);
            
            NotificationManager notificationManager = getSystemService(NotificationManager.class);
            if (notificationManager != null) {
                notificationManager.createNotificationChannel(channel);
            }
        }
    }
    
    /**
     * Creates the notification for the foreground service
     */
    private Notification createNotification() {
        NotificationCompat.Builder builder = new NotificationCompat.Builder(this, CHANNEL_ID)
                .setContentTitle("DSM Backend Service")
                .setContentText("Running in the background")
                .setSmallIcon(android.R.drawable.ic_lock_idle_lock)
                .setPriority(NotificationCompat.PRIORITY_LOW);
        
        return builder.build();
    }
    
    /**
     * Acquires a wake lock to keep the service running
     */
    private void acquireWakeLock() {
        if (wakeLock == null) {
            PowerManager powerManager = (PowerManager) getSystemService(Context.POWER_SERVICE);
            wakeLock = powerManager.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "DSM:BackendWakeLock");
            wakeLock.acquire();
            Log.i(TAG, "Wake lock acquired");
        }
    }
    
    /**
     * Releases the wake lock
     */
    private void releaseWakeLock() {
        if (wakeLock != null && wakeLock.isHeld()) {
            wakeLock.release();
            wakeLock = null;
            Log.i(TAG, "Wake lock released");
        }
    }
    
    /**
     * Initializes the data directories for the DSM backend
     */
    private void initializeDataDirectories() {
        // Define the base data directory
        File dataDir = new File(getFilesDir(), "dsm_service");
        
        // Create the main data directory
        if (!dataDir.exists() && !dataDir.mkdirs()) {
            Log.e(TAG, "Failed to create data directory: " + dataDir.getAbsolutePath());
        }
        
        // Create subdirectories
        String[] subdirs = {
                "identities",
                "tokens",
                "commitments",
                "unilateral",
                "vaults",
                "logs"
        };
        
        for (String subdir : subdirs) {
            File dir = new File(dataDir, subdir);
            if (!dir.exists() && !dir.mkdirs()) {
                Log.e(TAG, "Failed to create subdirectory: " + dir.getAbsolutePath());
            }
        }
        
        // Create a default configuration file if it doesn't exist
        File configFile = new File(dataDir, "config.json");
        if (!configFile.exists()) {
            try {
                createDefaultConfig(configFile);
            } catch (IOException e) {
                Log.e(TAG, "Failed to create default configuration file", e);
            }
        }
    }
    
    /**
     * Creates a default configuration file for the DSM backend
     */
    private void createDefaultConfig(File configFile) throws IOException {
        // Default configuration as JSON
        String defaultConfig = "{\n" +
                "  \"server\": {\n" +
                "    \"host\": \"127.0.0.1\",\n" +
                "    \"port\": 7545\n" +
                "  },\n" +
                "  \"storage\": {\n" +
                "    \"data_dir\": \"" + getFilesDir().getAbsolutePath() + "/dsm_service\"\n" +
                "  },\n" +
                "  \"network\": {\n" +
                "    \"enable_p2p\": false,\n" +
                "    \"bootstrap_nodes\": []\n" +
                "  },\n" +
                "  \"vault\": {\n" +
                "    \"auto_expire_check_interval\": 3600\n" +
                "  },\n" +
                "  \"unilateral\": {\n" +
                "    \"max_transaction_size\": 1048576\n" +
                "  },\n" +
                "  \"bluetooth\": {\n" +
                "    \"enabled\": true,\n" +
                "    \"service_uuid\": \"00001101-0000-1000-8000-00805F9B34FB\"\n" +
                "  }\n" +
                "}\n";
        
        // Write to the file
        java.nio.file.Files.write(configFile.toPath(), defaultConfig.getBytes());
    }
    
    /**
     * Gets the data directory path for the DSM backend
     */
    public String getDataDirectoryPath() {
        return new File(getFilesDir(), "dsm_service").getAbsolutePath();
    }
    
    /**
     * Gets the current configuration as a SharedPreferences object
     */
    public SharedPreferences getConfiguration() {
        return getSharedPreferences("dsm_service_config", Context.MODE_PRIVATE);
    }
}
