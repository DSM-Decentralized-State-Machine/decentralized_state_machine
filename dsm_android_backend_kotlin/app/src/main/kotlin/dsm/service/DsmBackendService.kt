package dsm.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import android.util.Log
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import org.json.JSONObject
import java.io.File
import java.io.IOException
import kotlin.coroutines.CoroutineContext

/**
 * The main Android service for the DSM standalone backend.
 * This service runs in the background and provides DSM functionality
 * to multiple applications through various interfaces.
 */
class DsmBackendService : Service(), CoroutineScope {
    companion object {
        private const val TAG = "DsmBackendService"
        private const val CHANNEL_ID = "dsm_service_channel"
        private const val NOTIFICATION_ID = 1
    }

    // Coroutine context for background operations
    private val job = Job()
    override val coroutineContext: CoroutineContext
        get() = Dispatchers.IO + job

    // Service lifecycle state
    private var isRunning = false

    // Wake lock to keep the service running in the background
    private var wakeLock: PowerManager.WakeLock? = null

    // The HTTP server
    private lateinit var httpServer: DsmHttpServer

    // DSM Core components
    private lateinit var dsmCore: DsmCore

    // Bluetooth service for device-to-device communication
    private lateinit var bluetoothService: DsmBluetoothService

    override fun onCreate() {
        super.onCreate()
        Log.i(TAG, "DSM Backend Service onCreate")

        // Create the notification channel (required for Android 8.0+)
        createNotificationChannel()

        // Initialize DSM data directories
        initializeDataDirectories()

        // Initialize the DSM core
        dsmCore = DsmCore(this)

        // Create the HTTP server
        httpServer = DsmHttpServer(this, dsmCore)

        // Initialize the Bluetooth service
        bluetoothService = DsmBluetoothService(this, dsmCore)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.i(TAG, "DSM Backend Service onStartCommand")

        // Start in the foreground with a notification
        startForeground(NOTIFICATION_ID, createNotification())

        // Acquire wake lock to keep the service running
        acquireWakeLock()

        if (!isRunning) {
            Log.i(TAG, "Starting DSM backend components")

            // Start the DSM core
            launch {
                try {
                    dsmCore.start()
                    Log.i(TAG, "DSM Core started successfully")
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to start DSM Core", e)
                }
            }

            // Start the HTTP server
            launch {
                try {
                    httpServer.start()
                    Log.i(TAG, "HTTP Server started successfully")
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to start HTTP Server", e)
                }
            }

            // Start the Bluetooth service if enabled
            val prefs = getSharedPreferences("dsm_service_config", Context.MODE_PRIVATE)
            val bluetoothEnabled = prefs.getBoolean("bluetooth_enabled", true)

            if (bluetoothEnabled) {
                launch {
                    try {
                        bluetoothService.start()
                        Log.i(TAG, "Bluetooth Service started successfully")
                    } catch (e: Exception) {
                        Log.e(TAG, "Failed to start Bluetooth Service", e)
                    }
                }
            }

            isRunning = true
        } else {
            Log.i(TAG, "DSM Backend Service already running")
        }

        // Return START_STICKY to ensure the service restarts if it's killed
        return START_STICKY
    }

    override fun onDestroy() {
        Log.i(TAG, "DSM Backend Service onDestroy")

        isRunning = false

        // Stop the Bluetooth service
        launch {
            try {
                bluetoothService.stop()
                Log.i(TAG, "Bluetooth Service stopped successfully")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to stop Bluetooth Service", e)
            }
        }

        // Stop the HTTP server
        launch {
            try {
                httpServer.stop()
                Log.i(TAG, "HTTP Server stopped successfully")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to stop HTTP Server", e)
            }
        }

        // Stop the DSM core
        launch {
            try {
                dsmCore.stop()
                Log.i(TAG, "DSM Core stopped successfully")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to stop DSM Core", e)
            }
        }

        // Cancel all coroutines
        job.cancel()

        // Release the wake lock
        releaseWakeLock()

        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? {
        // This service does not support binding
        return null
    }

    /**
     * Creates the notification channel required for Android 8.0 and above
     */
    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val name = "DSM Backend Service"
            val description = "Notification channel for the DSM Backend Service"
            val importance = NotificationManager.IMPORTANCE_LOW

            val channel = NotificationChannel(CHANNEL_ID, name, importance).apply {
                this.description = description
            }

            val notificationManager = getSystemService(NotificationManager::class.java)
            notificationManager?.createNotificationChannel(channel)
        }
    }

    /**
     * Creates the notification for the foreground service
     */
    private fun createNotification(): Notification {
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("DSM Backend Service")
            .setContentText("Running in the background")
            .setSmallIcon(android.R.drawable.ic_lock_idle_lock)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }

    /**
     * Acquires a wake lock to keep the service running
     */
    private fun acquireWakeLock() {
        if (wakeLock == null) {
            val powerManager = getSystemService(Context.POWER_SERVICE) as PowerManager
            wakeLock = powerManager.newWakeLock(
                PowerManager.PARTIAL_WAKE_LOCK,
                "DSM:BackendWakeLock"
            ).apply {
                acquire()
            }
            Log.i(TAG, "Wake lock acquired")
        }
    }

    /**
     * Releases the wake lock
     */
    private fun releaseWakeLock() {
        wakeLock?.let {
            if (it.isHeld) {
                it.release()
                wakeLock = null
                Log.i(TAG, "Wake lock released")
            }
        }
    }

    /**
     * Initializes the data directories for the DSM backend
     */
    private fun initializeDataDirectories() {
        // Define the base data directory
        val dataDir = File(filesDir, "dsm_service")

        // Create the main data directory
        if (!dataDir.exists() && !dataDir.mkdirs()) {
            Log.e(TAG, "Failed to create data directory: ${dataDir.absolutePath}")
        }

        // Create subdirectories
        val subdirs = arrayOf(
            "identities",
            "tokens",
            "commitments",
            "unilateral",
            "vaults",
            "logs",
            "namespaces"
        )

        for (subdir in subdirs) {
            val dir = File(dataDir, subdir)
            if (!dir.exists() && !dir.mkdirs()) {
                Log.e(TAG, "Failed to create subdirectory: ${dir.absolutePath}")
            }
        }

        // Create a default configuration file if it doesn't exist
        val configFile = File(dataDir, "config.json")
        if (!configFile.exists()) {
            try {
                createDefaultConfig(configFile)
            } catch (e: IOException) {
                Log.e(TAG, "Failed to create default configuration file", e)
            }
        }
    }

    /**
     * Creates a default configuration file for the DSM backend
     */
    private fun createDefaultConfig(configFile: File) {
        // Default configuration as JSON
        val defaultConfig = """
        {
          "server": {
            "host": "127.0.0.1",
            "port": 7545
          },
          "storage": {
            "data_dir": "${filesDir.absolutePath}/dsm_service"
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
        """.trimIndent()

        // Write to the file
        configFile.writeText(defaultConfig)
    }

    /**
     * Gets the data directory path for the DSM backend
     */
    fun getDataDirectoryPath(): String {
        return File(filesDir, "dsm_service").absolutePath
    }

    /**
     * Gets the current configuration as a SharedPreferences object
     */
    fun getConfiguration(): SharedPreferences {
        return getSharedPreferences("dsm_service_config", Context.MODE_PRIVATE)
    }
}
