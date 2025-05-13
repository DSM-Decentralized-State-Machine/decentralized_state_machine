package dsm.service

import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothServerSocket
import android.bluetooth.BluetoothSocket
import android.content.Context
import android.os.Build
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.util.UUID
import kotlin.coroutines.CoroutineContext

/**
 * Bluetooth service for device-to-device communication in the DSM backend.
 * This service allows direct communication between devices running the DSM backend
 * without requiring internet connectivity.
 */
class DsmBluetoothService(
    private val context: Context,
    private val dsmCore: DsmCore
) : CoroutineScope {
    companion object {
        private const val TAG = "DsmBluetoothService"
        private const val SERVICE_NAME = "DsmBluetoothService"
        private const val DEFAULT_UUID = "00001101-0000-1000-8000-00805F9B34FB"
        private const val BUFFER_SIZE = 4096
    }

    // Coroutine context for async operations
    private val job = Job()
    override val coroutineContext: CoroutineContext
        get() = Dispatchers.IO + job

    // Bluetooth adapter
    private val bluetoothAdapter: BluetoothAdapter? by lazy {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            val bluetoothManager = context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
            bluetoothManager.adapter
        } else {
            @Suppress("DEPRECATION")
            BluetoothAdapter.getDefaultAdapter()
        }
    }

    // Server socket
    private var serverSocket: BluetoothServerSocket? = null

    // Flag to indicate if the service is running
    private var isRunning = false

    // Get the service UUID from configuration
    private val serviceUuid: UUID
        get() {
            val prefs = context.getSharedPreferences("dsm_service_config", Context.MODE_PRIVATE)
            val uuidStr = prefs.getString("bluetooth_service_uuid", DEFAULT_UUID)
            return UUID.fromString(uuidStr)
        }

    /**
     * Starts the Bluetooth service
     */
    suspend fun start() {
        if (isRunning) {
            Log.w(TAG, "Bluetooth service is already running")
            return
        }

        // Check if Bluetooth is supported and enabled
        if (bluetoothAdapter == null) {
            Log.e(TAG, "Bluetooth is not supported on this device")
            return
        }

        if (bluetoothAdapter?.isEnabled != true) {
            Log.w(TAG, "Bluetooth is not enabled")
            return
        }

        withContext(Dispatchers.IO) {
            try {
                // Create a new listening server socket
                serverSocket = bluetoothAdapter?.listenUsingInsecureRfcommWithServiceRecord(
                    SERVICE_NAME,
                    serviceUuid
                )

                Log.i(TAG, "Bluetooth service started with UUID: $serviceUuid")

                // Flag the service as running
                isRunning = true

                // Start accepting client connections
                launch { acceptConnections() }
            } catch (e: IOException) {
                Log.e(TAG, "Error starting Bluetooth service", e)
            }
        }
    }

    /**
     * Stops the Bluetooth service
     */
    fun stop() {
        if (!isRunning) {
            Log.w(TAG, "Bluetooth service is not running")
            return
        }

        // Flag the service as not running
        isRunning = false

        // Close the server socket
        serverSocket?.let {
            try {
                it.close()
            } catch (e: IOException) {
                Log.e(TAG, "Error closing Bluetooth server socket", e)
            }
        }
        serverSocket = null

        // Cancel all coroutines
        job.cancel()

        Log.i(TAG, "Bluetooth service stopped")
    }

    /**
     * Accepts Bluetooth client connections
     */
    private suspend fun acceptConnections() {
        try {
            val socket = serverSocket ?: return

            while (isRunning) {
                try {
                    // This will block until a connection is accepted or an exception occurs
                    val clientSocket = socket.accept()
                    Log.i(TAG, "Accepted connection from ${clientSocket.remoteDevice.address}")

                    // Handle the connection in a separate coroutine
                    launch { handleClientConnection(clientSocket) }
                } catch (e: IOException) {
                    if (isRunning) {
                        Log.e(TAG, "Error accepting Bluetooth connection", e)
                    }
                }
            }
        } catch (e: Exception) {
            if (isRunning) {
                Log.e(TAG, "Error in Bluetooth connection acceptance loop", e)
            }
        }
    }

    /**
     * Handles a Bluetooth client connection
     *
     * @param socket The client socket
     */
    private suspend fun handleClientConnection(socket: BluetoothSocket) {
        var inputStream: InputStream? = null
        var outputStream: OutputStream? = null

        try {
            inputStream = socket.inputStream
            outputStream = socket.outputStream

            // Read command from the client
            val buffer = ByteArray(BUFFER_SIZE)
            val bytes = inputStream.read(buffer)

            if (bytes > 0) {
                val message = String(buffer, 0, bytes)
                try {
                    // Parse the message as JSON
                    val request = JSONObject(message)
                    val command = request.getString("command")
                    val params = request.optJSONObject("params") ?: JSONObject()

                    // Handle the command
                    val response = handleCommand(command, params)
                    
                    // Send the response
                    outputStream.write(response.toString().toByteArray())
                } catch (e: Exception) {
                    Log.e(TAG, "Error processing Bluetooth message", e)
                    
                    // Send error response
                    val errorResponse = JSONObject().apply {
                        put("success", false)
                        put("error", e.message ?: "Unknown error")
                    }
                    outputStream.write(errorResponse.toString().toByteArray())
                }
            }
        } catch (e: IOException) {
            Log.e(TAG, "Error handling Bluetooth client connection", e)
        } finally {
            // Clean up the connection
            try {
                inputStream?.close()
                outputStream?.close()
                socket.close()
            } catch (e: IOException) {
                Log.e(TAG, "Error closing Bluetooth connection", e)
            }
        }
    }

    /**
     * Handles a command received over Bluetooth
     *
     * @param command The command to handle
     * @param params The command parameters
     * @return The response as a JSONObject
     */
    private suspend fun handleCommand(command: String, params: JSONObject): JSONObject {
        return when (command) {
            "get_identities" -> {
                JSONObject().apply {
                    put("success", true)
                    put("data", dsmCore.getIdentities())
                }
            }
            "create_identity" -> {
                val deviceId = params.optString("device_id") ?: UUID.randomUUID().toString()
                val identity = dsmCore.createIdentity(deviceId)
                
                JSONObject().apply {
                    put("success", true)
                    put("data", identity)
                }
            }
            "get_identity" -> {
                val identityId = params.getString("identity_id")
                val identity = dsmCore.getIdentity(identityId)
                
                JSONObject().apply {
                    put("success", true)
                    put("data", identity)
                }
            }
            "create_vault" -> {
                val vault = dsmCore.createVault(params)
                
                JSONObject().apply {
                    put("success", true)
                    put("data", vault)
                }
            }
            "get_vaults" -> {
                JSONObject().apply {
                    put("success", true)
                    put("data", dsmCore.getVaults())
                }
            }
            "get_vault" -> {
                val vaultId = params.getString("vault_id")
                val vault = dsmCore.getVault(vaultId)
                
                JSONObject().apply {
                    put("success", true)
                    put("data", vault)
                }
            }
            "apply_operation" -> {
                val result = dsmCore.applyOperation(params)
                
                JSONObject().apply {
                    put("success", true)
                    put("data", result)
                }
            }
            "get_operations" -> {
                JSONObject().apply {
                    put("success", true)
                    put("data", dsmCore.getOperations())
                }
            }
            "create_namespace" -> {
                val namespace = dsmCore.createNamespace(params)
                
                JSONObject().apply {
                    put("success", true)
                    put("data", namespace)
                }
            }
            "get_namespaces" -> {
                JSONObject().apply {
                    put("success", true)
                    put("data", dsmCore.getNamespaces())
                }
            }
            else -> {
                JSONObject().apply {
                    put("success", false)
                    put("error", "Unknown command: $command")
                }
            }
        }
    }
}
