package dsm.client

import android.Manifest
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothSocket
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import androidx.core.app.ActivityCompat
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.util.UUID

/**
 * Client for direct device-to-device communication with the DSM backend via Bluetooth.
 * This client is useful in situations where HTTP connectivity is not available.
 */
class DsmBluetoothClient(
    private val context: Context,
    private val serviceUuid: UUID = UUID.fromString("00001101-0000-1000-8000-00805F9B34FB")
) {
    companion object {
        private const val TAG = "DsmBluetoothClient"
        private const val BUFFER_SIZE = 4096
    }
    
    // The Bluetooth adapter
    private val bluetoothAdapter: BluetoothAdapter? by lazy {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            val bluetoothManager = context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
            bluetoothManager.adapter
        } else {
            @Suppress("DEPRECATION")
            BluetoothAdapter.getDefaultAdapter()
        }
    }
    
    /**
     * Checks if Bluetooth is available and enabled on this device.
     * 
     * @return true if Bluetooth is available and enabled, false otherwise
     */
    fun isBluetoothAvailable(): Boolean {
        return bluetoothAdapter != null && bluetoothAdapter?.isEnabled == true
    }
    
    /**
     * Discovers DSM backend services on nearby devices.
     * 
     * @return A list of Bluetooth devices running the DSM backend
     */
    suspend fun discoverDsmServices(): List<BluetoothDevice> {
        if (!isBluetoothAvailable()) {
            throw IOException("Bluetooth is not available or enabled")
        }
        
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S &&
            ActivityCompat.checkSelfPermission(
                context,
                Manifest.permission.BLUETOOTH_SCAN
            ) != PackageManager.PERMISSION_GRANTED
        ) {
            throw IOException("Bluetooth scan permission not granted")
        }
        
        return withContext(Dispatchers.IO) {
            // This is a simplified implementation
            // In a real app, you would need to register a BroadcastReceiver for device discovery
            // For demonstration, we'll just return paired devices that might be running DSM
            
            // Get paired devices
            val pairedDevices = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S &&
                ActivityCompat.checkSelfPermission(
                    context,
                    Manifest.permission.BLUETOOTH_CONNECT
                ) != PackageManager.PERMISSION_GRANTED
            ) {
                // Permission not granted
                emptySet()
            } else {
                @Suppress("DEPRECATION")
                bluetoothAdapter?.bondedDevices ?: emptySet()
            }
            
            pairedDevices.toList()
        }
    }
    
    /**
     * Connects to a DSM backend service on a Bluetooth device.
     * 
     * @param device The Bluetooth device to connect to
     * @return A connection to the device
     */
    suspend fun connectToDevice(device: BluetoothDevice): DsmBluetoothConnection {
        if (!isBluetoothAvailable()) {
            throw IOException("Bluetooth is not available or enabled")
        }
        
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S &&
            ActivityCompat.checkSelfPermission(
                context,
                Manifest.permission.BLUETOOTH_CONNECT
            ) != PackageManager.PERMISSION_GRANTED
        ) {
            throw IOException("Bluetooth connect permission not granted")
        }
        
        return withContext(Dispatchers.IO) {
            try {
                @Suppress("DEPRECATION")
                val socket = device.createRfcommSocketToServiceRecord(serviceUuid)
                socket.connect()
                DsmBluetoothConnection(socket)
            } catch (e: IOException) {
                Log.e(TAG, "Error connecting to device: ${device.address}", e)
                throw IOException("Failed to connect to device: ${e.message}")
            }
        }
    }
    
    /**
     * A connection to a DSM backend service over Bluetooth.
     * This class handles communication with the DSM backend.
     */
    inner class DsmBluetoothConnection(private val socket: BluetoothSocket) {
        private val inputStream: InputStream = socket.inputStream
        private val outputStream: OutputStream = socket.outputStream
        
        /**
         * Sends a command to the DSM backend.
         * 
         * @param command The command to send
         * @param params Parameters for the command
         * @return The response from the backend
         */
        suspend fun sendCommand(command: String, params: JSONObject = JSONObject()): JSONObject {
            return withContext(Dispatchers.IO) {
                val request = JSONObject().apply {
                    put("command", command)
                    put("params", params)
                }
                
                val requestBytes = request.toString().toByteArray()
                outputStream.write(requestBytes)
                
                // Read the response
                val buffer = ByteArray(BUFFER_SIZE)
                val bytes = inputStream.read(buffer)
                
                if (bytes > 0) {
                    val response = String(buffer, 0, bytes)
                    try {
                        JSONObject(response)
                    } catch (e: Exception) {
                        JSONObject().apply {
                            put("success", false)
                            put("error", "Invalid response: $response")
                        }
                    }
                } else {
                    JSONObject().apply {
                        put("success", false)
                        put("error", "Empty response")
                    }
                }
            }
        }
        
        /**
         * Gets all identities from the DSM backend.
         * 
         * @return A list of identities
         */
        suspend fun getIdentities(): List<Identity> {
            val response = sendCommand("get_identities")
            
            if (!response.optBoolean("success", false)) {
                throw IOException("Failed to get identities: ${response.optString("error", "Unknown error")}")
            }
            
            val data = response.getJSONObject("data")
            val identitiesArray = data.getJSONArray("identities")
            
            val result = mutableListOf<Identity>()
            
            for (i in 0 until identitiesArray.length()) {
                val identityObj = identitiesArray.getJSONObject(i)
                result.add(
                    Identity(
                        id = identityObj.getString("id"),
                        deviceId = identityObj.getString("device_id"),
                        createdAt = identityObj.optLong("created_at")
                    )
                )
            }
            
            return result
        }
        
        /**
         * Creates a new identity on the DSM backend.
         * 
         * @param deviceId The device ID (optional)
         * @return The created identity
         */
        suspend fun createIdentity(deviceId: String? = null): Identity {
            val params = JSONObject().apply {
                deviceId?.let { put("device_id", it) }
            }
            
            val response = sendCommand("create_identity", params)
            
            if (!response.optBoolean("success", false)) {
                throw IOException("Failed to create identity: ${response.optString("error", "Unknown error")}")
            }
            
            val data = response.getJSONObject("data")
            
            return Identity(
                id = data.getString("id"),
                deviceId = data.getString("device_id"),
                createdAt = data.optLong("created_at")
            )
        }
        
        /**
         * Gets a specific identity from the DSM backend.
         * 
         * @param identityId The identity ID
         * @return The identity
         */
        suspend fun getIdentity(identityId: String): Identity {
            val params = JSONObject().apply {
                put("identity_id", identityId)
            }
            
            val response = sendCommand("get_identity", params)
            
            if (!response.optBoolean("success", false)) {
                throw IOException("Failed to get identity: ${response.optString("error", "Unknown error")}")
            }
            
            val data = response.getJSONObject("data")
            
            return Identity(
                id = data.getString("id"),
                deviceId = data.getString("device_id"),
                createdAt = data.optLong("created_at")
            )
        }
        
        /**
         * Creates a new vault on the DSM backend.
         * 
         * @param identityId The identity ID
         * @param name The vault name (optional)
         * @return The created vault
         */
        suspend fun createVault(identityId: String, name: String? = null): Vault {
            val params = JSONObject().apply {
                put("identity_id", identityId)
                name?.let { put("name", it) }
            }
            
            val response = sendCommand("create_vault", params)
            
            if (!response.optBoolean("success", false)) {
                throw IOException("Failed to create vault: ${response.optString("error", "Unknown error")}")
            }
            
            val data = response.getJSONObject("data")
            
            return Vault(
                id = data.getString("id"),
                identityId = data.getString("identity_id"),
                name = data.optString("name"),
                createdAt = data.optLong("created_at"),
                data = data.optJSONObject("data")
            )
        }
        
        /**
         * Gets all vaults from the DSM backend.
         * 
         * @return A list of vaults
         */
        suspend fun getVaults(): List<Vault> {
            val response = sendCommand("get_vaults")
            
            if (!response.optBoolean("success", false)) {
                throw IOException("Failed to get vaults: ${response.optString("error", "Unknown error")}")
            }
            
            val data = response.getJSONObject("data")
            val vaultsArray = data.getJSONArray("vaults")
            
            val result = mutableListOf<Vault>()
            
            for (i in 0 until vaultsArray.length()) {
                val vaultObj = vaultsArray.getJSONObject(i)
                result.add(
                    Vault(
                        id = vaultObj.getString("id"),
                        identityId = vaultObj.getString("identity_id"),
                        name = vaultObj.optString("name"),
                        createdAt = vaultObj.optLong("created_at"),
                        data = vaultObj.optJSONObject("data")
                    )
                )
            }
            
            return result
        }
        
        /**
         * Gets a specific vault from the DSM backend.
         * 
         * @param vaultId The vault ID
         * @return The vault
         */
        suspend fun getVault(vaultId: String): Vault {
            val params = JSONObject().apply {
                put("vault_id", vaultId)
            }
            
            val response = sendCommand("get_vault", params)
            
            if (!response.optBoolean("success", false)) {
                throw IOException("Failed to get vault: ${response.optString("error", "Unknown error")}")
            }
            
            val data = response.getJSONObject("data")
            
            return Vault(
                id = data.getString("id"),
                identityId = data.getString("identity_id"),
                name = data.optString("name"),
                createdAt = data.optLong("created_at"),
                data = data.optJSONObject("data")
            )
        }
        
        /**
         * Applies an operation to the state machine.
         * 
         * @param operationType The type of operation
         * @param message An optional message for the operation
         * @param data Additional data for the operation
         * @return The result of applying the operation
         */
        suspend fun applyOperation(
            operationType: String,
            message: String? = null,
            data: JSONObject? = null
        ): Operation {
            val params = JSONObject().apply {
                put("operation_type", operationType)
                message?.let { put("message", it) }
                data?.let { put("data", it) }
            }
            
            val response = sendCommand("apply_operation", params)
            
            if (!response.optBoolean("success", false)) {
                throw IOException("Failed to apply operation: ${response.optString("error", "Unknown error")}")
            }
            
            val responseData = response.getJSONObject("data")
            val operationObj = responseData.getJSONObject("operation")
            
            return Operation(
                type = operationObj.getString("operation_type"),
                message = operationObj.optString("message"),
                data = operationObj.optJSONObject("data"),
                timestamp = operationObj.optLong("timestamp"),
                previousState = operationObj.optString("previous_state"),
                nextState = operationObj.optString("next_state")
            )
        }
        
        /**
         * Closes the Bluetooth connection.
         */
        fun close() {
            try {
                socket.close()
            } catch (e: IOException) {
                Log.e(TAG, "Error closing Bluetooth socket", e)
            }
        }
    }
}
