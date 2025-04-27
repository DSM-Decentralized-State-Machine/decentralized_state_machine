package dsm.client

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.content.SharedPreferences
import android.os.Build
import android.os.IBinder
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import org.json.JSONException
import org.json.JSONObject
import java.io.BufferedReader
import java.io.IOException
import java.io.InputStreamReader
import java.io.OutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.nio.charset.StandardCharsets
import java.util.UUID
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * Client SDK for Android applications to connect to the DSM backend service.
 * 
 * This client provides a Kotlin-based API for interacting with the DSM backend,
 * including identity management, vault operations, and state machine operations.
 */
class DsmClient private constructor(
    private val context: Context,
    private val backendUrl: String,
    private val apiVersion: String,
    private val namespace: String?
) {
    companion object {
        private const val TAG = "DsmClient"
        private const val DEFAULT_BACKEND_URL = "http://127.0.0.1:7545"
        private const val DEFAULT_API_VERSION = "v1"
        private const val DEFAULT_CONNECTION_TIMEOUT_MS = 10000 // 10 seconds
        private const val DEFAULT_RETRY_ATTEMPTS = 3
        
        /**
         * Creates a client with default settings and no namespace (shared state).
         * 
         * @param context The Android context
         * @return A new DSM client
         */
        @JvmStatic
        fun createWithDefaults(context: Context): DsmClient {
            return DsmClient(context, DEFAULT_BACKEND_URL, DEFAULT_API_VERSION, null)
        }
        
        /**
         * Creates a client with default settings and a specific namespace.
         * 
         * @param context The Android context
         * @param namespace The application namespace for isolated state
         * @return A new DSM client
         */
        @JvmStatic
        fun createWithNamespace(context: Context, namespace: String): DsmClient {
            return DsmClient(context, DEFAULT_BACKEND_URL, DEFAULT_API_VERSION, namespace)
        }
        
        /**
         * Creates a client with custom settings.
         * 
         * @param context The Android context
         * @param backendUrl The URL of the DSM backend
         * @param apiVersion The API version to use
         * @param namespace The application namespace (or null for shared state)
         * @return A new DSM client
         */
        @JvmStatic
        fun create(
            context: Context,
            backendUrl: String,
            apiVersion: String,
            namespace: String?
        ): DsmClient {
            return DsmClient(context, backendUrl, apiVersion, namespace)
        }
    }
    
    // Client configuration
    private var connectionTimeout: Int = DEFAULT_CONNECTION_TIMEOUT_MS
    private var retryAttempts: Int = DEFAULT_RETRY_ATTEMPTS
    private var bluetoothEnabled: Boolean = true
    private var autoSyncInterval: Long = 60000 // 1 minute
    
    // Service connection
    private var serviceConnection: ServiceConnection? = null
    private var serviceBound: Boolean = false
    
    init {
        // Load configuration from shared preferences
        loadConfig()
    }
    
    /**
     * Loads the client configuration from shared preferences.
     */
    private fun loadConfig() {
        try {
            val prefs = context.getSharedPreferences("dsm_client_config", Context.MODE_PRIVATE)
            
            connectionTimeout = prefs.getInt("connection_timeout_ms", DEFAULT_CONNECTION_TIMEOUT_MS)
            retryAttempts = prefs.getInt("retry_attempts", DEFAULT_RETRY_ATTEMPTS)
            bluetoothEnabled = prefs.getBoolean("bluetooth_enabled", true)
            autoSyncInterval = prefs.getLong("auto_sync_interval_ms", 60000)
            
            Log.i(TAG, "Loaded client configuration from shared preferences")
        } catch (e: Exception) {
            Log.e(TAG, "Error loading client configuration", e)
        }
    }
    
    /**
     * Saves the client configuration to shared preferences.
     */
    fun saveConfig() {
        try {
            val prefs = context.getSharedPreferences("dsm_client_config", Context.MODE_PRIVATE)
            prefs.edit().apply {
                putInt("connection_timeout_ms", connectionTimeout)
                putInt("retry_attempts", DEFAULT_RETRY_ATTEMPTS)
                putBoolean("bluetooth_enabled", bluetoothEnabled)
                putLong("auto_sync_interval_ms", autoSyncInterval)
                
                if (namespace != null) {
                    putString("namespace", namespace)
                }
                
                apply()
            }
            
            Log.i(TAG, "Saved client configuration to shared preferences")
        } catch (e: Exception) {
            Log.e(TAG, "Error saving client configuration", e)
        }
    }
    
    /**
     * Ensures the DSM backend service is installed and running.
     * If the service is not installed, it will attempt to install and start it.
     * 
     * @return true if the service is available, false otherwise
     */
    suspend fun ensureServiceAvailable(): Boolean {
        // First check if the service is already running
        if (await checkConnection()) {
            return true
        }
        
        // Attempt to start the service if it's installed
        if (isServiceInstalled()) {
            startService()
            // Wait for the service to start
            return withTimeoutOrNull(5000) {
                var isConnected = false
                while (!isConnected) {
                    isConnected = checkConnection()
                    if (!isConnected) {
                        kotlinx.coroutines.delay(500)
                    }
                }
                true
            } ?: false
        }
        
        // Service is not installed, we would need to guide the user to install it
        return false
    }
    
    /**
     * Checks if the DSM backend service is installed on the device.
     * 
     * @return true if the service is installed, false otherwise
     */
    private fun isServiceInstalled(): Boolean {
        val intent = Intent("dsm.service.DsmBackendService")
        intent.setPackage("dsm.service")
        val resolveInfo = context.packageManager.resolveService(intent, 0)
        return resolveInfo != null
    }
    
    /**
     * Starts the DSM backend service.
     */
    private fun startService() {
        val intent = Intent("dsm.service.DsmBackendService")
        intent.setPackage("dsm.service")
        
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            context.startForegroundService(intent)
        } else {
            context.startService(intent)
        }
    }
    
    /**
     * Binds to the DSM backend service.
     * 
     * @return true if binding was successful, false otherwise
     */
    suspend fun bindService(): Boolean = suspendCancellableCoroutine { continuation ->
        if (serviceBound) {
            continuation.resume(true)
            return@suspendCancellableCoroutine
        }
        
        val intent = Intent("dsm.service.DsmBackendService")
        intent.setPackage("dsm.service")
        
        val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
                serviceBound = true
                serviceConnection = this
                continuation.resume(true)
            }
            
            override fun onServiceDisconnected(name: ComponentName?) {
                serviceBound = false
                serviceConnection = null
                // We don't resume here as the continuation is likely already complete
            }
        }
        
        val bindResult = context.bindService(intent, connection, Context.BIND_AUTO_CREATE)
        
        if (!bindResult) {
            serviceConnection = null
            continuation.resume(false)
        }
        
        continuation.invokeOnCancellation {
            if (serviceBound) {
                context.unbindService(connection)
                serviceBound = false
                serviceConnection = null
            }
        }
    }
    
    /**
     * Unbinds from the DSM backend service.
     */
    fun unbindService() {
        serviceConnection?.let {
            context.unbindService(it)
            serviceBound = false
            serviceConnection = null
        }
    }
    
    /**
     * Checks if the backend service is available.
     * 
     * @return true if the service is available, false otherwise
     */
    suspend fun checkConnection(): Boolean {
        return try {
            val response = sendGetRequest("/health")
            
            // If we get a response, check that it has the right status
            response.optString("status") == "running"
        } catch (e: Exception) {
            Log.e(TAG, "Error checking connection to DSM backend", e)
            false
        }
    }
    
    /**
     * Creates a new identity on the DSM backend.
     * 
     * @param deviceId The device ID (optional, will generate a random UUID if not provided)
     * @return The identity ID
     */
    suspend fun createIdentity(deviceId: String? = null): String {
        val actualDeviceId = deviceId ?: UUID.randomUUID().toString()
        
        val requestBody = JSONObject().apply {
            put("device_id", actualDeviceId)
            namespace?.let { put("namespace", it) }
        }
        
        val response = sendPostRequest("/api/v1/identities", requestBody)
        
        if (!response.optBoolean("success", false)) {
            throw IOException("Failed to create identity: ${response.optString("error", "Unknown error")}")
        }
        
        val data = response.getJSONObject("data")
        return data.getString("id")
    }
    
    /**
     * Gets all identities from the DSM backend.
     * 
     * @return A list of identities
     */
    suspend fun getIdentities(): List<Identity> {
        val path = buildPath("/api/v1/identities")
        
        val response = sendGetRequest(path)
        
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
     * Gets a specific identity from the DSM backend.
     * 
     * @param identityId The identity ID
     * @return The identity
     */
    suspend fun getIdentity(identityId: String): Identity {
        val path = buildPath("/api/v1/identities/$identityId")
        
        val response = sendGetRequest(path)
        
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
     * @return The vault ID
     */
    suspend fun createVault(identityId: String, name: String? = null): String {
        val requestBody = JSONObject().apply {
            put("identity_id", identityId)
            name?.let { put("name", it) }
            namespace?.let { put("namespace", it) }
        }
        
        val response = sendPostRequest("/api/v1/vaults", requestBody)
        
        if (!response.optBoolean("success", false)) {
            throw IOException("Failed to create vault: ${response.optString("error", "Unknown error")}")
        }
        
        val data = response.getJSONObject("data")
        return data.getString("id")
    }
    
    /**
     * Gets all vaults from the DSM backend.
     * 
     * @return A list of vaults
     */
    suspend fun getVaults(): List<Vault> {
        val path = buildPath("/api/v1/vaults")
        
        val response = sendGetRequest(path)
        
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
        val path = buildPath("/api/v1/vaults/$vaultId")
        
        val response = sendGetRequest(path)
        
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
     * Updates a vault's data.
     * 
     * @param vaultId The vault ID
     * @param vaultData The new vault data
     * @return True if the update was successful
     */
    suspend fun updateVault(vaultId: String, vaultData: JSONObject): Boolean {
        val requestBody = JSONObject().apply {
            put("vault_id", vaultId)
            put("data", vaultData)
            namespace?.let { put("namespace", it) }
        }
        
        val response = sendPostRequest("/api/v1/vaults/$vaultId/update", requestBody)
        
        return response.optBoolean("success", false)
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
        val requestBody = JSONObject().apply {
            put("operation_type", operationType)
            message?.let { put("message", it) }
            data?.let { put("data", it) }
            namespace?.let { put("namespace", it) }
        }
        
        val response = sendPostRequest("/api/v1/operations", requestBody)
        
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
     * Gets all recent operations from the DSM backend.
     * 
     * @return A list of operations and the current state hash
     */
    suspend fun getOperations(): Pair<List<Operation>, String> {
        val path = buildPath("/api/v1/operations")
        
        val response = sendGetRequest(path)
        
        if (!response.optBoolean("success", false)) {
            throw IOException("Failed to get operations: ${response.optString("error", "Unknown error")}")
        }
        
        val data = response.getJSONObject("data")
        val operationsArray = data.getJSONArray("operations")
        val currentState = data.getString("current_state")
        
        val operations = mutableListOf<Operation>()
        
        for (i in 0 until operationsArray.length()) {
            val opObj = operationsArray.getJSONObject(i)
            operations.add(
                Operation(
                    type = opObj.getString("operation_type"),
                    message = opObj.optString("message"),
                    data = opObj.optJSONObject("data"),
                    timestamp = opObj.optLong("timestamp"),
                    previousState = opObj.optString("previous_state"),
                    nextState = opObj.optString("next_state")
                )
            )
        }
        
        return Pair(operations, currentState)
    }
    
    /**
     * Creates a new namespace on the DSM backend.
     * 
     * @param name The namespace name
     * @param description An optional description of the namespace
     * @return The namespace ID
     */
    suspend fun createNamespace(name: String, description: String? = null): String {
        val requestBody = JSONObject().apply {
            put("name", name)
            description?.let { put("description", it) }
        }
        
        val response = sendPostRequest("/api/v1/namespaces", requestBody)
        
        if (!response.optBoolean("success", false)) {
            throw IOException("Failed to create namespace: ${response.optString("error", "Unknown error")}")
        }
        
        val data = response.getJSONObject("data")
        return data.getString("id")
    }
    
    /**
     * Gets all namespaces from the DSM backend.
     * 
     * @return A list of namespaces
     */
    suspend fun getNamespaces(): List<Namespace> {
        val response = sendGetRequest("/api/v1/namespaces")
        
        if (!response.optBoolean("success", false)) {
            throw IOException("Failed to get namespaces: ${response.optString("error", "Unknown error")}")
        }
        
        val data = response.getJSONObject("data")
        val namespacesArray = data.getJSONArray("namespaces")
        
        val result = mutableListOf<Namespace>()
        
        for (i in 0 until namespacesArray.length()) {
            val nsObj = namespacesArray.getJSONObject(i)
            result.add(
                Namespace(
                    id = nsObj.getString("id"),
                    name = nsObj.getString("name"),
                    description = nsObj.optString("description"),
                    createdAt = nsObj.optLong("created_at")
                )
            )
        }
        
        return result
    }
    
    /**
     * Registers this device for push notifications.
     * 
     * @param appId The application ID
     * @param deviceToken The device token for push notifications
     * @param topics Optional topics to subscribe to
     * @return The registration ID
     */
    suspend fun registerForNotifications(
        appId: String,
        deviceToken: String,
        topics: List<String>? = null
    ): String {
        val requestBody = JSONObject().apply {
            put("app_id", appId)
            put("device_token", deviceToken)
            put("platform", "android")
            
            namespace?.let { put("namespace", it) }
            
            topics?.let {
                val topicsArray = org.json.JSONArray()
                for (topic in it) {
                    topicsArray.put(topic)
                }
                put("topics", topicsArray)
            }
        }
        
        val response = sendPostRequest("/api/v1/notifications/register", requestBody)
        
        if (!response.optBoolean("success", false)) {
            throw IOException("Failed to register for notifications: ${response.optString("error", "Unknown error")}")
        }
        
        val data = response.getJSONObject("data")
        return data.getString("registration_id")
    }
    
    /**
     * Adds namespace parameter to path if a namespace is specified.
     * 
     * @param path The API path
     * @return The path with namespace parameter if needed
     */
    private fun buildPath(path: String): String {
        return if (namespace != null) {
            if (path.contains("?")) {
                "$path&namespace=$namespace"
            } else {
                "$path?namespace=$namespace"
            }
        } else {
            path
        }
    }
    
    /**
     * Sends a GET request to the DSM backend.
     * 
     * @param path The API path
     * @return The response as a JSONObject
     * @throws IOException If there is an error sending the request
     * @throws JSONException If there is an error parsing the response
     */
    private suspend fun sendGetRequest(path: String): JSONObject {
        return withContext(Dispatchers.IO) {
            val url = URL("$backendUrl$path")
            val connection = url.openConnection() as HttpURLConnection
            connection.apply {
                requestMethod = "GET"
                connectTimeout = connectionTimeout
                readTimeout = connectionTimeout
            }
            
            try {
                val responseCode = connection.responseCode
                
                if (responseCode == HttpURLConnection.HTTP_OK) {
                    val reader = BufferedReader(InputStreamReader(connection.inputStream))
                    val response = StringBuilder()
                    var line: String?
                    
                    while (reader.readLine().also { line = it } != null) {
                        response.append(line)
                    }
                    
                    reader.close()
                    
                    JSONObject(response.toString())
                } else {
                    throw IOException("HTTP error code: $responseCode")
                }
            } finally {
                connection.disconnect()
            }
        }
    }
    
    /**
     * Sends a POST request to the DSM backend.
     * 
     * @param path The API path
     * @param requestBody The request body as a JSONObject
     * @return The response as a JSONObject
     * @throws IOException If there is an error sending the request
     * @throws JSONException If there is an error parsing the response
     */
    private suspend fun sendPostRequest(path: String, requestBody: JSONObject): JSONObject {
        return withContext(Dispatchers.IO) {
            val url = URL("$backendUrl$path")
            val connection = url.openConnection() as HttpURLConnection
            connection.apply {
                requestMethod = "POST"
                setRequestProperty("Content-Type", "application/json")
                connectTimeout = connectionTimeout
                readTimeout = connectionTimeout
                doOutput = true
            }
            
            // Write the request body
            try {
                connection.outputStream.use { os ->
                    val input = requestBody.toString().toByteArray(StandardCharsets.UTF_8)
                    os.write(input, 0, input.size)
                }
                
                val responseCode = connection.responseCode
                
                if (responseCode == HttpURLConnection.HTTP_OK || responseCode == HttpURLConnection.HTTP_CREATED) {
                    val reader = BufferedReader(InputStreamReader(connection.inputStream))
                    val response = StringBuilder()
                    var line: String?
                    
                    while (reader.readLine().also { line = it } != null) {
                        response.append(line)
                    }
                    
                    reader.close()
                    
                    JSONObject(response.toString())
                } else {
                    // Try to read error message from response body
                    try {
                        val errorReader = BufferedReader(InputStreamReader(connection.errorStream))
                        val errorResponse = StringBuilder()
                        var line: String?
                        
                        while (errorReader.readLine().also { line = it } != null) {
                            errorResponse.append(line)
                        }
                        
                        errorReader.close()
                        
                        // Try to parse as JSON
                        val errorJson = JSONObject(errorResponse.toString())
                        throw IOException("HTTP error code: $responseCode, message: ${errorJson.optString("error", "Unknown error")}")
                    } catch (e: Exception) {
                        // If we can't parse the error, just report the status code
                        throw IOException("HTTP error code: $responseCode")
                    }
                }
            } finally {
                connection.disconnect()
            }
        }
    }
    
    // Getters and setters for configuration properties
    
    fun getBackendUrl(): String = backendUrl
    
    fun getApiVersion(): String = apiVersion
    
    fun getNamespace(): String? = namespace
    
    fun getConnectionTimeout(): Int = connectionTimeout
    
    fun setConnectionTimeout(timeout: Int) {
        connectionTimeout = timeout
    }
    
    fun getRetryAttempts(): Int = retryAttempts
    
    fun setRetryAttempts(attempts: Int) {
        retryAttempts = attempts
    }
    
    fun isBluetoothEnabled(): Boolean = bluetoothEnabled
    
    fun setBluetoothEnabled(enabled: Boolean) {
        bluetoothEnabled = enabled
    }
    
    fun getAutoSyncInterval(): Long = autoSyncInterval
    
    fun setAutoSyncInterval(interval: Long) {
        autoSyncInterval = interval
    }
}

/**
 * Data class representing an identity in the DSM system.
 */
data class Identity(
    val id: String,
    val deviceId: String,
    val createdAt: Long
)

/**
 * Data class representing a vault in the DSM system.
 */
data class Vault(
    val id: String,
    val identityId: String,
    val name: String,
    val createdAt: Long,
    val data: JSONObject?
)

/**
 * Data class representing an operation in the DSM system.
 */
data class Operation(
    val type: String,
    val message: String,
    val data: JSONObject?,
    val timestamp: Long,
    val previousState: String,
    val nextState: String
)

/**
 * Data class representing a namespace in the DSM system.
 */
data class Namespace(
    val id: String,
    val name: String,
    val description: String,
    val createdAt: Long
)
