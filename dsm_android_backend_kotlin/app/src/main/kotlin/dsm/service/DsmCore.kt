package dsm.service

import android.content.Context
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject
import java.io.File
import java.io.IOException
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.*
import java.util.concurrent.ConcurrentHashMap

/**
 * The core DSM functionality implemented in Kotlin.
 * This class provides the core Decentralized State Machine functionality
 * including identity management, state transitions, and persistent storage.
 */
class DsmCore(private val context: Context) {
    companion object {
        private const val TAG = "DsmCore"
    }

    // The data directory
    private val dataDir: File by lazy { File(context.filesDir, "dsm_service") }

    // The secure random number generator
    private val secureRandom = SecureRandom()

    // Storage for identities, vaults and namespaces
    private val identities = ConcurrentHashMap<String, JSONObject>()
    private val vaults = ConcurrentHashMap<String, JSONObject>()
    private val namespaces = ConcurrentHashMap<String, JSONObject>()
    private val pushTokens = ConcurrentHashMap<String, JSONObject>()
    
    // Storage for operations (guarded by mutex)
    private val operations = mutableListOf<JSONObject>()
    
    // Current state hash (guarded by mutex)
    private var currentStateHash: String = ""
    
    // Mutexes for thread safety
    private val identitiesMutex = Mutex()
    private val vaultsMutex = Mutex()
    private val namespacesMutex = Mutex()
    private val operationsMutex = Mutex()
    private val stateMutex = Mutex()
    private val pushTokensMutex = Mutex()

    /**
     * Starts the DSM core
     *
     * @throws Exception If there is an error starting the DSM core
     */
    suspend fun start() {
        Log.i(TAG, "Starting DSM Core")

        // Initialize crypto
        initCrypto()

        // Load identities
        loadIdentities()

        // Load vaults
        loadVaults()

        // Load namespaces
        loadNamespaces()

        // Initialize state
        initializeState()
        
        // Load push notification tokens
        loadPushTokens()
    }

    /**
     * Stops the DSM core
     *
     * @throws Exception If there is an error stopping the DSM core
     */
    suspend fun stop() {
        Log.i(TAG, "Stopping DSM Core")

        // Save identities
        saveIdentities()

        // Save vaults
        saveVaults()

        // Save namespaces
        saveNamespaces()

        // Save operations
        saveOperations()
        
        // Save push tokens
        savePushTokens()
    }

    /**
     * Initializes the cryptographic subsystem
     */
    private fun initCrypto() {
        // In a real implementation, this would initialize any crypto libraries
        // For now, we're just ensuring SecureRandom is seeded
        val seed = ByteArray(32)
        secureRandom.nextBytes(seed)
        secureRandom.setSeed(seed)

        Log.i(TAG, "Cryptographic subsystem initialized")
    }

    /**
     * Initializes the state machine
     */
    private suspend fun initializeState() {
        stateMutex.withLock {
            // Check if state exists
            val stateFile = File(dataDir, "state.json")
            if (stateFile.exists()) {
                try {
                    // Load the state
                    val stateJson = withContext(Dispatchers.IO) {
                        stateFile.readText()
                    }

                    // Parse the state
                    val state = JSONObject(stateJson)
                    currentStateHash = state.getString("hash")

                    Log.i(TAG, "Loaded existing state with hash: $currentStateHash")

                    // Load operations
                    if (state.has("operations")) {
                        val opsArray = state.getJSONArray("operations")

                        operationsMutex.withLock {
                            operations.clear()

                            for (i in 0 until opsArray.length()) {
                                val op = opsArray.getJSONObject(i)
                                operations.add(op)
                            }

                            Log.i(TAG, "Loaded ${operations.size} operations from state")
                        }
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "Error loading state", e)
                    // Create a genesis state
                    createGenesisState()
                }
            } else {
                // Create a genesis state
                createGenesisState()
            }
        }
    }

    /**
     * Creates the genesis state (first state in the chain)
     */
    private suspend fun createGenesisState() {
        withContext(Dispatchers.IO) {
            try {
                // Generate a random hash for the genesis state
                val randomBytes = ByteArray(32)
                secureRandom.nextBytes(randomBytes)

                // SHA-256 the random bytes to get a hash
                val digest = MessageDigest.getInstance("SHA-256")
                val hashBytes = digest.digest(randomBytes)

                // Convert to hex string
                val hexString = StringBuilder()
                for (b in hashBytes) {
                    val hex = Integer.toHexString(0xff and b.toInt())
                    if (hex.length == 1) {
                        hexString.append('0')
                    }
                    hexString.append(hex)
                }

                currentStateHash = hexString.toString()

                // Create the state object
                val state = JSONObject().apply {
                    put("hash", currentStateHash)
                    put("timestamp", System.currentTimeMillis())
                    put("operations", JSONArray())
                }

                // Save the state
                val stateFile = File(dataDir, "state.json")
                stateFile.writeText(state.toString(2))

                Log.i(TAG, "Created genesis state with hash: $currentStateHash")
            } catch (e: Exception) {
                Log.e(TAG, "Error creating genesis state", e)
            }
        }
    }

    /**
     * Loads identities from storage
     */
    private suspend fun loadIdentities() {
        val identitiesDir = File(dataDir, "identities")
        if (!identitiesDir.exists()) {
            Log.i(TAG, "Identities directory does not exist, creating")
            if (!identitiesDir.mkdirs()) {
                Log.e(TAG, "Failed to create identities directory")
            }
            return
        }

        identitiesMutex.withLock {
            withContext(Dispatchers.IO) {
                identities.clear()

                identitiesDir.listFiles { _, name -> name.endsWith(".json") }?.forEach { file ->
                    try {
                        // Load the identity
                        val identityJson = file.readText()

                        // Parse the identity
                        val identity = JSONObject(identityJson)
                        val id = identity.getString("id")

                        // Store the identity
                        identities[id] = identity
                    } catch (e: Exception) {
                        Log.e(TAG, "Error loading identity from ${file.name}", e)
                    }
                }

                Log.i(TAG, "Loaded ${identities.size} identities")
            }
        }
    }

    /**
     * Saves identities to storage
     */
    private suspend fun saveIdentities() {
        val identitiesDir = File(dataDir, "identities")
        if (!identitiesDir.exists() && !identitiesDir.mkdirs()) {
            Log.e(TAG, "Failed to create identities directory")
            return
        }

        identitiesMutex.withLock {
            withContext(Dispatchers.IO) {
                identities.forEach { (id, identity) ->
                    try {
                        // Save the identity
                        val file = File(identitiesDir, "$id.json")
                        file.writeText(identity.toString(2))
                    } catch (e: Exception) {
                        Log.e(TAG, "Error saving identity", e)
                    }
                }

                Log.i(TAG, "Saved ${identities.size} identities")
            }
        }
    }

    /**
     * Loads vaults from storage
     */
    private suspend fun loadVaults() {
        val vaultsDir = File(dataDir, "vaults")
        if (!vaultsDir.exists()) {
            Log.i(TAG, "Vaults directory does not exist, creating")
            if (!vaultsDir.mkdirs()) {
                Log.e(TAG, "Failed to create vaults directory")
            }
            return
        }

        vaultsMutex.withLock {
            withContext(Dispatchers.IO) {
                vaults.clear()

                vaultsDir.listFiles { _, name -> name.endsWith(".json") }?.forEach { file ->
                    try {
                        // Load the vault
                        val vaultJson = file.readText()

                        // Parse the vault
                        val vault = JSONObject(vaultJson)
                        val id = vault.getString("id")

                        // Store the vault
                        vaults[id] = vault
                    } catch (e: Exception) {
                        Log.e(TAG, "Error loading vault from ${file.name}", e)
                    }
                }

                Log.i(TAG, "Loaded ${vaults.size} vaults")
            }
        }
    }

    /**
     * Saves vaults to storage
     */
    private suspend fun saveVaults() {
        val vaultsDir = File(dataDir, "vaults")
        if (!vaultsDir.exists() && !vaultsDir.mkdirs()) {
            Log.e(TAG, "Failed to create vaults directory")
            return
        }

        vaultsMutex.withLock {
            withContext(Dispatchers.IO) {
                vaults.forEach { (id, vault) ->
                    try {
                        // Save the vault
                        val file = File(vaultsDir, "$id.json")
                        file.writeText(vault.toString(2))
                    } catch (e: Exception) {
                        Log.e(TAG, "Error saving vault", e)
                    }
                }

                Log.i(TAG, "Saved ${vaults.size} vaults")
            }
        }
    }

    /**
     * Loads namespaces from storage
     */
    private suspend fun loadNamespaces() {
        val namespacesDir = File(dataDir, "namespaces")
        if (!namespacesDir.exists()) {
            Log.i(TAG, "Namespaces directory does not exist, creating")
            if (!namespacesDir.mkdirs()) {
                Log.e(TAG, "Failed to create namespaces directory")
            }
            return
        }

        namespacesMutex.withLock {
            withContext(Dispatchers.IO) {
                namespaces.clear()

                namespacesDir.listFiles { _, name -> name.endsWith(".json") }?.forEach { file ->
                    try {
                        // Load the namespace
                        val namespaceJson = file.readText()

                        // Parse the namespace
                        val namespace = JSONObject(namespaceJson)
                        val id = namespace.getString("id")

                        // Store the namespace
                        namespaces[id] = namespace
                    } catch (e: Exception) {
                        Log.e(TAG, "Error loading namespace from ${file.name}", e)
                    }
                }

                Log.i(TAG, "Loaded ${namespaces.size} namespaces")
            }
        }
    }

    /**
     * Saves namespaces to storage
     */
    private suspend fun saveNamespaces() {
        val namespacesDir = File(dataDir, "namespaces")
        if (!namespacesDir.exists() && !namespacesDir.mkdirs()) {
            Log.e(TAG, "Failed to create namespaces directory")
            return
        }

        namespacesMutex.withLock {
            withContext(Dispatchers.IO) {
                namespaces.forEach { (id, namespace) ->
                    try {
                        // Save the namespace
                        val file = File(namespacesDir, "$id.json")
                        file.writeText(namespace.toString(2))
                    } catch (e: Exception) {
                        Log.e(TAG, "Error saving namespace", e)
                    }
                }

                Log.i(TAG, "Saved ${namespaces.size} namespaces")
            }
        }
    }
    
    /**
     * Loads push notification tokens from storage
     */
    private suspend fun loadPushTokens() {
        val tokensDir = File(dataDir, "push_tokens")
        if (!tokensDir.exists()) {
            Log.i(TAG, "Push tokens directory does not exist, creating")
            if (!tokensDir.mkdirs()) {
                Log.e(TAG, "Failed to create push tokens directory")
            }
            return
        }

        pushTokensMutex.withLock {
            withContext(Dispatchers.IO) {
                pushTokens.clear()

                tokensDir.listFiles { _, name -> name.endsWith(".json") }?.forEach { file ->
                    try {
                        // Load the token
                        val tokenJson = file.readText()

                        // Parse the token
                        val token = JSONObject(tokenJson)
                        val id = token.getString("id")

                        // Store the token
                        pushTokens[id] = token
                    } catch (e: Exception) {
                        Log.e(TAG, "Error loading push token from ${file.name}", e)
                    }
                }

                Log.i(TAG, "Loaded ${pushTokens.size} push tokens")
            }
        }
    }

    /**
     * Saves push notification tokens to storage
     */
    private suspend fun savePushTokens() {
        val tokensDir = File(dataDir, "push_tokens")
        if (!tokensDir.exists() && !tokensDir.mkdirs()) {
            Log.e(TAG, "Failed to create push tokens directory")
            return
        }

        pushTokensMutex.withLock {
            withContext(Dispatchers.IO) {
                pushTokens.forEach { (id, token) ->
                    try {
                        // Save the token
                        val file = File(tokensDir, "$id.json")
                        file.writeText(token.toString(2))
                    } catch (e: Exception) {
                        Log.e(TAG, "Error saving push token", e)
                    }
                }

                Log.i(TAG, "Saved ${pushTokens.size} push tokens")
            }
        }
    }

    /**
     * Saves operations to storage
     */
    private suspend fun saveOperations() {
        stateMutex.withLock {
            operationsMutex.withLock {
                try {
                    // Save the current state with operations
                    val state = JSONObject().apply {
                        put("hash", currentStateHash)
                        put("timestamp", System.currentTimeMillis())

                        val opsArray = JSONArray()
                        operations.forEach { op ->
                            opsArray.put(op)
                        }

                        put("operations", opsArray)
                    }

                    // Save the state
                    withContext(Dispatchers.IO) {
                        val stateFile = File(dataDir, "state.json")
                        stateFile.writeText(state.toString(2))
                    }

                    Log.i(TAG, "Saved state with ${operations.size} operations")
                } catch (e: Exception) {
                    Log.e(TAG, "Error saving operations", e)
                }
            }
        }
    }

    /**
     * Creates a new identity
     *
     * @param deviceId The device ID
     * @return The created identity as a JSONObject
     * @throws Exception If there is an error creating the identity
     */
    suspend fun createIdentity(deviceId: String): JSONObject {
        // Generate a unique ID for the identity
        val id = UUID.randomUUID().toString()

        // Create the identity
        val identity = JSONObject().apply {
            put("id", id)
            put("device_id", deviceId)
            put("created_at", System.currentTimeMillis())
        }

        // Store the identity
        identitiesMutex.withLock {
            identities[id] = identity
        }

        // Save to file
        withContext(Dispatchers.IO) {
            val identitiesDir = File(dataDir, "identities")
            if (!identitiesDir.exists() && !identitiesDir.mkdirs()) {
                throw IOException("Failed to create identities directory")
            }

            val file = File(identitiesDir, "$id.json")
            file.writeText(identity.toString(2))
        }

        Log.i(TAG, "Created identity with ID: $id")

        // Return the identity
        return identity
    }

    /**
     * Gets all identities
     *
     * @return A JSONObject with all identities
     */
    suspend fun getIdentities(): JSONObject {
        val result = JSONObject()
        val identitiesArray = JSONArray()

        identitiesMutex.withLock {
            identities.values.forEach { identity ->
                identitiesArray.put(identity)
            }
        }

        try {
            result.put("identities", identitiesArray)
        } catch (e: JSONException) {
            Log.e(TAG, "Error creating identities JSON", e)
        }

        return result
    }

    /**
     * Gets a specific identity
     *
     * @param identityId The identity ID
     * @return The identity as a JSONObject
     * @throws Exception If the identity is not found
     */
    suspend fun getIdentity(identityId: String): JSONObject {
        identitiesMutex.withLock {
            val identity = identities[identityId]
                ?: throw IllegalArgumentException("Identity not found: $identityId")
            return JSONObject(identity.toString())
        }
    }

    /**
     * Creates a new vault
     *
     * @param requestBody The request body with vault details
     * @return The created vault as a JSONObject
     * @throws Exception If there is an error creating the vault
     */
    suspend fun createVault(requestBody: JSONObject): JSONObject {
        // Extract parameters
        val identityId = requestBody.getString("identity_id")
        val name = requestBody.optString("name", "Vault-${UUID.randomUUID().toString().substring(0, 8)}")

        // Verify the identity exists
        identitiesMutex.withLock {
            if (!identities.containsKey(identityId)) {
                throw IllegalArgumentException("Identity not found: $identityId")
            }
        }

        // Generate a unique ID for the vault
        val id = UUID.randomUUID().toString()

        // Create the vault
        val vault = JSONObject().apply {
            put("id", id)
            put("identity_id", identityId)
            put("name", name)
            put("created_at", System.currentTimeMillis())
            put("data", JSONObject())
        }

        // Store the vault
        vaultsMutex.withLock {
            vaults[id] = vault
        }

        // Save to file
        withContext(Dispatchers.IO) {
            val vaultsDir = File(dataDir, "vaults")
            if (!vaultsDir.exists() && !vaultsDir.mkdirs()) {
                throw IOException("Failed to create vaults directory")
            }

            val file = File(vaultsDir, "$id.json")
            file.writeText(vault.toString(2))
        }

        Log.i(TAG, "Created vault with ID: $id")

        // Return the vault
        return vault
    }

    /**
     * Gets all vaults
     *
     * @return A JSONObject with all vaults
     */
    suspend fun getVaults(): JSONObject {
        val result = JSONObject()
        val vaultsArray = JSONArray()

        vaultsMutex.withLock {
            vaults.values.forEach { vault ->
                vaultsArray.put(vault)
            }
        }

        try {
            result.put("vaults", vaultsArray)
        } catch (e: JSONException) {
            Log.e(TAG, "Error creating vaults JSON", e)
        }

        return result
    }

    /**
     * Gets a specific vault
     *
     * @param vaultId The vault ID
     * @return The vault as a JSONObject
     * @throws Exception If the vault is not found
     */
    suspend fun getVault(vaultId: String): JSONObject {
        vaultsMutex.withLock {
            val vault = vaults[vaultId] ?: throw IllegalArgumentException("Vault not found: $vaultId")
            return JSONObject(vault.toString())
        }
    }

    /**
     * Creates a new namespace
     *
     * @param requestBody The request body with namespace details
     * @return The created namespace as a JSONObject
     * @throws Exception If there is an error creating the namespace
     */
    suspend fun createNamespace(requestBody: JSONObject): JSONObject {
        // Extract parameters
        val name = requestBody.getString("name")
        val description = requestBody.optString("description", "")

        // Generate a unique ID for the namespace
        val id = UUID.randomUUID().toString()

        // Create the namespace
        val namespace = JSONObject().apply {
            put("id", id)
            put("name", name)
            put("description", description)
            put("created_at", System.currentTimeMillis())
        }

        // Store the namespace
        namespacesMutex.withLock {
            namespaces[id] = namespace
        }

        // Save to file
        withContext(Dispatchers.IO) {
            val namespacesDir = File(dataDir, "namespaces")
            if (!namespacesDir.exists() && !namespacesDir.mkdirs()) {
                throw IOException("Failed to create namespaces directory")
            }

            val file = File(namespacesDir, "$id.json")
            file.writeText(namespace.toString(2))
        }

        Log.i(TAG, "Created namespace with ID: $id")

        // Return the namespace
        return namespace
    }

    /**
     * Gets all namespaces
     *
     * @return A JSONObject with all namespaces
     */
    suspend fun getNamespaces(): JSONObject {
        val result = JSONObject()
        val namespacesArray = JSONArray()

        namespacesMutex.withLock {
            namespaces.values.forEach { namespace ->
                namespacesArray.put(namespace)
            }
        }

        try {
            result.put("namespaces", namespacesArray)
        } catch (e: JSONException) {
            Log.e(TAG, "Error creating namespaces JSON", e)
        }

        return result
    }

    /**
     * Applies an operation to the state machine
     *
     * @param requestBody The request body with operation details
     * @return The result of the operation
     * @throws Exception If there is an error applying the operation
     */
    suspend fun applyOperation(requestBody: JSONObject): JSONObject {
        // Extract parameters
        val operationType = requestBody.getString("operation_type")
        val message = requestBody.optString("message", "")
        val data = requestBody.optJSONObject("data") ?: JSONObject()

        // Create the operation object
        val operation = JSONObject().apply {
            put("operation_type", operationType)
            put("message", message)
            put("data", data)
            put("timestamp", System.currentTimeMillis())
        }

        // Generate entropy for the state transition
        val entropy = ByteArray(32)
        secureRandom.nextBytes(entropy)

        // Apply the operation to the state machine
        stateMutex.withLock {
            // Hash the current state and the operation to get the next state
            val digest = MessageDigest.getInstance("SHA-256")
            digest.update(currentStateHash.toByteArray())
            digest.update(operation.toString().toByteArray())
            digest.update(entropy)

            val hashBytes = digest.digest()

            // Convert to hex string
            val hexString = StringBuilder()
            for (b in hashBytes) {
                val hex = Integer.toHexString(0xff and b.toInt())
                if (hex.length == 1) {
                    hexString.append('0')
                }
                hexString.append(hex)
            }

            val newStateHash = hexString.toString()

            // Store the operation with its result
            operation.put("previous_state", currentStateHash)
            operation.put("next_state", newStateHash)

            operationsMutex.withLock {
                operations.add(operation)

                // Keep only the last 100 operations
                while (operations.size > 100) {
                    operations.removeAt(0)
                }
            }

            // Update the current state
            currentStateHash = newStateHash

            // Save the state
            saveOperations()
        }

        // Send notifications to registered apps if applicable
        if (shouldSendNotification(operationType)) {
            sendNotification(operation)
        }

        // Return the operation result
        return JSONObject().apply {
            put("operation", operation)
            put("state_hash", currentStateHash)
        }
    }

    /**
     * Gets all operations
     *
     * @return A JSONObject with all operations
     */
    suspend fun getOperations(): JSONObject {
        val result = JSONObject()
        val operationsArray = JSONArray()

        operationsMutex.withLock {
            operations.forEach { op ->
                operationsArray.put(op)
            }
        }

        stateMutex.withLock {
            try {
                result.put("operations", operationsArray)
                result.put("current_state", currentStateHash)
            } catch (e: JSONException) {
                Log.e(TAG, "Error creating operations JSON", e)
            }
        }

        return result
    }
    
    /**
     * Registers a device for push notifications
     * 
     * @param requestBody The registration details
     * @return Registration confirmation
     */
    suspend fun registerForNotifications(requestBody: JSONObject): JSONObject {
        // Extract the required parameters
        val appId = requestBody.getString("app_id")
        val deviceToken = requestBody.getString("device_token")
        val platform = requestBody.optString("platform", "android")
        
        // Optional parameters
        val namespace = requestBody.optString("namespace", null)
        val topics = requestBody.optJSONArray("topics")
        
        // Create a unique ID for this registration
        val id = UUID.randomUUID().toString()
        
        // Create the registration object
        val registration = JSONObject().apply {
            put("id", id)
            put("app_id", appId)
            put("device_token", deviceToken)
            put("platform", platform)
            put("created_at", System.currentTimeMillis())
            
            if (namespace != null) {
                put("namespace", namespace)
            }
            
            if (topics != null) {
                put("topics", topics)
            }
        }
        
        // Store the registration
        pushTokensMutex.withLock {
            pushTokens[id] = registration
        }
        
        // Save to file
        withContext(Dispatchers.IO) {
            val tokenDir = File(dataDir, "push_tokens")
            if (!tokenDir.exists() && !tokenDir.mkdirs()) {
                throw IOException("Failed to create push tokens directory")
            }
            
            val file = File(tokenDir, "$id.json")
            file.writeText(registration.toString(2))
        }
        
        Log.i(TAG, "Registered device for push notifications: $id")
        
        // Return confirmation
        return JSONObject().apply {
            put("registration_id", id)
            put("status", "registered")
        }
    }
    
    /**
     * Determines if a notification should be sent for an operation type
     */
    private fun shouldSendNotification(operationType: String): Boolean {
        // Define operation types that should trigger notifications
        return when (operationType) {
            "create_vault", "update_vault", "delete_vault",
            "create_identity", "update_identity", "delete_identity",
            "token_transfer", "message" -> true
            else -> false
        }
    }
    
    /**
     * Sends a notification to all registered devices
     */
    private suspend fun sendNotification(operation: JSONObject) {
        pushTokensMutex.withLock {
            // This is where you would implement actual push notification sending
            // For now, we just log it
            Log.i(TAG, "Would send notification for operation: ${operation.getString("operation_type")}")
            Log.i(TAG, "Notification would go to ${pushTokens.size} registered devices")
            
            // In a real implementation, you would:
            // 1. Create a notification payload
            // 2. Filter tokens by namespace/topics if needed
            // 3. Send to FCM, APNS, etc. as appropriate
        }
    }
}
