package dsm.service;

import android.content.Context;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * The core DSM functionality implemented in Java.
 * This class provides the core Decentralized State Machine functionality
 * including identity management, state transitions, and persistent storage.
 */
public class DsmCore {
    private static final String TAG = "DsmCore";
    
    // The Android context
    private final Context context;
    
    // The data directory
    private final File dataDir;
    
    // The secure random number generator
    private final SecureRandom secureRandom = new SecureRandom();
    
    // Storage for identities
    private final Map<String, JSONObject> identities = new ConcurrentHashMap<>();
    
    // Storage for vaults
    private final Map<String, JSONObject> vaults = new ConcurrentHashMap<>();
    
    // Storage for namespaces
    private final Map<String, JSONObject> namespaces = new ConcurrentHashMap<>();
    
    // Storage for operations
    private final List<JSONObject> operations = new ArrayList<>();
    
    // Current state hash
    private String currentStateHash;
    
    // Locks for thread safety
    private final ReadWriteLock identitiesLock = new ReentrantReadWriteLock();
    private final ReadWriteLock vaultsLock = new ReentrantReadWriteLock();
    private final ReadWriteLock namespacesLock = new ReentrantReadWriteLock();
    private final ReadWriteLock operationsLock = new ReentrantReadWriteLock();
    private final ReadWriteLock stateLock = new ReentrantReadWriteLock();
    
    /**
     * Constructor
     * 
     * @param context The Android context
     */
    public DsmCore(Context context) {
        this.context = context;
        this.dataDir = new File(context.getFilesDir(), "dsm_service");
    }
    
    /**
     * Starts the DSM core
     * 
     * @throws Exception If there is an error starting the DSM core
     */
    public void start() throws Exception {
        Log.i(TAG, "Starting DSM Core");
        
        // Initialize crypto
        initCrypto();
        
        // Load identities
        loadIdentities();
        
        // Load vaults
        loadVaults();
        
        // Load namespaces
        loadNamespaces();
        
        // Initialize state
        initializeState();
    }
    
    /**
     * Stops the DSM core
     * 
     * @throws Exception If there is an error stopping the DSM core
     */
    public void stop() throws Exception {
        Log.i(TAG, "Stopping DSM Core");
        
        // Save identities
        saveIdentities();
        
        // Save vaults
        saveVaults();
        
        // Save namespaces
        saveNamespaces();
        
        // Save operations
        saveOperations();
    }
    
    /**
     * Initializes the cryptographic subsystem
     */
    private void initCrypto() {
        // In a real implementation, this would initialize any crypto libraries
        // For now, we're just ensuring SecureRandom is seeded
        byte[] seed = new byte[32];
        secureRandom.nextBytes(seed);
        secureRandom.setSeed(seed);
        
        Log.i(TAG, "Cryptographic subsystem initialized");
    }
    
    /**
     * Initializes the state machine
     */
    private void initializeState() {
        stateLock.writeLock().lock();
        try {
            // Check if state exists
            File stateFile = new File(dataDir, "state.json");
            if (stateFile.exists()) {
                try {
                    // Load the state
                    FileReader reader = new FileReader(stateFile);
                    StringBuilder content = new StringBuilder();
                    char[] buffer = new char[1024];
                    int length;
                    
                    while ((length = reader.read(buffer)) > 0) {
                        content.append(buffer, 0, length);
                    }
                    
                    reader.close();
                    
                    // Parse the state
                    JSONObject state = new JSONObject(content.toString());
                    currentStateHash = state.getString("hash");
                    
                    Log.i(TAG, "Loaded existing state with hash: " + currentStateHash);
                    
                    // Load operations
                    if (state.has("operations")) {
                        JSONArray opsArray = state.getJSONArray("operations");
                        
                        operationsLock.writeLock().lock();
                        try {
                            operations.clear();
                            
                            for (int i = 0; i < opsArray.length(); i++) {
                                JSONObject op = opsArray.getJSONObject(i);
                                operations.add(op);
                            }
                            
                            Log.i(TAG, "Loaded " + operations.size() + " operations from state");
                        } finally {
                            operationsLock.writeLock().unlock();
                        }
                    }
                } catch (Exception e) {
                    Log.e(TAG, "Error loading state", e);
                    // Create a genesis state
                    createGenesisState();
                }
            } else {
                // Create a genesis state
                createGenesisState();
            }
        } finally {
            stateLock.writeLock().unlock();
        }
    }
    
    /**
     * Creates the genesis state (first state in the chain)
     */
    private void createGenesisState() {
        try {
            // Generate a random hash for the genesis state
            byte[] randomBytes = new byte[32];
            secureRandom.nextBytes(randomBytes);
            
            // SHA-256 the random bytes to get a hash
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(randomBytes);
            
            // Convert to hex string
            StringBuilder hexString = new StringBuilder();
            for (byte b : hashBytes) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            
            currentStateHash = hexString.toString();
            
            // Create the state object
            JSONObject state = new JSONObject();
            state.put("hash", currentStateHash);
            state.put("timestamp", System.currentTimeMillis());
            state.put("operations", new JSONArray());
            
            // Save the state
            File stateFile = new File(dataDir, "state.json");
            FileWriter writer = new FileWriter(stateFile);
            writer.write(state.toString(2));
            writer.close();
            
            Log.i(TAG, "Created genesis state with hash: " + currentStateHash);
        } catch (Exception e) {
            Log.e(TAG, "Error creating genesis state", e);
        }
    }
    
    /**
     * Loads identities from storage
     */
    private void loadIdentities() {
        File identitiesDir = new File(dataDir, "identities");
        if (!identitiesDir.exists()) {
            Log.i(TAG, "Identities directory does not exist, creating");
            if (!identitiesDir.mkdirs()) {
                Log.e(TAG, "Failed to create identities directory");
            }
            return;
        }
        
        File[] files = identitiesDir.listFiles((dir, name) -> name.endsWith(".json"));
        if (files == null) {
            Log.w(TAG, "No identity files found or error listing files");
            return;
        }
        
        identitiesLock.writeLock().lock();
        try {
            identities.clear();
            
            for (File file : files) {
                try {
                    // Load the identity
                    FileReader reader = new FileReader(file);
                    StringBuilder content = new StringBuilder();
                    char[] buffer = new char[1024];
                    int length;
                    
                    while ((length = reader.read(buffer)) > 0) {
                        content.append(buffer, 0, length);
                    }
                    
                    reader.close();
                    
                    // Parse the identity
                    JSONObject identity = new JSONObject(content.toString());
                    String id = identity.getString("id");
                    
                    // Store the identity
                    identities.put(id, identity);
                } catch (Exception e) {
                    Log.e(TAG, "Error loading identity from " + file.getName(), e);
                }
            }
            
            Log.i(TAG, "Loaded " + identities.size() + " identities");
        } finally {
            identitiesLock.writeLock().unlock();
        }
    }
    
    /**
     * Saves identities to storage
     */
    private void saveIdentities() {
        File identitiesDir = new File(dataDir, "identities");
        if (!identitiesDir.exists() && !identitiesDir.mkdirs()) {
            Log.e(TAG, "Failed to create identities directory");
            return;
        }
        
        identitiesLock.readLock().lock();
        try {
            for (Map.Entry<String, JSONObject> entry : identities.entrySet()) {
                try {
                    String id = entry.getKey();
                    JSONObject identity = entry.getValue();
                    
                    // Save the identity
                    File file = new File(identitiesDir, id + ".json");
                    FileWriter writer = new FileWriter(file);
                    writer.write(identity.toString(2));
                    writer.close();
                } catch (Exception e) {
                    Log.e(TAG, "Error saving identity", e);
                }
            }
            
            Log.i(TAG, "Saved " + identities.size() + " identities");
        } finally {
            identitiesLock.readLock().unlock();
        }
    }
    
    /**
     * Loads vaults from storage
     */
    private void loadVaults() {
        File vaultsDir = new File(dataDir, "vaults");
        if (!vaultsDir.exists()) {
            Log.i(TAG, "Vaults directory does not exist, creating");
            if (!vaultsDir.mkdirs()) {
                Log.e(TAG, "Failed to create vaults directory");
            }
            return;
        }
        
        File[] files = vaultsDir.listFiles((dir, name) -> name.endsWith(".json"));
        if (files == null) {
            Log.w(TAG, "No vault files found or error listing files");
            return;
        }
        
        vaultsLock.writeLock().lock();
        try {
            vaults.clear();
            
            for (File file : files) {
                try {
                    // Load the vault
                    FileReader reader = new FileReader(file);
                    StringBuilder content = new StringBuilder();
                    char[] buffer = new char[1024];
                    int length;
                    
                    while ((length = reader.read(buffer)) > 0) {
                        content.append(buffer, 0, length);
                    }
                    
                    reader.close();
                    
                    // Parse the vault
                    JSONObject vault = new JSONObject(content.toString());
                    String id = vault.getString("id");
                    
                    // Store the vault
                    vaults.put(id, vault);
                } catch (Exception e) {
                    Log.e(TAG, "Error loading vault from " + file.getName(), e);
                }
            }
            
            Log.i(TAG, "Loaded " + vaults.size() + " vaults");
        } finally {
            vaultsLock.writeLock().unlock();
        }
    }
    
    /**
     * Saves vaults to storage
     */
    private void saveVaults() {
        File vaultsDir = new File(dataDir, "vaults");
        if (!vaultsDir.exists() && !vaultsDir.mkdirs()) {
            Log.e(TAG, "Failed to create vaults directory");
            return;
        }
        
        vaultsLock.readLock().lock();
        try {
            for (Map.Entry<String, JSONObject> entry : vaults.entrySet()) {
                try {
                    String id = entry.getKey();
                    JSONObject vault = entry.getValue();
                    
                    // Save the vault
                    File file = new File(vaultsDir, id + ".json");
                    FileWriter writer = new FileWriter(file);
                    writer.write(vault.toString(2));
                    writer.close();
                } catch (Exception e) {
                    Log.e(TAG, "Error saving vault", e);
                }
            }
            
            Log.i(TAG, "Saved " + vaults.size() + " vaults");
        } finally {
            vaultsLock.readLock().unlock();
        }
    }
    
    /**
     * Loads namespaces from storage
     */
    private void loadNamespaces() {
        File namespacesDir = new File(dataDir, "namespaces");
        if (!namespacesDir.exists()) {
            Log.i(TAG, "Namespaces directory does not exist, creating");
            if (!namespacesDir.mkdirs()) {
                Log.e(TAG, "Failed to create namespaces directory");
            }
            return;
        }
        
        File[] files = namespacesDir.listFiles((dir, name) -> name.endsWith(".json"));
        if (files == null) {
            Log.w(TAG, "No namespace files found or error listing files");
            return;
        }
        
        namespacesLock.writeLock().lock();
        try {
            namespaces.clear();
            
            for (File file : files) {
                try {
                    // Load the namespace
                    FileReader reader = new FileReader(file);
                    StringBuilder content = new StringBuilder();
                    char[] buffer = new char[1024];
                    int length;
                    
                    while ((length = reader.read(buffer)) > 0) {
                        content.append(buffer, 0, length);
                    }
                    
                    reader.close();
                    
                    // Parse the namespace
                    JSONObject namespace = new JSONObject(content.toString());
                    String id = namespace.getString("id");
                    
                    // Store the namespace
                    namespaces.put(id, namespace);
                } catch (Exception e) {
                    Log.e(TAG, "Error loading namespace from " + file.getName(), e);
                }
            }
            
            Log.i(TAG, "Loaded " + namespaces.size() + " namespaces");
        } finally {
            namespacesLock.writeLock().unlock();
        }
    }
    
    /**
     * Saves namespaces to storage
     */
    private void saveNamespaces() {
        File namespacesDir = new File(dataDir, "namespaces");
        if (!namespacesDir.exists() && !namespacesDir.mkdirs()) {
            Log.e(TAG, "Failed to create namespaces directory");
            return;
        }
        
        namespacesLock.readLock().lock();
        try {
            for (Map.Entry<String, JSONObject> entry : namespaces.entrySet()) {
                try {
                    String id = entry.getKey();
                    JSONObject namespace = entry.getValue();
                    
                    // Save the namespace
                    File file = new File(namespacesDir, id + ".json");
                    FileWriter writer = new FileWriter(file);
                    writer.write(namespace.toString(2));
                    writer.close();
                } catch (Exception e) {
                    Log.e(TAG, "Error saving namespace", e);
                }
            }
            
            Log.i(TAG, "Saved " + namespaces.size() + " namespaces");
        } finally {
            namespacesLock.readLock().unlock();
        }
    }
    
    /**
     * Saves operations to storage
     */
    private void saveOperations() {
        operationsLock.readLock().lock();
        try {
            // Save the current state with operations
            JSONObject state = new JSONObject();
            state.put("hash", currentStateHash);
            state.put("timestamp", System.currentTimeMillis());
            
            JSONArray opsArray = new JSONArray();
            for (JSONObject op : operations) {
                opsArray.put(op);
            }
            
            state.put("operations", opsArray);
            
            // Save the state
            File stateFile = new File(dataDir, "state.json");
            FileWriter writer = new FileWriter(stateFile);
            writer.write(state.toString(2));
            writer.close();
            
            Log.i(TAG, "Saved state with " + operations.size() + " operations");
        } catch (Exception e) {
            Log.e(TAG, "Error saving operations", e);
        } finally {
            operationsLock.readLock().unlock();
        }
    }
    
    /**
     * Creates a new identity
     * 
     * @param deviceId The device ID
     * @return The created identity as a JSONObject
     * @throws Exception If there is an error creating the identity
     */
    public JSONObject createIdentity(String deviceId) throws Exception {
        // Generate a unique ID for the identity
        String id = UUID.randomUUID().toString();
        
        // Create the identity
        JSONObject identity = new JSONObject();
        identity.put("id", id);
        identity.put("device_id", deviceId);
        identity.put("created_at", System.currentTimeMillis());
        
        // Store the identity
        identitiesLock.writeLock().lock();
        try {
            identities.put(id, identity);
        } finally {
            identitiesLock.writeLock().unlock();
        }
        
        // Save to file
        File identitiesDir = new File(dataDir, "identities");
        if (!identitiesDir.exists() && !identitiesDir.mkdirs()) {
            throw new IOException("Failed to create identities directory");
        }
        
        File file = new File(identitiesDir, id + ".json");
        FileWriter writer = new FileWriter(file);
        writer.write(identity.toString(2));
        writer.close();
        
        Log.i(TAG, "Created identity with ID: " + id);
        
        // Return the identity
        return identity;
    }
    
    /**
     * Gets all identities
     * 
     * @return A JSONObject with all identities
     */
    public JSONObject getIdentities() {
        JSONObject result = new JSONObject();
        JSONArray identitiesArray = new JSONArray();
        
        identitiesLock.readLock().lock();
        try {
            for (JSONObject identity : identities.values()) {
                identitiesArray.put(identity);
            }
        } finally {
            identitiesLock.readLock().unlock();
        }
        
        try {
            result.put("identities", identitiesArray);
        } catch (JSONException e) {
            Log.e(TAG, "Error creating identities JSON", e);
        }
        
        return result;
    }
    
    /**
     * Gets a specific identity
     * 
     * @param identityId The identity ID
     * @return The identity as a JSONObject
     * @throws Exception If the identity is not found
     */
    public JSONObject getIdentity(String identityId) throws Exception {
        identitiesLock.readLock().lock();
        try {
            JSONObject identity = identities.get(identityId);
            if (identity == null) {
                throw new Exception("Identity not found: " + identityId);
            }
            return new JSONObject(identity.toString());
        } finally {
            identitiesLock.readLock().unlock();
        }
    }
    
    /**
     * Creates a new vault
     * 
     * @param requestBody The request body with vault details
     * @return The created vault as a JSONObject
     * @throws Exception If there is an error creating the vault
     */
    public JSONObject createVault(JSONObject requestBody) throws Exception {
        // Extract parameters
        String identityId = requestBody.getString("identity_id");
        String name = requestBody.optString("name", "Vault-" + UUID.randomUUID().toString().substring(0, 8));
        
        // Verify the identity exists
        identitiesLock.readLock().lock();
        try {
            if (!identities.containsKey(identityId)) {
                throw new Exception("Identity not found: " + identityId);
            }
        } finally {
            identitiesLock.readLock().unlock();
        }
        
        // Generate a unique ID for the vault
        String id = UUID.randomUUID().toString();
        
        // Create the vault
        JSONObject vault = new JSONObject();
        vault.put("id", id);
        vault.put("identity_id", identityId);
        vault.put("name", name);
        vault.put("created_at", System.currentTimeMillis());
        vault.put("data", new JSONObject());
        
        // Store the vault
        vaultsLock.writeLock().lock();
        try {
            vaults.put(id, vault);
        } finally {
            vaultsLock.writeLock().unlock();
        }
        
        // Save to file
        File vaultsDir = new File(dataDir, "vaults");
        if (!vaultsDir.exists() && !vaultsDir.mkdirs()) {
            throw new IOException("Failed to create vaults directory");
        }
        
        File file = new File(vaultsDir, id + ".json");
        FileWriter writer = new FileWriter(file);
        writer.write(vault.toString(2));
        writer.close();
        
        Log.i(TAG, "Created vault with ID: " + id);
        
        // Return the vault
        return vault;
    }
    
    /**
     * Gets all vaults
     * 
     * @return A JSONObject with all vaults
     */
    public JSONObject getVaults() {
        JSONObject result = new JSONObject();
        JSONArray vaultsArray = new JSONArray();
        
        vaultsLock.readLock().lock();
        try {
            for (JSONObject vault : vaults.values()) {
                vaultsArray.put(vault);
            }
        } finally {
            vaultsLock.readLock().unlock();
        }
        
        try {
            result.put("vaults", vaultsArray);
        } catch (JSONException e) {
            Log.e(TAG, "Error creating vaults JSON", e);
        }
        
        return result;
    }
    
    /**
     * Gets a specific vault
     * 
     * @param vaultId The vault ID
     * @return The vault as a JSONObject
     * @throws Exception If the vault is not found
     */
    public JSONObject getVault(String vaultId) throws Exception {
        vaultsLock.readLock().lock();
        try {
            JSONObject vault = vaults.get(vaultId);
            if (vault == null) {
                throw new Exception("Vault not found: " + vaultId);
            }
            return new JSONObject(vault.toString());
        } finally {
            vaultsLock.readLock().unlock();
        }
    }
    
    /**
     * Creates a new namespace
     * 
     * @param requestBody The request body with namespace details
     * @return The created namespace as a JSONObject
     * @throws Exception If there is an error creating the namespace
     */
    public JSONObject createNamespace(JSONObject requestBody) throws Exception {
        // Extract parameters
        String name = requestBody.getString("name");
        String description = requestBody.optString("description", "");
        
        // Generate a unique ID for the namespace
        String id = UUID.randomUUID().toString();
        
        // Create the namespace
        JSONObject namespace = new JSONObject();
        namespace.put("id", id);
        namespace.put("name", name);
        namespace.put("description", description);
        namespace.put("created_at", System.currentTimeMillis());
        
        // Store the namespace
        namespacesLock.writeLock().lock();
        try {
            namespaces.put(id, namespace);
        } finally {
            namespacesLock.writeLock().unlock();
        }
        
        // Save to file
        File namespacesDir = new File(dataDir, "namespaces");
        if (!namespacesDir.exists() && !namespacesDir.mkdirs()) {
            throw new IOException("Failed to create namespaces directory");
        }
        
        File file = new File(namespacesDir, id + ".json");
        FileWriter writer = new FileWriter(file);
        writer.write(namespace.toString(2));
        writer.close();
        
        Log.i(TAG, "Created namespace with ID: " + id);
        
        // Return the namespace
        return namespace;
    }
    
    /**
     * Gets all namespaces
     * 
     * @return A JSONObject with all namespaces
     */
    public JSONObject getNamespaces() {
        JSONObject result = new JSONObject();
        JSONArray namespacesArray = new JSONArray();
        
        namespacesLock.readLock().lock();
        try {
            for (JSONObject namespace : namespaces.values()) {
                namespacesArray.put(namespace);
            }
        } finally {
            namespacesLock.readLock().unlock();
        }
        
        try {
            result.put("namespaces", namespacesArray);
        } catch (JSONException e) {
            Log.e(TAG, "Error creating namespaces JSON", e);
        }
        
        return result;
    }
    
    /**
     * Applies an operation to the state machine
     * 
     * @param requestBody The request body with operation details
     * @return The result of the operation
     * @throws Exception If there is an error applying the operation
     */
    public JSONObject applyOperation(JSONObject requestBody) throws Exception {
        // Extract parameters
        String operationType = requestBody.getString("operation_type");
        String message = requestBody.optString("message", "");
        JSONObject data = requestBody.optJSONObject("data");
        
        // Create the operation object
        JSONObject operation = new JSONObject();
        operation.put("operation_type", operationType);
        operation.put("message", message);
        operation.put("data", data != null ? data : new JSONObject());
        operation.put("timestamp", System.currentTimeMillis());
        
        // Generate entropy for the state transition
        byte[] entropy = new byte[32];
        secureRandom.nextBytes(entropy);
        
        // Apply the operation to the state machine
        stateLock.writeLock().lock();
        try {
            // Hash the current state and the operation to get the next state
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(currentStateHash.getBytes());
            digest.update(operation.toString().getBytes());
            digest.update(entropy);
            
            byte[] hashBytes = digest.digest();
            
            // Convert to hex string
            StringBuilder hexString = new StringBuilder();
            for (byte b : hashBytes) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            
            String newStateHash = hexString.toString();
            
            // Store the operation with its result
            operation.put("previous_state", currentStateHash);
            operation.put("next_state", newStateHash);
            
            operationsLock.writeLock().lock();
            try {
                operations.add(operation);
                
                // Keep only the last 100 operations
                while (operations.size() > 100) {
                    operations.remove(0);
                }
            } finally {
                operationsLock.writeLock().unlock();
            }
            
            // Update the current state
            currentStateHash = newStateHash;
            
            // Save the state
            saveOperations();
        } finally {
            stateLock.writeLock().unlock();
        }
        
        // Return the operation result
        JSONObject result = new JSONObject();
        result.put("operation", operation);
        result.put("state_hash", currentStateHash);
        
        return result;
    }
    
    /**
     * Gets all operations
     * 
     * @return A JSONObject with all operations
     */
    public JSONObject getOperations() {
        JSONObject result = new JSONObject();
        JSONArray operationsArray = new JSONArray();
        
        operationsLock.readLock().lock();
        try {
            for (JSONObject op : operations) {
                operationsArray.put(op);
            }
        } finally {
            operationsLock.readLock().unlock();
        }
        
        try {
            result.put("operations", operationsArray);
            result.put("current_state", currentStateHash);
        } catch (JSONException e) {
            Log.e(TAG, "Error creating operations JSON", e);
        }
        
        return result;
    }
}
