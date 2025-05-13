package dsm.client;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Log;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Client SDK for Android applications to connect to the DSM backend service.
 * This client provides methods for interacting with the DSM backend.
 */
public class DsmClient {
    private static final String TAG = "DsmClient";
    
    // Default configuration
    private static final String DEFAULT_BACKEND_URL = "http://127.0.0.1:7545";
    private static final String DEFAULT_API_VERSION = "v1";
    private static final int DEFAULT_CONNECTION_TIMEOUT = 10000; // 10 seconds
    private static final int DEFAULT_RETRY_ATTEMPTS = 3;
    
    // Client configuration
    private String backendUrl;
    private String apiVersion;
    private String namespace;
    private int connectionTimeout;
    private int retryAttempts;
    private boolean bluetoothEnabled;
    private long autoSyncInterval;
    
    // Android context
    private Context context;
    
    // Executor service for async operations
    private ExecutorService executorService;
    
    /**
     * Creates a client with default settings and no namespace (shared state).
     * 
     * @param context The Android context
     * @return A new DSM client
     */
    public static DsmClient createWithDefaults(Context context) {
        return new DsmClient(context, DEFAULT_BACKEND_URL, DEFAULT_API_VERSION, null);
    }
    
    /**
     * Creates a client with default settings and a specific namespace.
     * 
     * @param context The Android context
     * @param namespace The application namespace for isolated state
     * @return A new DSM client
     */
    public static DsmClient createWithNamespace(Context context, String namespace) {
        return new DsmClient(context, DEFAULT_BACKEND_URL, DEFAULT_API_VERSION, namespace);
    }
    
    /**
     * Constructor with minimal parameters.
     * 
     * @param context The Android context
     * @param backendUrl The URL of the DSM backend
     * @param apiVersion The API version to use
     * @param namespace The application namespace (or null for shared state)
     */
    public DsmClient(Context context, String backendUrl, String apiVersion, String namespace) {
        this.context = context;
        this.backendUrl = backendUrl;
        this.apiVersion = apiVersion;
        this.namespace = namespace;
        this.connectionTimeout = DEFAULT_CONNECTION_TIMEOUT;
        this.retryAttempts = DEFAULT_RETRY_ATTEMPTS;
        this.bluetoothEnabled = true;
        this.autoSyncInterval = 60000; // 1 minute
        
        // Create the executor service
        this.executorService = Executors.newCachedThreadPool();
        
        // Load configuration from shared preferences
        loadConfig();
    }
    
    /**
     * Loads the client configuration from shared preferences.
     */
    private void loadConfig() {
        try {
            SharedPreferences prefs = context.getSharedPreferences("dsm_client_config", Context.MODE_PRIVATE);
            
            if (prefs.contains("backend_url")) {
                backendUrl = prefs.getString("backend_url", DEFAULT_BACKEND_URL);
            }
            
            if (prefs.contains("api_version")) {
                apiVersion = prefs.getString("api_version", DEFAULT_API_VERSION);
            }
            
            if (prefs.contains("connection_timeout_ms")) {
                connectionTimeout = prefs.getInt("connection_timeout_ms", DEFAULT_CONNECTION_TIMEOUT);
            }
            
            if (prefs.contains("retry_attempts")) {
                retryAttempts = prefs.getInt("retry_attempts", DEFAULT_RETRY_ATTEMPTS);
            }
            
            if (prefs.contains("bluetooth_enabled")) {
                bluetoothEnabled = prefs.getBoolean("bluetooth_enabled", true);
            }
            
            if (prefs.contains("auto_sync_interval_ms")) {
                autoSyncInterval = prefs.getLong("auto_sync_interval_ms", 60000);
            }
            
            Log.i(TAG, "Loaded client configuration from shared preferences");
        } catch (Exception e) {
            Log.e(TAG, "Error loading client configuration", e);
        }
    }
    
    /**
     * Saves the client configuration to shared preferences.
     */
    public void saveConfig() {
        try {
            SharedPreferences prefs = context.getSharedPreferences("dsm_client_config", Context.MODE_PRIVATE);
            SharedPreferences.Editor editor = prefs.edit();
            
            editor.putString("backend_url", backendUrl);
            editor.putString("api_version", apiVersion);
            editor.putInt("connection_timeout_ms", connectionTimeout);
            editor.putInt("retry_attempts", retryAttempts);
            editor.putBoolean("bluetooth_enabled", bluetoothEnabled);
            editor.putLong("auto_sync_interval_ms", autoSyncInterval);
            
            if (namespace != null) {
                editor.putString("namespace", namespace);
            }
            
            editor.apply();
            
            Log.i(TAG, "Saved client configuration to shared preferences");
        } catch (Exception e) {
            Log.e(TAG, "Error saving client configuration", e);
        }
    }
    
    /**
     * Checks if the backend service is available.
     * 
     * @return A CompletableFuture that resolves to true if the service is available
     */
    public CompletableFuture<Boolean> checkConnection() {
        CompletableFuture<Boolean> future = new CompletableFuture<>();
        
        executorService.execute(() -> {
            try {
                URL url = new URL(backendUrl + "/health");
                HttpURLConnection connection = (HttpURLConnection) url.openConnection();
                connection.setRequestMethod("GET");
                connection.setConnectTimeout(connectionTimeout);
                connection.setReadTimeout(connectionTimeout);
                
                int responseCode = connection.getResponseCode();
                
                if (responseCode == HttpURLConnection.HTTP_OK) {
                    future.complete(true);
                } else {
                    future.complete(false);
                }
                
                connection.disconnect();
            } catch (Exception e) {
                Log.e(TAG, "Error checking connection to DSM backend", e);
                future.complete(false);
            }
        });
        
        return future;
    }
    
    /**
     * Creates a new identity on the DSM backend.
     * 
     * @param deviceId The device ID
     * @return A CompletableFuture that resolves to the identity ID
     */
    public CompletableFuture<String> createIdentity(String deviceId) {
        CompletableFuture<String> future = new CompletableFuture<>();
        
        executorService.execute(() -> {
            try {
                JSONObject requestBody = new JSONObject();
                requestBody.put("device_id", deviceId);
                
                if (namespace != null) {
                    requestBody.put("namespace", namespace);
                }
                
                JSONObject response = sendPostRequest("/api/v1/identities", requestBody);
                
                if (response.getBoolean("success")) {
                    JSONObject data = response.getJSONObject("data");
                    String identityId = data.getString("identity_id");
                    future.complete(identityId);
                } else {
                    String error = response.getString("error");
                    future.completeExceptionally(new Exception(error));
                }
            } catch (Exception e) {
                Log.e(TAG, "Error creating identity", e);
                future.completeExceptionally(e);
            }
        });
        
        return future;
    }
    
    /**
     * Gets all identities from the DSM backend.
     * 
     * @return A CompletableFuture that resolves to a JSONObject with the identities
     */
    public CompletableFuture<JSONObject> getIdentities() {
        CompletableFuture<JSONObject> future = new CompletableFuture<>();
        
        executorService.execute(() -> {
            try {
                String path = "/api/v1/identities";
                
                if (namespace != null) {
                    path += "?namespace=" + namespace;
                }
                
                JSONObject response = sendGetRequest(path);
                
                if (response.getBoolean("success")) {
                    JSONObject data = response.getJSONObject("data");
                    future.complete(data);
                } else {
                    String error = response.getString("error");
                    future.completeExceptionally(new Exception(error));
                }
            } catch (Exception e) {
                Log.e(TAG, "Error getting identities", e);
                future.completeExceptionally(e);
            }
        });
        
        return future;
    }
    
    /**
     * Gets a specific identity from the DSM backend.
     * 
     * @param identityId The identity ID
     * @return A CompletableFuture that resolves to a JSONObject with the identity
     */
    public CompletableFuture<JSONObject> getIdentity(String identityId) {
        CompletableFuture<JSONObject> future = new CompletableFuture<>();
        
        executorService.execute(() -> {
            try {
                String path = "/api/v1/identities/" + identityId;
                
                if (namespace != null) {
                    path += "?namespace=" + namespace;
                }
                
                JSONObject response = sendGetRequest(path);
                
                if (response.getBoolean("success")) {
                    JSONObject data = response.getJSONObject("data");
                    future.complete(data);
                } else {
                    String error = response.getString("error");
                    future.completeExceptionally(new Exception(error));
                }
            } catch (Exception e) {
                Log.e(TAG, "Error getting identity", e);
                future.completeExceptionally(e);
            }
        });
        
        return future;
    }
    
    /**
     * Creates a new vault on the DSM backend.
     * 
     * @param identityId The identity ID
     * @param name The vault name
     * @return A CompletableFuture that resolves to the vault ID
     */
    public CompletableFuture<String> createVault(String identityId, String name) {
        CompletableFuture<String> future = new CompletableFuture<>();
        
        executorService.execute(() -> {
            try {
                JSONObject requestBody = new JSONObject();
                requestBody.put("identity_id", identityId);
                requestBody.put("name", name);
                
                if (namespace != null) {
                    requestBody.put("namespace", namespace);
                }
                
                JSONObject response = sendPostRequest("/api/v1/vaults", requestBody);
                
                if (response.getBoolean("success")) {
                    JSONObject data = response.getJSONObject("data");
                    String vaultId = data.getString("id");
                    future.complete(vaultId);
                } else {
                    String error = response.getString("error");
                    future.completeExceptionally(new Exception(error));
                }
            } catch (Exception e) {
                Log.e(TAG, "Error creating vault", e);
                future.completeExceptionally(e);
            }
        });
        
        return future;
    }
    
    /**
     * Gets all vaults from the DSM backend.
     * 
     * @return A CompletableFuture that resolves to a JSONObject with the vaults
     */
    public CompletableFuture<JSONObject> getVaults() {
        CompletableFuture<JSONObject> future = new CompletableFuture<>();
        
        executorService.execute(() -> {
            try {
                String path = "/api/v1/vaults";
                
                if (namespace != null) {
                    path += "?namespace=" + namespace;
                }
                
                JSONObject response = sendGetRequest(path);
                
                if (response.getBoolean("success")) {
                    JSONObject data = response.getJSONObject("data");
                    future.complete(data);
                } else {
                    String error = response.getString("error");
                    future.completeExceptionally(new Exception(error));
                }
            } catch (Exception e) {
                Log.e(TAG, "Error getting vaults", e);
                future.completeExceptionally(e);
            }
        });
        
        return future;
    }
    
    /**
     * Gets a specific vault from the DSM backend.
     * 
     * @param vaultId The vault ID
     * @return A CompletableFuture that resolves to a JSONObject with the vault
     */
    public CompletableFuture<JSONObject> getVault(String vaultId) {
        CompletableFuture<JSONObject> future = new CompletableFuture<>();
        
        executorService.execute(() -> {
            try {
                String path = "/api/v1/vaults/" + vaultId;
                
                if (namespace != null) {
                    path += "?namespace=" + namespace;
                }
                
                JSONObject response = sendGetRequest(path);
                
                if (response.getBoolean("success")) {
                    JSONObject data = response.getJSONObject("data");
                    future.complete(data);
                } else {
                    String error = response.getString("error");
                    future.completeExceptionally(new Exception(error));
                }
            } catch (Exception e) {
                Log.e(TAG, "Error getting vault", e);
                future.completeExceptionally(e);
            }
        });
        
        return future;
    }
    
    /**
     * Applies an operation to the state machine.
     * 
     * @param operationType The operation type
     * @param message The operation message
     * @param data The operation data as a JSONObject
     * @return A CompletableFuture that resolves to a JSONObject with the operation result
     */
    public CompletableFuture<JSONObject> applyOperation(String operationType, String message, JSONObject data) {
        CompletableFuture<JSONObject> future = new CompletableFuture<>();
        
        executorService.execute(() -> {
            try {
                JSONObject requestBody = new JSONObject();
                requestBody.put("operation_type", operationType);
                requestBody.put("message", message);
                requestBody.put("data", data);
                
                if (namespace != null) {
                    requestBody.put("namespace", namespace);
                }
                
                JSONObject response = sendPostRequest("/api/v1/operations", requestBody);
                
                if (response.getBoolean("success")) {
                    JSONObject responseData = response.getJSONObject("data");
                    future.complete(responseData);
                } else {
                    String error = response.getString("error");
                    future.completeExceptionally(new Exception(error));
                }
            } catch (Exception e) {
                Log.e(TAG, "Error applying operation", e);
                future.completeExceptionally(e);
            }
        });
        
        return future;
    }
    
    /**
     * Gets all operations from the DSM backend.
     * 
     * @return A CompletableFuture that resolves to a JSONObject with the operations
     */
    public CompletableFuture<JSONObject> getOperations() {
        CompletableFuture<JSONObject> future = new CompletableFuture<>();
        
        executorService.execute(() -> {
            try {
                String path = "/api/v1/operations";
                
                if (namespace != null) {
                    path += "?namespace=" + namespace;
                }
                
                JSONObject response = sendGetRequest(path);
                
                if (response.getBoolean("success")) {
                    JSONObject data = response.getJSONObject("data");
                    future.complete(data);
                } else {
                    String error = response.getString("error");
                    future.completeExceptionally(new Exception(error));
                }
            } catch (Exception e) {
                Log.e(TAG, "Error getting operations", e);
                future.completeExceptionally(e);
            }
        });
        
        return future;
    }
    
    /**
     * Creates a new namespace on the DSM backend.
     * 
     * @param name The namespace name
     * @param description The namespace description
     * @return A CompletableFuture that resolves to the namespace ID
     */
    public CompletableFuture<String> createNamespace(String name, String description) {
        CompletableFuture<String> future = new CompletableFuture<>();
        
        executorService.execute(() -> {
            try {
                JSONObject requestBody = new JSONObject();
                requestBody.put("name", name);
                requestBody.put("description", description);
                
                JSONObject response = sendPostRequest("/api/v1/namespaces", requestBody);
                
                if (response.getBoolean("success")) {
                    JSONObject data = response.getJSONObject("data");
                    String namespaceId = data.getString("id");
                    
                    // Update the client's namespace
                    this.namespace = name;
                    saveConfig();
                    
                    future.complete(namespaceId);
                } else {
                    String error = response.getString("error");
                    future.completeExceptionally(new Exception(error));
                }
            } catch (Exception e) {
                Log.e(TAG, "Error creating namespace", e);
                future.completeExceptionally(e);
            }
        });
        
        return future;
    }
    
    /**
     * Gets all namespaces from the DSM backend.
     * 
     * @return A CompletableFuture that resolves to a JSONObject with the namespaces
     */
    public CompletableFuture<JSONObject> getNamespaces() {
        CompletableFuture<JSONObject> future = new CompletableFuture<>();
        
        executorService.execute(() -> {
            try {
                JSONObject response = sendGetRequest("/api/v1/namespaces");
                
                if (response.getBoolean("success")) {
                    JSONObject data = response.getJSONObject("data");
                    future.complete(data);
                } else {
                    String error = response.getString("error");
                    future.completeExceptionally(new Exception(error));
                }
            } catch (Exception e) {
                Log.e(TAG, "Error getting namespaces", e);
                future.completeExceptionally(e);
            }
        });
        
        return future;
    }
    
    /**
     * Sends a GET request to the DSM backend.
     * 
     * @param path The API path
     * @return The response as a JSONObject
     * @throws IOException If there is an error sending the request
     * @throws JSONException If there is an error parsing the response
     */
    private JSONObject sendGetRequest(String path) throws IOException, JSONException {
        URL url = new URL(backendUrl + path);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        connection.setConnectTimeout(connectionTimeout);
        connection.setReadTimeout(connectionTimeout);
        
        int responseCode = connection.getResponseCode();
        
        if (responseCode == HttpURLConnection.HTTP_OK) {
            BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            StringBuilder response = new StringBuilder();
            String line;
            
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            
            reader.close();
            
            return new JSONObject(response.toString());
        } else {
            throw new IOException("HTTP error code: " + responseCode);
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
    private JSONObject sendPostRequest(String path, JSONObject requestBody) throws IOException, JSONException {
        URL url = new URL(backendUrl + path);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("POST");
        connection.setRequestProperty("Content-Type", "application/json");
        connection.setConnectTimeout(connectionTimeout);
        connection.setReadTimeout(connectionTimeout);
        connection.setDoOutput(true);
        
        // Write the request body
        try (OutputStream os = connection.getOutputStream()) {
            byte[] input = requestBody.toString().getBytes(StandardCharsets.UTF_8);
            os.write(input, 0, input.length);
        }
        
        int responseCode = connection.getResponseCode();
        
        if (responseCode == HttpURLConnection.HTTP_OK || responseCode == HttpURLConnection.HTTP_CREATED) {
            BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            StringBuilder response = new StringBuilder();
            String line;
            
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            
            reader.close();
            
            return new JSONObject(response.toString());
        } else {
            throw new IOException("HTTP error code: " + responseCode);
        }
    }
    
    /**
     * Gets the backend URL.
     * 
     * @return The backend URL
     */
    public String getBackendUrl() {
        return backendUrl;
    }
    
    /**
     * Sets the backend URL.
     * 
     * @param backendUrl The new backend URL
     */
    public void setBackendUrl(String backendUrl) {
        this.backendUrl = backendUrl;
    }
    
    /**
     * Gets the API version.
     * 
     * @return The API version
     */
    public String getApiVersion() {
        return apiVersion;
    }
    
    /**
     * Sets the API version.
     * 
     * @param apiVersion The new API version
     */
    public void setApiVersion(String apiVersion) {
        this.apiVersion = apiVersion;
    }
    
    /**
     * Gets the namespace.
     * 
     * @return The namespace or null if using shared state
     */
    public String getNamespace() {
        return namespace;
    }
    
    /**
     * Sets the namespace.
     * 
     * @param namespace The new namespace or null for shared state
     */
    public void setNamespace(String namespace) {
        this.namespace = namespace;
    }
    
    /**
     * Gets the connection timeout in milliseconds.
     * 
     * @return The connection timeout
     */
    public int getConnectionTimeout() {
        return connectionTimeout;
    }
    
    /**
     * Sets the connection timeout in milliseconds.
     * 
     * @param connectionTimeout The new connection timeout
     */
    public void setConnectionTimeout(int connectionTimeout) {
        this.connectionTimeout = connectionTimeout;
    }
    
    /**
     * Gets the retry attempts.
     * 
     * @return The retry attempts
     */
    public int getRetryAttempts() {
        return retryAttempts;
    }
    
    /**
     * Sets the retry attempts.
     * 
     * @param retryAttempts The new retry attempts
     */
    public void setRetryAttempts(int retryAttempts) {
        this.retryAttempts = retryAttempts;
    }
    
    /**
     * Checks if Bluetooth is enabled.
     * 
     * @return true if Bluetooth is enabled
     */
    public boolean isBluetoothEnabled() {
        return bluetoothEnabled;
    }
    
    /**
     * Sets whether Bluetooth is enabled.
     * 
     * @param bluetoothEnabled true to enable Bluetooth
     */
    public void setBluetoothEnabled(boolean bluetoothEnabled) {
        this.bluetoothEnabled = bluetoothEnabled;
    }
    
    /**
     * Gets the auto sync interval in milliseconds.
     * 
     * @return The auto sync interval
     */
    public long getAutoSyncInterval() {
        return autoSyncInterval;
    }
    
    /**
     * Sets the auto sync interval in milliseconds.
     * 
     * @param autoSyncInterval The new auto sync interval
     */
    public void setAutoSyncInterval(long autoSyncInterval) {
        this.autoSyncInterval = autoSyncInterval;
    }
}
