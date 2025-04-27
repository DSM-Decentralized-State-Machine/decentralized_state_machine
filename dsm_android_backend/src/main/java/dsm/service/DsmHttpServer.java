package dsm.service;

import android.content.Context;
import android.util.Log;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * A simple HTTP server for the DSM backend service.
 * This server exposes the DSM API to client applications.
 */
public class DsmHttpServer {
    private static final String TAG = "DsmHttpServer";
    
    // Default server port
    private static final int DEFAULT_PORT = 7545;
    
    // The server socket
    private ServerSocket serverSocket;
    
    // Flag to indicate if the server is running
    private boolean isRunning = false;
    
    // Executor service for handling client connections
    private ExecutorService executorService;
    
    // The Android context
    private Context context;
    
    // The DSM core
    private DsmCore dsmCore;
    
    // API handlers
    private Map<String, ApiHandler> apiHandlers = new HashMap<>();
    
    /**
     * Interface for API handlers
     */
    public interface ApiHandler {
        JSONObject handle(String method, String path, JSONObject requestBody) throws Exception;
    }
    
    /**
     * Constructor
     * 
     * @param context The Android context
     * @param dsmCore The DSM core
     */
    public DsmHttpServer(Context context, DsmCore dsmCore) {
        this.context = context;
        this.dsmCore = dsmCore;
        this.executorService = Executors.newCachedThreadPool();
        
        // Register API handlers
        registerApiHandlers();
    }
    
    /**
     * Registers the API handlers for different endpoints
     */
    private void registerApiHandlers() {
        // Health check endpoint
        apiHandlers.put("/health", (method, path, requestBody) -> {
            JSONObject response = new JSONObject();
            response.put("status", "running");
            response.put("version", "1.0.0");
            response.put("timestamp", System.currentTimeMillis() / 1000);
            return response;
        });
        
        // Identities endpoint
        apiHandlers.put("/api/v1/identities", (method, path, requestBody) -> {
            if (method.equals("POST")) {
                // Create a new identity
                String deviceId = (requestBody != null && requestBody.has("device_id")) ? 
                        requestBody.getString("device_id") : 
                        java.util.UUID.randomUUID().toString();
                
                return dsmCore.createIdentity(deviceId);
            } else if (method.equals("GET")) {
                // List all identities
                return dsmCore.getIdentities();
            }
            
            throw new Exception("Method not supported: " + method);
        });
        
        // Specific identity endpoint
        apiHandlers.put("/api/v1/identities/", (method, path, requestBody) -> {
            if (!method.equals("GET")) {
                throw new Exception("Method not supported: " + method);
            }
            
            // Extract the identity ID from the path
            String identityId = path.substring("/api/v1/identities/".length());
            return dsmCore.getIdentity(identityId);
        });
        
        // State machine operations endpoint
        apiHandlers.put("/api/v1/operations", (method, path, requestBody) -> {
            if (method.equals("POST")) {
                // Apply an operation to the state machine
                return dsmCore.applyOperation(requestBody);
            } else if (method.equals("GET")) {
                // List recent operations
                return dsmCore.getOperations();
            }
            
            throw new Exception("Method not supported: " + method);
        });
        
        // Vaults endpoint
        apiHandlers.put("/api/v1/vaults", (method, path, requestBody) -> {
            if (method.equals("POST")) {
                // Create a new vault
                return dsmCore.createVault(requestBody);
            } else if (method.equals("GET")) {
                // List all vaults
                return dsmCore.getVaults();
            }
            
            throw new Exception("Method not supported: " + method);
        });
        
        // Specific vault endpoint
        apiHandlers.put("/api/v1/vaults/", (method, path, requestBody) -> {
            if (!method.equals("GET")) {
                throw new Exception("Method not supported: " + method);
            }
            
            // Extract the vault ID from the path
            String vaultId = path.substring("/api/v1/vaults/".length());
            return dsmCore.getVault(vaultId);
        });

        // Application namespaces endpoint
        apiHandlers.put("/api/v1/namespaces", (method, path, requestBody) -> {
            if (method.equals("POST")) {
                // Create a new namespace
                return dsmCore.createNamespace(requestBody);
            } else if (method.equals("GET")) {
                // List all namespaces
                return dsmCore.getNamespaces();
            }
            
            throw new Exception("Method not supported: " + method);
        });
    }
    
    /**
     * Starts the HTTP server
     * 
     * @throws IOException If the server socket cannot be opened
     */
    public synchronized void start() throws IOException {
        if (isRunning) {
            Log.w(TAG, "HTTP server is already running");
            return;
        }
        
        // Get the configured port
        int port = getServerPort();
        
        // Create the server socket
        serverSocket = new ServerSocket();
        serverSocket.setReuseAddress(true);
        serverSocket.bind(new InetSocketAddress("127.0.0.1", port));
        
        Log.i(TAG, "HTTP server started on port " + port);
        
        // Flag the server as running
        isRunning = true;
        
        // Start accepting client connections
        executorService.execute(this::acceptConnections);
    }
    
    /**
     * Stops the HTTP server
     * 
     * @throws IOException If the server socket cannot be closed
     */
    public synchronized void stop() throws IOException {
        if (!isRunning) {
            Log.w(TAG, "HTTP server is not running");
            return;
        }
        
        // Flag the server as not running
        isRunning = false;
        
        // Close the server socket
        if (serverSocket != null && !serverSocket.isClosed()) {
            serverSocket.close();
            serverSocket = null;
        }
        
        Log.i(TAG, "HTTP server stopped");
    }
    
    /**
     * Accepts client connections
     */
    private void acceptConnections() {
        try {
            while (isRunning && serverSocket != null && !serverSocket.isClosed()) {
                Socket clientSocket = serverSocket.accept();
                executorService.execute(() -> handleClientConnection(clientSocket));
            }
        } catch (IOException e) {
            if (isRunning) {
                Log.e(TAG, "Error accepting client connection", e);
            }
        }
    }
    
    /**
     * Handles a client connection
     * 
     * @param clientSocket The client socket
     */
    private void handleClientConnection(Socket clientSocket) {
        try {
            // Read the request
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(clientSocket.getInputStream(), StandardCharsets.UTF_8));
            
            // Read the first line (the request line)
            String requestLine = reader.readLine();
            if (requestLine == null) {
                return;
            }
            
            // Parse the request line
            String[] requestParts = requestLine.split(" ");
            if (requestParts.length != 3) {
                sendErrorResponse(clientSocket, 400, "Bad Request");
                return;
            }
            
            String method = requestParts[0];
            String path = requestParts[1];
            
            // Read headers
            Map<String, String> headers = new HashMap<>();
            String line;
            while ((line = reader.readLine()) != null && !line.isEmpty()) {
                int colonPos = line.indexOf(':');
                if (colonPos > 0) {
                    String headerName = line.substring(0, colonPos).trim();
                    String headerValue = line.substring(colonPos + 1).trim();
                    headers.put(headerName.toLowerCase(), headerValue);
                }
            }
            
            // Read the request body if present
            JSONObject requestBody = null;
            if (headers.containsKey("content-length")) {
                int contentLength = Integer.parseInt(headers.get("content-length"));
                if (contentLength > 0) {
                    char[] buffer = new char[contentLength];
                    int bytesRead = reader.read(buffer, 0, contentLength);
                    if (bytesRead > 0) {
                        String bodyStr = new String(buffer, 0, bytesRead);
                        try {
                            requestBody = new JSONObject(bodyStr);
                        } catch (JSONException e) {
                            Log.w(TAG, "Invalid JSON request body", e);
                        }
                    }
                }
            }
            
            // Handle the request
            handleRequest(clientSocket, method, path, requestBody);
            
        } catch (IOException e) {
            Log.e(TAG, "Error handling client connection", e);
            try {
                sendErrorResponse(clientSocket, 500, "Internal Server Error");
            } catch (IOException ex) {
                Log.e(TAG, "Error sending error response", ex);
            }
        } finally {
            try {
                clientSocket.close();
            } catch (IOException e) {
                Log.e(TAG, "Error closing client socket", e);
            }
        }
    }
    
    /**
     * Handles an HTTP request
     * 
     * @param clientSocket The client socket
     * @param method The HTTP method
     * @param path The request path
     * @param requestBody The request body as a JSONObject
     * @throws IOException If there is an error sending the response
     */
    private void handleRequest(Socket clientSocket, String method, String path, JSONObject requestBody) throws IOException {
        try {
            // Find an exact match first
            ApiHandler handler = apiHandlers.get(path);
            
            // If no exact match, try prefix matches
            if (handler == null) {
                for (Map.Entry<String, ApiHandler> entry : apiHandlers.entrySet()) {
                    if (entry.getKey().endsWith("/") && path.startsWith(entry.getKey())) {
                        handler = entry.getValue();
                        break;
                    }
                }
            }
            
            if (handler != null) {
                JSONObject responseBody = handler.handle(method, path, requestBody);
                
                // Wrap the response
                JSONObject wrappedResponse = new JSONObject();
                wrappedResponse.put("success", true);
                wrappedResponse.put("data", responseBody);
                wrappedResponse.put("error", JSONObject.NULL);
                
                sendSuccessResponse(clientSocket, wrappedResponse);
            } else {
                // Not found
                JSONObject errorResponse = new JSONObject();
                errorResponse.put("success", false);
                errorResponse.put("data", JSONObject.NULL);
                errorResponse.put("error", "Unknown endpoint: " + method + " " + path);
                
                sendResponse(clientSocket, 404, errorResponse);
            }
        } catch (Exception e) {
            Log.e(TAG, "Error handling request: " + path, e);
            
            // Create an error response
            try {
                JSONObject errorResponse = new JSONObject();
                errorResponse.put("success", false);
                errorResponse.put("data", JSONObject.NULL);
                errorResponse.put("error", e.getMessage());
                
                sendResponse(clientSocket, 500, errorResponse);
            } catch (JSONException ex) {
                Log.e(TAG, "Error creating JSON error response", ex);
                sendErrorResponse(clientSocket, 500, "Internal Server Error");
            }
        }
    }
    
    /**
     * Sends a success response (HTTP 200 OK)
     * 
     * @param clientSocket The client socket
     * @param responseBody The response body as a JSONObject
     * @throws IOException If there is an error sending the response
     */
    private void sendSuccessResponse(Socket clientSocket, JSONObject responseBody) throws IOException {
        sendResponse(clientSocket, 200, responseBody);
    }
    
    /**
     * Sends an error response
     * 
     * @param clientSocket The client socket
     * @param statusCode The HTTP status code
     * @param message The error message
     * @throws IOException If there is an error sending the response
     */
    private void sendErrorResponse(Socket clientSocket, int statusCode, String message) throws IOException {
        try {
            JSONObject errorResponse = new JSONObject();
            errorResponse.put("success", false);
            errorResponse.put("data", JSONObject.NULL);
            errorResponse.put("error", message);
            
            sendResponse(clientSocket, statusCode, errorResponse);
        } catch (JSONException e) {
            Log.e(TAG, "Error creating JSON error response", e);
            
            // Fallback to a simple error response
            String statusText = getStatusText(statusCode);
            String response = "HTTP/1.1 " + statusCode + " " + statusText + "\r\n" +
                    "Content-Type: text/plain\r\n" +
                    "Connection: close\r\n" +
                    "\r\n" +
                    message;
            
            OutputStream outputStream = clientSocket.getOutputStream();
            outputStream.write(response.getBytes(StandardCharsets.UTF_8));
            outputStream.flush();
        }
    }
    
    /**
     * Sends an HTTP response
     * 
     * @param clientSocket The client socket
     * @param statusCode The HTTP status code
     * @param responseBody The response body as a JSONObject
     * @throws IOException If there is an error sending the response
     */
    private void sendResponse(Socket clientSocket, int statusCode, JSONObject responseBody) throws IOException {
        String statusText = getStatusText(statusCode);
        String jsonResponse = responseBody.toString();
        
        StringBuilder responseBuilder = new StringBuilder();
        responseBuilder.append("HTTP/1.1 ").append(statusCode).append(" ").append(statusText).append("\r\n");
        responseBuilder.append("Content-Type: application/json\r\n");
        responseBuilder.append("Content-Length: ").append(jsonResponse.getBytes(StandardCharsets.UTF_8).length).append("\r\n");
        responseBuilder.append("Connection: close\r\n");
        responseBuilder.append("\r\n");
        responseBuilder.append(jsonResponse);
        
        OutputStream outputStream = clientSocket.getOutputStream();
        outputStream.write(responseBuilder.toString().getBytes(StandardCharsets.UTF_8));
        outputStream.flush();
    }
    
    /**
     * Gets the text representation of an HTTP status code
     * 
     * @param statusCode The HTTP status code
     * @return The text representation
     */
    private String getStatusText(int statusCode) {
        switch (statusCode) {
            case 200:
                return "OK";
            case 201:
                return "Created";
            case 400:
                return "Bad Request";
            case 404:
                return "Not Found";
            case 500:
                return "Internal Server Error";
            default:
                return "Unknown Status";
        }
    }
    
    /**
     * Gets the server port from the configuration
     * 
     * @return The server port
     */
    private int getServerPort() {
        try {
            return Integer.parseInt(context.getSharedPreferences("dsm_service_config", Context.MODE_PRIVATE)
                    .getString("server_port", String.valueOf(DEFAULT_PORT)));
        } catch (NumberFormatException e) {
            Log.w(TAG, "Invalid server port in configuration, using default", e);
            return DEFAULT_PORT;
        }
    }
}
