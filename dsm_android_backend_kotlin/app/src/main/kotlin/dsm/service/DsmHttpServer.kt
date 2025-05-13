package dsm.service

import android.content.Context
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONException
import org.json.JSONObject
import java.io.BufferedReader
import java.io.IOException
import java.io.InputStreamReader
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.util.concurrent.ConcurrentHashMap
import kotlin.coroutines.CoroutineContext

/**
 * A Kotlin implementation of the HTTP server for the DSM backend service.
 * This server exposes the DSM API to client applications.
 */
class DsmHttpServer(
    private val context: Context,
    private val dsmCore: DsmCore
) : CoroutineScope {

    companion object {
        private const val TAG = "DsmHttpServer"
        private const val DEFAULT_PORT = 7545
    }

    // Coroutine context for async operations
    private val job = Job()
    override val coroutineContext: CoroutineContext
        get() = Dispatchers.IO + job

    // The server socket
    private var serverSocket: ServerSocket? = null

    // Flag to indicate if the server is running
    private var isRunning = false

    // API handlers mapped by path
    private val apiHandlers = ConcurrentHashMap<String, ApiHandler>()

    /**
     * Functional interface for API handlers
     */
    fun interface ApiHandler {
        suspend fun handle(method: String, path: String, requestBody: JSONObject?): JSONObject
    }

    init {
        // Register API handlers
        registerApiHandlers()
    }

    /**
     * Registers the API handlers for different endpoints
     */
    private fun registerApiHandlers() {
        // Health check endpoint
        apiHandlers["/health"] = ApiHandler { method, _, _ ->
            JSONObject().apply {
                put("status", "running")
                put("version", "1.0.0")
                put("timestamp", System.currentTimeMillis() / 1000)
            }
        }

        // Identities endpoint
        apiHandlers["/api/v1/identities"] = ApiHandler { method, _, requestBody ->
            when (method) {
                "POST" -> {
                    // Create a new identity
                    val deviceId = requestBody?.optString("device_id") ?: java.util.UUID.randomUUID().toString()
                    dsmCore.createIdentity(deviceId)
                }
                "GET" -> {
                    // List all identities
                    dsmCore.getIdentities()
                }
                else -> throw IllegalArgumentException("Method not supported: $method")
            }
        }

        // Specific identity endpoint (prefix match)
        apiHandlers["/api/v1/identities/"] = ApiHandler { method, path, _ ->
            if (method != "GET") {
                throw IllegalArgumentException("Method not supported: $method")
            }

            // Extract the identity ID from the path
            val identityId = path.substringAfter("/api/v1/identities/")
            dsmCore.getIdentity(identityId)
        }

        // State machine operations endpoint
        apiHandlers["/api/v1/operations"] = ApiHandler { method, _, requestBody ->
            when (method) {
                "POST" -> {
                    // Apply an operation to the state machine
                    if (requestBody == null) {
                        throw IllegalArgumentException("Request body is required")
                    }
                    dsmCore.applyOperation(requestBody)
                }
                "GET" -> {
                    // List recent operations
                    dsmCore.getOperations()
                }
                else -> throw IllegalArgumentException("Method not supported: $method")
            }
        }

        // Vaults endpoint
        apiHandlers["/api/v1/vaults"] = ApiHandler { method, _, requestBody ->
            when (method) {
                "POST" -> {
                    // Create a new vault
                    if (requestBody == null) {
                        throw IllegalArgumentException("Request body is required")
                    }
                    dsmCore.createVault(requestBody)
                }
                "GET" -> {
                    // List all vaults
                    dsmCore.getVaults()
                }
                else -> throw IllegalArgumentException("Method not supported: $method")
            }
        }

        // Specific vault endpoint (prefix match)
        apiHandlers["/api/v1/vaults/"] = ApiHandler { method, path, _ ->
            if (method != "GET") {
                throw IllegalArgumentException("Method not supported: $method")
            }

            // Extract the vault ID from the path
            val vaultId = path.substringAfter("/api/v1/vaults/")
            dsmCore.getVault(vaultId)
        }

        // Application namespaces endpoint
        apiHandlers["/api/v1/namespaces"] = ApiHandler { method, _, requestBody ->
            when (method) {
                "POST" -> {
                    // Create a new namespace
                    if (requestBody == null) {
                        throw IllegalArgumentException("Request body is required")
                    }
                    dsmCore.createNamespace(requestBody)
                }
                "GET" -> {
                    // List all namespaces
                    dsmCore.getNamespaces()
                }
                else -> throw IllegalArgumentException("Method not supported: $method")
            }
        }

        // Push notification endpoint
        apiHandlers["/api/v1/notifications/register"] = ApiHandler { method, _, requestBody ->
            if (method != "POST" || requestBody == null) {
                throw IllegalArgumentException("Invalid request for notification registration")
            }
            
            // Register for push notifications
            dsmCore.registerForNotifications(requestBody)
        }
    }

    /**
     * Starts the HTTP server
     *
     * @throws IOException If the server socket cannot be opened
     */
    @Synchronized
    suspend fun start() {
        if (isRunning) {
            Log.w(TAG, "HTTP server is already running")
            return
        }

        // Get the configured port
        val port = getServerPort()

        withContext(Dispatchers.IO) {
            // Create the server socket
            serverSocket = ServerSocket().apply {
                reuseAddress = true
                bind(InetSocketAddress("127.0.0.1", port))
            }

            Log.i(TAG, "HTTP server started on port $port")

            // Flag the server as running
            isRunning = true

            // Start accepting client connections
            launch { acceptConnections() }
        }
    }

    /**
     * Stops the HTTP server
     *
     * @throws IOException If the server socket cannot be closed
     */
    @Synchronized
    fun stop() {
        if (!isRunning) {
            Log.w(TAG, "HTTP server is not running")
            return
        }

        // Flag the server as not running
        isRunning = false

        // Close the server socket
        serverSocket?.let {
            if (!it.isClosed) {
                try {
                    it.close()
                } catch (e: IOException) {
                    Log.e(TAG, "Error closing server socket", e)
                }
            }
        }
        serverSocket = null

        // Cancel all coroutines
        job.cancel()

        Log.i(TAG, "HTTP server stopped")
    }

    /**
     * Accepts client connections
     */
    private suspend fun acceptConnections() {
        try {
            val socket = serverSocket ?: return
            
            while (isRunning && !socket.isClosed) {
                try {
                    val clientSocket = socket.accept()
                    launch { handleClientConnection(clientSocket) }
                } catch (e: IOException) {
                    if (isRunning) {
                        Log.e(TAG, "Error accepting client connection", e)
                    }
                }
            }
        } catch (e: Exception) {
            if (isRunning) {
                Log.e(TAG, "Error in connection acceptance loop", e)
            }
        }
    }

    /**
     * Handles a client connection
     *
     * @param clientSocket The client socket
     */
    private suspend fun handleClientConnection(clientSocket: Socket) {
        try {
            // Read the request
            val reader = BufferedReader(
                InputStreamReader(clientSocket.getInputStream(), StandardCharsets.UTF_8)
            )

            // Read the first line (the request line)
            val requestLine = reader.readLine() ?: return

            // Parse the request line
            val requestParts = requestLine.split(" ")
            if (requestParts.size != 3) {
                sendErrorResponse(clientSocket, 400, "Bad Request")
                return
            }

            val method = requestParts[0]
            val path = requestParts[1]

            // Read headers
            val headers = mutableMapOf<String, String>()
            var line: String?
            while (reader.readLine().also { line = it } != null && line!!.isNotEmpty()) {
                val colonPos = line!!.indexOf(':')
                if (colonPos > 0) {
                    val headerName = line!!.substring(0, colonPos).trim()
                    val headerValue = line!!.substring(colonPos + 1).trim()
                    headers[headerName.lowercase()] = headerValue
                }
            }

            // Read the request body if present
            var requestBody: JSONObject? = null
            headers["content-length"]?.toIntOrNull()?.let { contentLength ->
                if (contentLength > 0) {
                    val buffer = CharArray(contentLength)
                    val bytesRead = reader.read(buffer, 0, contentLength)
                    if (bytesRead > 0) {
                        val bodyStr = String(buffer, 0, bytesRead)
                        try {
                            requestBody = JSONObject(bodyStr)
                        } catch (e: JSONException) {
                            Log.w(TAG, "Invalid JSON request body", e)
                        }
                    }
                }
            }

            // Handle the request
            handleRequest(clientSocket, method, path, requestBody)

        } catch (e: IOException) {
            Log.e(TAG, "Error handling client connection", e)
            try {
                sendErrorResponse(clientSocket, 500, "Internal Server Error")
            } catch (ex: IOException) {
                Log.e(TAG, "Error sending error response", ex)
            }
        } finally {
            try {
                clientSocket.close()
            } catch (e: IOException) {
                Log.e(TAG, "Error closing client socket", e)
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
    private suspend fun handleRequest(
        clientSocket: Socket,
        method: String,
        path: String,
        requestBody: JSONObject?
    ) {
        try {
            // Find an exact match first
            var handler = apiHandlers[path]

            // If no exact match, try prefix matches
            if (handler == null) {
                for ((key, value) in apiHandlers) {
                    if (key.endsWith("/") && path.startsWith(key)) {
                        handler = value
                        break
                    }
                }
            }

            if (handler != null) {
                val responseBody = handler.handle(method, path, requestBody)

                // Wrap the response
                val wrappedResponse = JSONObject().apply {
                    put("success", true)
                    put("data", responseBody)
                    put("error", JSONObject.NULL)
                }

                sendSuccessResponse(clientSocket, wrappedResponse)
            } else {
                // Not found
                val errorResponse = JSONObject().apply {
                    put("success", false)
                    put("data", JSONObject.NULL)
                    put("error", "Unknown endpoint: $method $path")
                }

                sendResponse(clientSocket, 404, errorResponse)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error handling request: $path", e)

            // Create an error response
            try {
                val errorResponse = JSONObject().apply {
                    put("success", false)
                    put("data", JSONObject.NULL)
                    put("error", e.message ?: "Unknown error")
                }

                sendResponse(clientSocket, 500, errorResponse)
            } catch (ex: JSONException) {
                Log.e(TAG, "Error creating JSON error response", ex)
                sendErrorResponse(clientSocket, 500, "Internal Server Error")
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
    private fun sendSuccessResponse(clientSocket: Socket, responseBody: JSONObject) {
        sendResponse(clientSocket, 200, responseBody)
    }

    /**
     * Sends an error response
     *
     * @param clientSocket The client socket
     * @param statusCode The HTTP status code
     * @param message The error message
     * @throws IOException If there is an error sending the response
     */
    private fun sendErrorResponse(clientSocket: Socket, statusCode: Int, message: String) {
        try {
            val errorResponse = JSONObject().apply {
                put("success", false)
                put("data", JSONObject.NULL)
                put("error", message)
            }

            sendResponse(clientSocket, statusCode, errorResponse)
        } catch (e: JSONException) {
            Log.e(TAG, "Error creating JSON error response", e)

            // Fallback to a simple error response
            val statusText = getStatusText(statusCode)
            val response = "HTTP/1.1 $statusCode $statusText\r\n" +
                    "Content-Type: text/plain\r\n" +
                    "Connection: close\r\n" +
                    "\r\n" +
                    message

            clientSocket.getOutputStream().apply {
                write(response.toByteArray(StandardCharsets.UTF_8))
                flush()
            }
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
    private fun sendResponse(clientSocket: Socket, statusCode: Int, responseBody: JSONObject) {
        val statusText = getStatusText(statusCode)
        val jsonResponse = responseBody.toString()

        val responseBuilder = StringBuilder().apply {
            append("HTTP/1.1 $statusCode $statusText\r\n")
            append("Content-Type: application/json\r\n")
            append("Content-Length: ${jsonResponse.toByteArray(StandardCharsets.UTF_8).size}\r\n")
            append("Connection: close\r\n")
            append("\r\n")
            append(jsonResponse)
        }

        clientSocket.getOutputStream().apply {
            write(responseBuilder.toString().toByteArray(StandardCharsets.UTF_8))
            flush()
        }
    }

    /**
     * Gets the text representation of an HTTP status code
     *
     * @param statusCode The HTTP status code
     * @return The text representation
     */
    private fun getStatusText(statusCode: Int): String {
        return when (statusCode) {
            200 -> "OK"
            201 -> "Created"
            400 -> "Bad Request"
            404 -> "Not Found"
            500 -> "Internal Server Error"
            else -> "Unknown Status"
        }
    }

    /**
     * Gets the server port from the configuration
     *
     * @return The server port
     */
    private fun getServerPort(): Int {
        return try {
            context.getSharedPreferences("dsm_service_config", Context.MODE_PRIVATE)
                .getString("server_port", DEFAULT_PORT.toString())?.toInt() ?: DEFAULT_PORT
        } catch (e: NumberFormatException) {
            Log.w(TAG, "Invalid server port in configuration, using default", e)
            DEFAULT_PORT
        }
    }
}
