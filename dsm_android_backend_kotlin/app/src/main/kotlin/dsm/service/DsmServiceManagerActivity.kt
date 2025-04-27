package dsm.service

import android.app.ActivityManager
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity

/**
 * Management activity for the DSM Backend Service.
 * This activity allows users to start, stop, and configure the service.
 */
class DsmServiceManagerActivity : AppCompatActivity() {
    companion object {
        private const val TAG = "DsmServiceManager"
    }
    
    // UI components
    private lateinit var statusTextView: TextView
    private lateinit var startButton: Button
    private lateinit var stopButton: Button
    private lateinit var portEditText: EditText
    private lateinit var saveSettingsButton: Button
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_dsm_service_manager)
        
        // Initialize UI components
        statusTextView = findViewById(R.id.status_text_view)
        startButton = findViewById(R.id.start_button)
        stopButton = findViewById(R.id.stop_button)
        portEditText = findViewById(R.id.port_text_view)
        saveSettingsButton = findViewById(R.id.save_settings_button)
        
        // Set up button click listeners
        startButton.setOnClickListener {
            startService()
        }
        
        stopButton.setOnClickListener {
            stopService()
        }
        
        saveSettingsButton.setOnClickListener {
            saveSettings()
        }
        
        // Load settings
        loadSettings()
        
        // Update status
        updateServiceStatus()
    }
    
    override fun onResume() {
        super.onResume()
        updateServiceStatus()
    }
    
    /**
     * Starts the DSM backend service
     */
    private fun startService() {
        val intent = Intent(this, DsmBackendService::class.java)
        
        // Start the service based on Android version
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent)
        } else {
            startService(intent)
        }
        
        updateServiceStatus()
    }
    
    /**
     * Stops the DSM backend service
     */
    private fun stopService() {
        val intent = Intent(this, DsmBackendService::class.java)
        stopService(intent)
        
        updateServiceStatus()
    }
    
    /**
     * Updates the service status display
     */
    private fun updateServiceStatus() {
        val isRunning = isServiceRunning()
        
        if (isRunning) {
            statusTextView.text = getString(R.string.service_running)
            startButton.isEnabled = false
            stopButton.isEnabled = true
        } else {
            statusTextView.text = getString(R.string.service_stopped)
            startButton.isEnabled = true
            stopButton.isEnabled = false
        }
    }
    
    /**
     * Checks if the service is running
     * 
     * @return true if the service is running, false otherwise
     */
    private fun isServiceRunning(): Boolean {
        val manager = getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
        
        for (service in manager.getRunningServices(Integer.MAX_VALUE)) {
            if (DsmBackendService::class.java.name == service.service.className) {
                return true
            }
        }
        
        return false
    }
    
    /**
     * Saves the service settings
     */
    private fun saveSettings() {
        try {
            val port = portEditText.text.toString().toInt()
            
            if (port < 1024 || port > 65535) {
                // Invalid port number
                portEditText.error = getString(R.string.invalid_port)
                return
            }
            
            // Save settings
            val prefs = getSharedPreferences("dsm_service_config", Context.MODE_PRIVATE)
            prefs.edit().apply {
                putString("server_port", port.toString())
                apply()
            }
            
            // Show a toast message
            Toast.makeText(this, getString(R.string.settings_saved), Toast.LENGTH_SHORT).show()
            
            // Restart the service if it's running
            if (isServiceRunning()) {
                stopService()
                startService()
            }
        } catch (e: NumberFormatException) {
            portEditText.error = getString(R.string.invalid_port)
        }
    }
    
    /**
     * Loads the service settings
     */
    private fun loadSettings() {
        val prefs = getSharedPreferences("dsm_service_config", Context.MODE_PRIVATE)
        val port = prefs.getString("server_port", getString(R.string.default_port))
        
        portEditText.setText(port)
    }
}
