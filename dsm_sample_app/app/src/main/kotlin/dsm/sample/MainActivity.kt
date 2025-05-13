package dsm.sample

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.launch

/**
 * Main activity for the DSM Sample App.
 * Shows the connection status and provides buttons to access different features.
 */
class MainActivity : AppCompatActivity() {
    
    // UI components
    private lateinit var statusTextView: TextView
    private lateinit var identitiesButton: Button
    private lateinit var vaultsButton: Button
    private lateinit var operationsButton: Button
    private lateinit var bluetoothButton: Button
    private lateinit var checkConnectionButton: Button
    
    // The DSM client
    private val dsmClient by lazy {
        (application as DsmSampleApplication).dsmClient
    }
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        
        // Initialize UI components
        statusTextView = findViewById(R.id.status_text_view)
        identitiesButton = findViewById(R.id.identities_button)
        vaultsButton = findViewById(R.id.vaults_button)
        operationsButton = findViewById(R.id.operations_button)
        bluetoothButton = findViewById(R.id.bluetooth_button)
        checkConnectionButton = findViewById(R.id.check_connection_button)
        
        // Set up button click listeners
        identitiesButton.setOnClickListener {
            startActivity(Intent(this, IdentityActivity::class.java))
        }
        
        vaultsButton.setOnClickListener {
            startActivity(Intent(this, VaultActivity::class.java))
        }
        
        operationsButton.setOnClickListener {
            startActivity(Intent(this, OperationsActivity::class.java))
        }
        
        bluetoothButton.setOnClickListener {
            startActivity(Intent(this, BluetoothActivity::class.java))
        }
        
        checkConnectionButton.setOnClickListener {
            checkConnection()
        }
        
        // Check connection initially
        checkConnection()
    }
    
    override fun onResume() {
        super.onResume()
        checkConnection()
    }
    
    /**
     * Checks the connection to the DSM backend service.
     */
    private fun checkConnection() {
        statusTextView.text = "Checking connection..."
        identitiesButton.isEnabled = false
        vaultsButton.isEnabled = false
        operationsButton.isEnabled = false
        bluetoothButton.isEnabled = false
        
        lifecycleScope.launch {
            try {
                val isConnected = dsmClient.checkConnection()
                
                if (isConnected) {
                    statusTextView.text = "Connected to DSM backend"
                    identitiesButton.isEnabled = true
                    vaultsButton.isEnabled = true
                    operationsButton.isEnabled = true
                    bluetoothButton.isEnabled = true
                } else {
                    statusTextView.text = "Not connected to DSM backend"
                    
                    // Try to ensure the service is available
                    val serviceAvailable = dsmClient.ensureServiceAvailable()
                    if (serviceAvailable) {
                        statusTextView.text = "Connected to DSM backend"
                        identitiesButton.isEnabled = true
                        vaultsButton.isEnabled = true
                        operationsButton.isEnabled = true
                        bluetoothButton.isEnabled = true
                    } else {
                        Toast.makeText(
                            this@MainActivity,
                            "Failed to connect to DSM backend",
                            Toast.LENGTH_SHORT
                        ).show()
                    }
                }
            } catch (e: Exception) {
                statusTextView.text = "Error: ${e.message}"
                Toast.makeText(
                    this@MainActivity,
                    "Error checking connection: ${e.message}",
                    Toast.LENGTH_SHORT
                ).show()
            }
        }
    }
}
