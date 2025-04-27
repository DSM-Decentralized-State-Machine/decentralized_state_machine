package dsm.sample

import android.Manifest
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import dsm.client.DsmBluetoothClient
import dsm.client.Identity
import kotlinx.coroutines.launch
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Activity for demonstrating Bluetooth device-to-device communication with the DSM backend.
 */
class BluetoothActivity : AppCompatActivity() {
    
    // UI components
    private lateinit var statusTextView: TextView
    private lateinit var scanButton: Button
    private lateinit var devicesRecyclerView: RecyclerView
    private lateinit var loadingProgressBar: ProgressBar
    private lateinit var emptyTextView: TextView
    
    // Bluetooth client
    private lateinit var bluetoothClient: DsmBluetoothClient
    
    // Bluetooth adapter
    private val bluetoothAdapter: BluetoothAdapter? by lazy {
        val bluetoothManager = getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
        bluetoothManager.adapter
    }
    
    // Adapter for the devices list
    private val devicesAdapter = DeviceAdapter { device ->
        // Handle device item click
        connectToDevice(device)
    }
    
    // Bluetooth device discovery receiver
    private val discoveryReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            when (intent.action) {
                BluetoothDevice.ACTION_FOUND -> {
                    val device = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                        intent.getParcelableExtra(
                            BluetoothDevice.EXTRA_DEVICE,
                            BluetoothDevice::class.java
                        )
                    } else {
                        @Suppress("DEPRECATION")
                        intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE)
                    }
                    
                    device?.let {
                        devicesAdapter.addDevice(it)
                    }
                }
                BluetoothAdapter.ACTION_DISCOVERY_STARTED -> {
                    // Show loading state
                    loadingProgressBar.visibility = View.VISIBLE
                    emptyTextView.visibility = View.GONE
                    statusTextView.text = "Scanning for devices..."
                }
                BluetoothAdapter.ACTION_DISCOVERY_FINISHED -> {
                    // Hide loading state
                    loadingProgressBar.visibility = View.GONE
                    statusTextView.text = "Scan complete"
                    
                    // Show empty state if needed
                    if (devicesAdapter.itemCount == 0) {
                        emptyTextView.visibility = View.VISIBLE
                    }
                }
            }
        }
    }
    
    // Bluetooth permission request launcher
    private val requestBluetoothPermissions = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { permissions ->
        if (permissions.entries.all { it.value }) {
            // All permissions granted, start scan
            startDeviceDiscovery()
        } else {
            // Some permissions denied
            Toast.makeText(
                this,
                "Bluetooth permissions are required for device discovery",
                Toast.LENGTH_SHORT
            ).show()
        }
    }
    
    // Bluetooth enable request launcher
    private val requestEnableBluetooth = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            // Bluetooth enabled, check permissions
            checkBluetoothPermissions()
        } else {
            // Bluetooth not enabled
            Toast.makeText(
                this,
                "Bluetooth must be enabled for device discovery",
                Toast.LENGTH_SHORT
            ).show()
        }
    }
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_bluetooth)
        
        // Set up the action bar
        supportActionBar?.title = "DSM Bluetooth"
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        
        // Initialize UI components
        statusTextView = findViewById(R.id.status_text_view)
        scanButton = findViewById(R.id.scan_button)
        devicesRecyclerView = findViewById(R.id.devices_recycler_view)
        loadingProgressBar = findViewById(R.id.loading_progress_bar)
        emptyTextView = findViewById(R.id.empty_text_view)
        
        // Initialize Bluetooth client
        bluetoothClient = DsmBluetoothClient(this)
        
        // Set up the RecyclerView
        devicesRecyclerView.layoutManager = LinearLayoutManager(this)
        devicesRecyclerView.adapter = devicesAdapter
        
        // Set up button click listeners
        scanButton.setOnClickListener {
            // Check if Bluetooth is available and enabled
            if (bluetoothClient.isBluetoothAvailable()) {
                // Start device discovery if permissions are granted
                checkBluetoothPermissions()
            } else {
                // Bluetooth not available or not enabled
                if (bluetoothAdapter == null) {
                    Toast.makeText(
                        this,
                        "Bluetooth is not supported on this device",
                        Toast.LENGTH_SHORT
                    ).show()
                } else {
                    // Request to enable Bluetooth
                    val enableBtIntent = Intent(BluetoothAdapter.ACTION_REQUEST_ENABLE)
                    requestEnableBluetooth.launch(enableBtIntent)
                }
            }
        }
        
        // Register for device discovery broadcasts
        val filter = IntentFilter().apply {
            addAction(BluetoothDevice.ACTION_FOUND)
            addAction(BluetoothAdapter.ACTION_DISCOVERY_STARTED)
            addAction(BluetoothAdapter.ACTION_DISCOVERY_FINISHED)
        }
        registerReceiver(discoveryReceiver, filter)
        
        // Check if Bluetooth is available
        statusTextView.text = if (bluetoothClient.isBluetoothAvailable()) {
            "Bluetooth is available"
        } else {
            "Bluetooth is not available"
        }
    }
    
    override fun onDestroy() {
        super.onDestroy()
        
        // Unregister receiver
        unregisterReceiver(discoveryReceiver)
        
        // Cancel discovery if it's running
        if (bluetoothAdapter?.isDiscovering == true) {
            bluetoothAdapter?.cancelDiscovery()
        }
    }
    
    /**
     * Checks if the necessary Bluetooth permissions are granted.
     * Requests permissions if not granted.
     */
    private fun checkBluetoothPermissions() {
        val permissions = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            arrayOf(
                Manifest.permission.BLUETOOTH_SCAN,
                Manifest.permission.BLUETOOTH_CONNECT
            )
        } else {
            arrayOf(
                Manifest.permission.BLUETOOTH,
                Manifest.permission.BLUETOOTH_ADMIN,
                Manifest.permission.ACCESS_FINE_LOCATION
            )
        }
        
        val permissionsToRequest = permissions.filter {
            ActivityCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED
        }.toTypedArray()
        
        if (permissionsToRequest.isEmpty()) {
            // All permissions granted, start discovery
            startDeviceDiscovery()
        } else {
            // Request permissions
            requestBluetoothPermissions.launch(permissionsToRequest)
        }
    }
    
    /**
     * Starts Bluetooth device discovery.
     */
    private fun startDeviceDiscovery() {
        // Clear the list of devices
        devicesAdapter.clearDevices()
        
        // Cancel discovery if it's already running
        if (bluetoothAdapter?.isDiscovering == true) {
            bluetoothAdapter?.cancelDiscovery()
        }
        
        // Check permissions again (for safety)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S &&
            (ActivityCompat.checkSelfPermission(
                this,
                Manifest.permission.BLUETOOTH_SCAN
            ) != PackageManager.PERMISSION_GRANTED)
        ) {
            Toast.makeText(
                this,
                "Bluetooth scan permission not granted",
                Toast.LENGTH_SHORT
            ).show()
            return
        }
        
        // Add paired devices first
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S &&
            ActivityCompat.checkSelfPermission(
                this,
                Manifest.permission.BLUETOOTH_CONNECT
            ) != PackageManager.PERMISSION_GRANTED
        ) {
            Toast.makeText(
                this,
                "Bluetooth connect permission not granted",
                Toast.LENGTH_SHORT
            ).show()
        } else {
            // Add paired devices
            @Suppress("DEPRECATION")
            bluetoothAdapter?.bondedDevices?.forEach { device ->
                devicesAdapter.addDevice(device)
            }
        }
        
        // Start discovery
        bluetoothAdapter?.startDiscovery()
    }
    
    /**
     * Connects to a Bluetooth device running the DSM backend.
     * 
     * @param device The Bluetooth device to connect to
     */
    private fun connectToDevice(device: BluetoothDevice) {
        // Cancel discovery if it's running
        if (bluetoothAdapter?.isDiscovering == true) {
            bluetoothAdapter?.cancelDiscovery()
        }
        
        // Show loading state
        loadingProgressBar.visibility = View.VISIBLE
        statusTextView.text = "Connecting to ${device.name ?: device.address}..."
        
        lifecycleScope.launch {
            try {
                // Connect to the device
                val connection = bluetoothClient.connectToDevice(device)
                
                // Get identities from the device
                val identities = connection.getIdentities()
                
                // Hide loading state
                loadingProgressBar.visibility = View.GONE
                statusTextView.text = "Connected to ${device.name ?: device.address}"
                
                // Show identities in a dialog
                showIdentitiesDialog(device, identities, connection)
            } catch (e: Exception) {
                // Hide loading state
                loadingProgressBar.visibility = View.GONE
                statusTextView.text = "Error: ${e.message}"
                
                Toast.makeText(
                    this@BluetoothActivity,
                    "Error connecting to device: ${e.message}",
                    Toast.LENGTH_SHORT
                ).show()
            }
        }
    }
    
    /**
     * Shows a dialog with the identities from a Bluetooth device.
     * 
     * @param device The Bluetooth device
     * @param identities The list of identities
     * @param connection The Bluetooth connection
     */
    private fun showIdentitiesDialog(
        device: BluetoothDevice,
        identities: List<Identity>,
        connection: DsmBluetoothClient.DsmBluetoothConnection
    ) {
        // Format identities as a string
        val identitiesStr = identities.joinToString("\n\n") { identity ->
            val dateFormat = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault())
            val date = Date(identity.createdAt)
            
            """
            ID: ${identity.id}
            Device ID: ${identity.deviceId}
            Created: ${dateFormat.format(date)}
            """.trimIndent()
        }
        
        // Show a dialog with the identities
        val dialog = AlertDialog.Builder(this)
            .setTitle("Identities from ${device.name ?: device.address}")
            .setMessage(
                if (identities.isEmpty()) {
                    "No identities found"
                } else {
                    identitiesStr
                }
            )
            .setPositiveButton("Create Identity") { _, _ ->
                // Create a new identity on the remote device
                createRemoteIdentity(device, connection)
            }
            .setNegativeButton("Close") { _, _ ->
                // Close the connection
                connection.close()
            }
            .setCancelable(false)
            .create()
        
        dialog.show()
    }
    
    /**
     * Creates a new identity on a remote device.
     * 
     * @param device The Bluetooth device
     * @param connection The Bluetooth connection
     */
    private fun createRemoteIdentity(
        device: BluetoothDevice,
        connection: DsmBluetoothClient.DsmBluetoothConnection
    ) {
        // Show loading state
        loadingProgressBar.visibility = View.VISIBLE
        statusTextView.text = "Creating identity on ${device.name ?: device.address}..."
        
        lifecycleScope.launch {
            try {
                // Create a new identity
                val identity = connection.createIdentity("remote-device-${System.currentTimeMillis()}")
                
                // Hide loading state
                loadingProgressBar.visibility = View.GONE
                statusTextView.text = "Identity created on ${device.name ?: device.address}"
                
                // Show a dialog with the new identity
                val dialog = AlertDialog.Builder(this@BluetoothActivity)
                    .setTitle("Identity Created")
                    .setMessage(
                        """
                        ID: ${identity.id}
                        Device ID: ${identity.deviceId}
                        Created: ${SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(Date(identity.createdAt))}
                        """.trimIndent()
                    )
                    .setPositiveButton("OK") { _, _ ->
                        // Close the connection
                        connection.close()
                    }
                    .setCancelable(false)
                    .create()
                
                dialog.show()
            } catch (e: Exception) {
                // Hide loading state
                loadingProgressBar.visibility = View.GONE
                statusTextView.text = "Error: ${e.message}"
                
                Toast.makeText(
                    this@BluetoothActivity,
                    "Error creating identity: ${e.message}",
                    Toast.LENGTH_SHORT
                ).show()
                
                // Close the connection
                connection.close()
            }
        }
    }
    
    /**
     * Adapter for the Bluetooth devices RecyclerView.
     */
    private class DeviceAdapter(private val onItemClick: (BluetoothDevice) -> Unit) :
            RecyclerView.Adapter<DeviceAdapter.DeviceViewHolder>() {
        
        private val devices = ArrayList<BluetoothDevice>()
        
        fun clearDevices() {
            devices.clear()
            notifyDataSetChanged()
        }
        
        fun addDevice(device: BluetoothDevice) {
            // Check if the device is already in the list
            if (!devices.any { it.address == device.address }) {
                devices.add(device)
                notifyItemInserted(devices.size - 1)
            }
        }
        
        override fun onCreateViewHolder(parent: android.view.ViewGroup, viewType: Int): DeviceViewHolder {
            val view = android.view.LayoutInflater.from(parent.context)
                .inflate(R.layout.item_bluetooth_device, parent, false)
            return DeviceViewHolder(view, onItemClick)
        }
        
        override fun onBindViewHolder(holder: DeviceViewHolder, position: Int) {
            val device = devices[position]
            
            // Check if we have permission to access the device name
            val deviceName = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S &&
                ActivityCompat.checkSelfPermission(
                    holder.itemView.context,
                    Manifest.permission.BLUETOOTH_CONNECT
                ) != PackageManager.PERMISSION_GRANTED
            ) {
                "Unknown Device"
            } else {
                device.name ?: "Unknown Device"
            }
            
            holder.nameTextView.text = deviceName
            holder.addressTextView.text = device.address
            
            // Store the device in the item view's tag
            holder.itemView.tag = device
        }
        
        override fun getItemCount(): Int = devices.size
        
        class DeviceViewHolder(itemView: View, private val onItemClick: (BluetoothDevice) -> Unit) :
                RecyclerView.ViewHolder(itemView) {
            
            val nameTextView: TextView = itemView.findViewById(R.id.name_text_view)
            val addressTextView: TextView = itemView.findViewById(R.id.address_text_view)
            
            init {
                itemView.setOnClickListener {
                    val device = itemView.tag as? BluetoothDevice
                    device?.let { onItemClick(it) }
                }
            }
        }
    }
    
    override fun onSupportNavigateUp(): Boolean {
        finish()
        return true
    }
}
