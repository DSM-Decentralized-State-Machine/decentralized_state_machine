package dsm.sample

import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import dsm.client.Identity
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Activity for managing identities in the DSM backend.
 * Demonstrates the identity-related functionality of the DSM client SDK.
 */
class IdentityActivity : AppCompatActivity() {
    
    // UI components
    private lateinit var deviceIdEditText: EditText
    private lateinit var createIdentityButton: Button
    private lateinit var refreshButton: Button
    private lateinit var identitiesRecyclerView: RecyclerView
    private lateinit var loadingProgressBar: ProgressBar
    private lateinit var emptyTextView: TextView
    
    // The DSM client
    private val dsmClient by lazy {
        (application as DsmSampleApplication).dsmClient
    }
    
    // Adapter for the identities list
    private val identitiesAdapter = IdentityAdapter()
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_identity)
        
        // Set up the action bar
        supportActionBar?.title = "DSM Identities"
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        
        // Initialize UI components
        deviceIdEditText = findViewById(R.id.device_id_edit_text)
        createIdentityButton = findViewById(R.id.create_identity_button)
        refreshButton = findViewById(R.id.refresh_button)
        identitiesRecyclerView = findViewById(R.id.identities_recycler_view)
        loadingProgressBar = findViewById(R.id.loading_progress_bar)
        emptyTextView = findViewById(R.id.empty_text_view)
        
        // Set up the RecyclerView
        identitiesRecyclerView.layoutManager = LinearLayoutManager(this)
        identitiesRecyclerView.adapter = identitiesAdapter
        
        // Set up button click listeners
        createIdentityButton.setOnClickListener {
            createIdentity()
        }
        
        refreshButton.setOnClickListener {
            loadIdentities()
        }
        
        // Load identities initially
        loadIdentities()
    }
    
    /**
     * Loads all identities from the DSM backend.
     */
    private fun loadIdentities() {
        // Show loading state
        loadingProgressBar.visibility = View.VISIBLE
        emptyTextView.visibility = View.GONE
        
        lifecycleScope.launch {
            try {
                // Get identities from the DSM backend
                val identities = dsmClient.getIdentities()
                
                // Update the adapter
                identitiesAdapter.setIdentities(identities)
                
                // Show empty state if needed
                emptyTextView.visibility = if (identities.isEmpty()) View.VISIBLE else View.GONE
            } catch (e: Exception) {
                Toast.makeText(
                    this@IdentityActivity,
                    "Error loading identities: ${e.message}",
                    Toast.LENGTH_SHORT
                ).show()
                
                emptyTextView.visibility = View.VISIBLE
                emptyTextView.text = "Error: ${e.message}"
            } finally {
                loadingProgressBar.visibility = View.GONE
            }
        }
    }
    
    /**
     * Creates a new identity in the DSM backend.
     */
    private fun createIdentity() {
        // Get the device ID from the edit text
        val deviceId = deviceIdEditText.text.toString().takeIf { it.isNotBlank() }
        
        // Show loading state
        loadingProgressBar.visibility = View.VISIBLE
        createIdentityButton.isEnabled = false
        
        lifecycleScope.launch {
            try {
                // Create a new identity
                val identityId = dsmClient.createIdentity(deviceId)
                
                // Show success message
                Toast.makeText(
                    this@IdentityActivity,
                    "Identity created with ID: $identityId",
                    Toast.LENGTH_SHORT
                ).show()
                
                // Clear the device ID field
                deviceIdEditText.text.clear()
                
                // Reload identities
                loadIdentities()
            } catch (e: Exception) {
                Toast.makeText(
                    this@IdentityActivity,
                    "Error creating identity: ${e.message}",
                    Toast.LENGTH_SHORT
                ).show()
            } finally {
                loadingProgressBar.visibility = View.GONE
                createIdentityButton.isEnabled = true
            }
        }
    }
    
    /**
     * Adapter for the identities RecyclerView.
     */
    private class IdentityAdapter : RecyclerView.Adapter<IdentityAdapter.IdentityViewHolder>() {
        private val identities = ArrayList<Identity>()
        private val dateFormat = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault())
        
        fun setIdentities(identities: List<Identity>) {
            this.identities.clear()
            this.identities.addAll(identities)
            notifyDataSetChanged()
        }
        
        override fun onCreateViewHolder(parent: android.view.ViewGroup, viewType: Int): IdentityViewHolder {
            val view = android.view.LayoutInflater.from(parent.context)
                .inflate(R.layout.item_identity, parent, false)
            return IdentityViewHolder(view)
        }
        
        override fun onBindViewHolder(holder: IdentityViewHolder, position: Int) {
            val identity = identities[position]
            
            holder.idTextView.text = "ID: ${identity.id}"
            holder.deviceIdTextView.text = "Device ID: ${identity.deviceId}"
            
            val date = Date(identity.createdAt)
            holder.createdAtTextView.text = "Created: ${dateFormat.format(date)}"
        }
        
        override fun getItemCount(): Int = identities.size
        
        class IdentityViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
            val idTextView: TextView = itemView.findViewById(R.id.id_text_view)
            val deviceIdTextView: TextView = itemView.findViewById(R.id.device_id_text_view)
            val createdAtTextView: TextView = itemView.findViewById(R.id.created_at_text_view)
        }
    }
    
    override fun onSupportNavigateUp(): Boolean {
        finish()
        return true
    }
}
