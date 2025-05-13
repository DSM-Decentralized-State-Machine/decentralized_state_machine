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
import dsm.client.Vault
import kotlinx.coroutines.launch
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Activity for managing vaults in the DSM backend.
 * Demonstrates the vault-related functionality of the DSM client SDK.
 */
class VaultActivity : AppCompatActivity() {
    
    // UI components
    private lateinit var identityIdEditText: EditText
    private lateinit var vaultNameEditText: EditText
    private lateinit var createVaultButton: Button
    private lateinit var refreshButton: Button
    private lateinit var vaultsRecyclerView: RecyclerView
    private lateinit var loadingProgressBar: ProgressBar
    private lateinit var emptyTextView: TextView
    
    // The DSM client
    private val dsmClient by lazy {
        (application as DsmSampleApplication).dsmClient
    }
    
    // Adapter for the vaults list
    private val vaultsAdapter = VaultAdapter { vault ->
        // Handle vault item click
        showVaultDetails(vault)
    }
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_vault)
        
        // Set up the action bar
        supportActionBar?.title = "DSM Vaults"
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        
        // Initialize UI components
        identityIdEditText = findViewById(R.id.identity_id_edit_text)
        vaultNameEditText = findViewById(R.id.vault_name_edit_text)
        createVaultButton = findViewById(R.id.create_vault_button)
        refreshButton = findViewById(R.id.refresh_button)
        vaultsRecyclerView = findViewById(R.id.vaults_recycler_view)
        loadingProgressBar = findViewById(R.id.loading_progress_bar)
        emptyTextView = findViewById(R.id.empty_text_view)
        
        // Set up the RecyclerView
        vaultsRecyclerView.layoutManager = LinearLayoutManager(this)
        vaultsRecyclerView.adapter = vaultsAdapter
        
        // Set up button click listeners
        createVaultButton.setOnClickListener {
            createVault()
        }
        
        refreshButton.setOnClickListener {
            loadVaults()
        }
        
        // Load vaults initially
        loadVaults()
    }
    
    /**
     * Loads all vaults from the DSM backend.
     */
    private fun loadVaults() {
        // Show loading state
        loadingProgressBar.visibility = View.VISIBLE
        emptyTextView.visibility = View.GONE
        
        lifecycleScope.launch {
            try {
                // Get vaults from the DSM backend
                val vaults = dsmClient.getVaults()
                
                // Update the adapter
                vaultsAdapter.setVaults(vaults)
                
                // Show empty state if needed
                emptyTextView.visibility = if (vaults.isEmpty()) View.VISIBLE else View.GONE
            } catch (e: Exception) {
                Toast.makeText(
                    this@VaultActivity,
                    "Error loading vaults: ${e.message}",
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
     * Creates a new vault in the DSM backend.
     */
    private fun createVault() {
        // Get values from input fields
        val identityId = identityIdEditText.text.toString().trim()
        val vaultName = vaultNameEditText.text.toString().trim().takeIf { it.isNotBlank() }
        
        // Validate identity ID
        if (identityId.isBlank()) {
            identityIdEditText.error = "Identity ID is required"
            return
        }
        
        // Show loading state
        loadingProgressBar.visibility = View.VISIBLE
        createVaultButton.isEnabled = false
        
        lifecycleScope.launch {
            try {
                // Create a new vault
                val vaultId = dsmClient.createVault(identityId, vaultName)
                
                // Show success message
                Toast.makeText(
                    this@VaultActivity,
                    "Vault created with ID: $vaultId",
                    Toast.LENGTH_SHORT
                ).show()
                
                // Clear input fields
                identityIdEditText.text.clear()
                vaultNameEditText.text.clear()
                
                // Reload vaults
                loadVaults()
            } catch (e: Exception) {
                Toast.makeText(
                    this@VaultActivity,
                    "Error creating vault: ${e.message}",
                    Toast.LENGTH_SHORT
                ).show()
            } finally {
                loadingProgressBar.visibility = View.GONE
                createVaultButton.isEnabled = true
            }
        }
    }
    
    /**
     * Shows the details of a vault.
     * 
     * @param vault The vault to show
     */
    private fun showVaultDetails(vault: Vault) {
        // Create a dialog to show vault details
        val dialog = androidx.appcompat.app.AlertDialog.Builder(this)
            .setTitle("Vault Details")
            .setMessage(
                """
                ID: ${vault.id}
                Identity ID: ${vault.identityId}
                Name: ${vault.name}
                Created: ${formatDate(vault.createdAt)}
                
                Data: ${formatVaultData(vault.data)}
                """.trimIndent()
            )
            .setPositiveButton("OK", null)
            .create()
        
        dialog.show()
    }
    
    /**
     * Formats a timestamp as a date string.
     * 
     * @param timestamp The timestamp to format
     * @return The formatted date string
     */
    private fun formatDate(timestamp: Long): String {
        val dateFormat = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault())
        return dateFormat.format(Date(timestamp))
    }
    
    /**
     * Formats vault data as a string.
     * 
     * @param data The vault data
     * @return The formatted string
     */
    private fun formatVaultData(data: JSONObject?): String {
        return data?.toString(2) ?: "No data"
    }
    
    /**
     * Adapter for the vaults RecyclerView.
     */
    private class VaultAdapter(private val onItemClick: (Vault) -> Unit) : 
            RecyclerView.Adapter<VaultAdapter.VaultViewHolder>() {
        
        private val vaults = ArrayList<Vault>()
        private val dateFormat = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault())
        
        fun setVaults(vaults: List<Vault>) {
            this.vaults.clear()
            this.vaults.addAll(vaults)
            notifyDataSetChanged()
        }
        
        override fun onCreateViewHolder(parent: android.view.ViewGroup, viewType: Int): VaultViewHolder {
            val view = android.view.LayoutInflater.from(parent.context)
                .inflate(R.layout.item_vault, parent, false)
            return VaultViewHolder(view, onItemClick)
        }
        
        override fun onBindViewHolder(holder: VaultViewHolder, position: Int) {
            val vault = vaults[position]
            
            holder.idTextView.text = "ID: ${vault.id}"
            holder.identityIdTextView.text = "Identity ID: ${vault.identityId}"
            holder.nameTextView.text = "Name: ${vault.name}"
            
            val date = Date(vault.createdAt)
            holder.createdAtTextView.text = "Created: ${dateFormat.format(date)}"
            
            // Store the vault in the item view's tag
            holder.itemView.tag = vault
        }
        
        override fun getItemCount(): Int = vaults.size
        
        class VaultViewHolder(itemView: View, private val onItemClick: (Vault) -> Unit) : 
                RecyclerView.ViewHolder(itemView) {
            
            val idTextView: TextView = itemView.findViewById(R.id.id_text_view)
            val identityIdTextView: TextView = itemView.findViewById(R.id.identity_id_text_view)
            val nameTextView: TextView = itemView.findViewById(R.id.name_text_view)
            val createdAtTextView: TextView = itemView.findViewById(R.id.created_at_text_view)
            
            init {
                itemView.setOnClickListener {
                    val vault = itemView.tag as? Vault
                    vault?.let { onItemClick(it) }
                }
            }
        }
    }
    
    override fun onSupportNavigateUp(): Boolean {
        finish()
        return true
    }
}
