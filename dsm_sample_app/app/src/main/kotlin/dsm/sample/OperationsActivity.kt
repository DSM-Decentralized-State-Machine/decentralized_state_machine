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
import dsm.client.Operation
import kotlinx.coroutines.launch
import org.json.JSONException
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Activity for demonstrating state machine operations in the DSM backend.
 */
class OperationsActivity : AppCompatActivity() {
    
    // UI components
    private lateinit var operationTypeEditText: EditText
    private lateinit var messageEditText: EditText
    private lateinit var dataEditText: EditText
    private lateinit var applyButton: Button
    private lateinit var refreshButton: Button
    private lateinit var currentStateTextView: TextView
    private lateinit var operationsRecyclerView: RecyclerView
    private lateinit var loadingProgressBar: ProgressBar
    private lateinit var emptyTextView: TextView
    
    // The DSM client
    private val dsmClient by lazy {
        (application as DsmSampleApplication).dsmClient
    }
    
    // Adapter for the operations list
    private val operationsAdapter = OperationAdapter()
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_operations)
        
        // Set up the action bar
        supportActionBar?.title = "DSM Operations"
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        
        // Initialize UI components
        operationTypeEditText = findViewById(R.id.operation_type_edit_text)
        messageEditText = findViewById(R.id.message_edit_text)
        dataEditText = findViewById(R.id.data_edit_text)
        applyButton = findViewById(R.id.apply_button)
        refreshButton = findViewById(R.id.refresh_button)
        currentStateTextView = findViewById(R.id.current_state_text_view)
        operationsRecyclerView = findViewById(R.id.operations_recycler_view)
        loadingProgressBar = findViewById(R.id.loading_progress_bar)
        emptyTextView = findViewById(R.id.empty_text_view)
        
        // Set up the RecyclerView
        operationsRecyclerView.layoutManager = LinearLayoutManager(this)
        operationsRecyclerView.adapter = operationsAdapter
        
        // Set up button click listeners
        applyButton.setOnClickListener {
            applyOperation()
        }
        
        refreshButton.setOnClickListener {
            loadOperations()
        }
        
        // Load operations initially
        loadOperations()
    }
    
    /**
     * Loads all operations from the DSM backend.
     */
    private fun loadOperations() {
        // Show loading state
        loadingProgressBar.visibility = View.VISIBLE
        emptyTextView.visibility = View.GONE
        
        lifecycleScope.launch {
            try {
                // Get operations from the DSM backend
                val (operations, currentState) = dsmClient.getOperations()
                
                // Update the current state text view
                currentStateTextView.text = "Current State: $currentState"
                
                // Update the adapter
                operationsAdapter.setOperations(operations)
                
                // Show empty state if needed
                emptyTextView.visibility = if (operations.isEmpty()) View.VISIBLE else View.GONE
            } catch (e: Exception) {
                Toast.makeText(
                    this@OperationsActivity,
                    "Error loading operations: ${e.message}",
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
     * Applies an operation to the state machine.
     */
    private fun applyOperation() {
        // Get values from input fields
        val operationType = operationTypeEditText.text.toString().trim()
        val message = messageEditText.text.toString().trim()
        val dataString = dataEditText.text.toString().trim()
        
        // Validate operation type
        if (operationType.isBlank()) {
            operationTypeEditText.error = "Operation type is required"
            return
        }
        
        // Parse data as JSON if provided
        var data: JSONObject? = null
        if (dataString.isNotBlank()) {
            try {
                data = JSONObject(dataString)
            } catch (e: JSONException) {
                dataEditText.error = "Invalid JSON"
                return
            }
        }
        
        // Show loading state
        loadingProgressBar.visibility = View.VISIBLE
        applyButton.isEnabled = false
        
        lifecycleScope.launch {
            try {
                // Apply the operation
                val operation = dsmClient.applyOperation(operationType, message, data)
                
                // Show success message
                Toast.makeText(
                    this@OperationsActivity,
                    "Operation applied successfully",
                    Toast.LENGTH_SHORT
                ).show()
                
                // Clear input fields
                operationTypeEditText.text.clear()
                messageEditText.text.clear()
                dataEditText.text.clear()
                
                // Reload operations
                loadOperations()
            } catch (e: Exception) {
                Toast.makeText(
                    this@OperationsActivity,
                    "Error applying operation: ${e.message}",
                    Toast.LENGTH_SHORT
                ).show()
            } finally {
                loadingProgressBar.visibility = View.GONE
                applyButton.isEnabled = true
            }
        }
    }
    
    /**
     * Adapter for the operations RecyclerView.
     */
    private class OperationAdapter : RecyclerView.Adapter<OperationAdapter.OperationViewHolder>() {
        private val operations = ArrayList<Operation>()
        private val dateFormat = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault())
        
        fun setOperations(operations: List<Operation>) {
            this.operations.clear()
            this.operations.addAll(operations)
            notifyDataSetChanged()
        }
        
        override fun onCreateViewHolder(parent: android.view.ViewGroup, viewType: Int): OperationViewHolder {
            val view = android.view.LayoutInflater.from(parent.context)
                .inflate(R.layout.item_operation, parent, false)
            return OperationViewHolder(view)
        }
        
        override fun onBindViewHolder(holder: OperationViewHolder, position: Int) {
            val operation = operations[position]
            
            holder.typeTextView.text = "Type: ${operation.type}"
            holder.messageTextView.text = "Message: ${operation.message}"
            
            val date = Date(operation.timestamp)
            holder.timestampTextView.text = "Timestamp: ${dateFormat.format(date)}"
            
            holder.previousStateTextView.text = "Previous: ${shortenHash(operation.previousState)}"
            holder.nextStateTextView.text = "Next: ${shortenHash(operation.nextState)}"
            
            // Format the data as JSON string
            val dataString = operation.data?.toString(2) ?: "No data"
            holder.dataTextView.text = "Data: $dataString"
        }
        
        override fun getItemCount(): Int = operations.size
        
        /**
         * Shortens a hash string for display.
         * 
         * @param hash The hash string
         * @return The shortened hash
         */
        private fun shortenHash(hash: String): String {
            return if (hash.length > 12) {
                "${hash.substring(0, 6)}...${hash.substring(hash.length - 6)}"
            } else {
                hash
            }
        }
        
        class OperationViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
            val typeTextView: TextView = itemView.findViewById(R.id.type_text_view)
            val messageTextView: TextView = itemView.findViewById(R.id.message_text_view)
            val timestampTextView: TextView = itemView.findViewById(R.id.timestamp_text_view)
            val previousStateTextView: TextView = itemView.findViewById(R.id.previous_state_text_view)
            val nextStateTextView: TextView = itemView.findViewById(R.id.next_state_text_view)
            val dataTextView: TextView = itemView.findViewById(R.id.data_text_view)
        }
    }
    
    override fun onSupportNavigateUp(): Boolean {
        finish()
        return true
    }
}
