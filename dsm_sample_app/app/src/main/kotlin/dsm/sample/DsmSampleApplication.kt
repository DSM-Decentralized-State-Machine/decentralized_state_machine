package dsm.sample

import android.app.Application
import dsm.client.DsmClient
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

/**
 * Application class for the DSM Sample App.
 * Initializes the DSM client and ensures the backend service is available.
 */
class DsmSampleApplication : Application() {
    
    // Application scope for coroutines
    private val applicationScope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    
    // DSM client instance
    lateinit var dsmClient: DsmClient
        private set
    
    override fun onCreate() {
        super.onCreate()
        
        // Initialize the DSM client
        dsmClient = DsmClient.createWithDefaults(this)
        
        // Ensure the DSM backend service is available
        applicationScope.launch {
            try {
                if (dsmClient.ensureServiceAvailable()) {
                    android.util.Log.i(TAG, "DSM backend service is available")
                } else {
                    android.util.Log.w(TAG, "DSM backend service is not available")
                }
            } catch (e: Exception) {
                android.util.Log.e(TAG, "Error ensuring DSM backend service availability", e)
            }
        }
    }
    
    companion object {
        private const val TAG = "DsmSampleApp"
    }
}
