package dsm.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import android.util.Log

/**
 * Boot receiver for the DSM Backend Service.
 * This receiver starts the service automatically when the device boots.
 */
class BootReceiver : BroadcastReceiver() {
    companion object {
        private const val TAG = "DsmBootReceiver"
    }
    
    override fun onReceive(context: Context, intent: Intent) {
        if (Intent.ACTION_BOOT_COMPLETED == intent.action) {
            Log.i(TAG, "Boot completed, starting DSM Backend Service")
            
            // Create an intent to start the service
            val serviceIntent = Intent(context, DsmBackendService::class.java)
            
            // Start the service based on Android version
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(serviceIntent)
            } else {
                context.startService(serviceIntent)
            }
        }
    }
}
