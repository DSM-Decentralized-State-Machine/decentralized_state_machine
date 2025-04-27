package dsm.service;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.util.Log;

/**
 * Broadcast receiver that starts the DSM Backend Service when the device boots.
 * This ensures that the DSM backend is always running and available for applications.
 */
public class BootReceiver extends BroadcastReceiver {
    private static final String TAG = "DsmBootReceiver";
    
    @Override
    public void onReceive(Context context, Intent intent) {
        if (Intent.ACTION_BOOT_COMPLETED.equals(intent.getAction())) {
            Log.i(TAG, "Boot completed, starting DSM Backend Service");
            
            // Create an intent to start the service
            Intent serviceIntent = new Intent(context, DsmBackendService.class);
            
            // Start the service based on Android version
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(serviceIntent);
            } else {
                context.startService(serviceIntent);
            }
        }
    }
}
