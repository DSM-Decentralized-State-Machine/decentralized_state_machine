package dsm.service;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Build;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

/**
 * A simple activity for managing the DSM Backend Service.
 * This activity allows users to start, stop, and configure the service.
 */
public class DsmServiceManagerActivity extends Activity {
    private static final String TAG = "DsmServiceManager";
    
    // UI components
    private TextView statusTextView;
    private Button startButton;
    private Button stopButton;
    private TextView portTextView;
    private Button saveSettingsButton;
    
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_dsm_service_manager);
        
        // Get UI components
        statusTextView = findViewById(R.id.status_text_view);
        startButton = findViewById(R.id.start_button);
        stopButton = findViewById(R.id.stop_button);
        portTextView = findViewById(R.id.port_text_view);
        saveSettingsButton = findViewById(R.id.save_settings_button);
        
        // Set up button click listeners
        startButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                startService();
            }
        });
        
        stopButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                stopService();
            }
        });
        
        saveSettingsButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                saveSettings();
            }
        });
        
        // Load settings
        loadSettings();
        
        // Update status
        updateServiceStatus();
    }
    
    @Override
    protected void onResume() {
        super.onResume();
        updateServiceStatus();
    }
    
    /**
     * Starts the DSM backend service
     */
    private void startService() {
        Intent intent = new Intent(this, DsmBackendService.class);
        
        // Start the service based on Android version
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent);
        } else {
            startService(intent);
        }
        
        Log.i(TAG, "DSM Backend Service started");
        updateServiceStatus();
    }
    
    /**
     * Stops the DSM backend service
     */
    private void stopService() {
        Intent intent = new Intent(this, DsmBackendService.class);
        stopService(intent);
        
        Log.i(TAG, "DSM Backend Service stopped");
        updateServiceStatus();
    }
    
    /**
     * Updates the service status display
     */
    private void updateServiceStatus() {
        boolean isRunning = isServiceRunning();
        
        if (isRunning) {
            statusTextView.setText("Service Status: Running");
            startButton.setEnabled(false);
            stopButton.setEnabled(true);
        } else {
            statusTextView.setText("Service Status: Stopped");
            startButton.setEnabled(true);
            stopButton.setEnabled(false);
        }
    }
    
    /**
     * Checks if the service is running
     * 
     * @return true if the service is running, false otherwise
     */
    private boolean isServiceRunning() {
        // Use ActivityManager to check if the service is running
        android.app.ActivityManager manager = (android.app.ActivityManager) getSystemService(Context.ACTIVITY_SERVICE);
        for (android.app.ActivityManager.RunningServiceInfo service : manager.getRunningServices(Integer.MAX_VALUE)) {
            if (DsmBackendService.class.getName().equals(service.service.getClassName())) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * Saves the service settings
     */
    private void saveSettings() {
        try {
            int port = Integer.parseInt(portTextView.getText().toString());
            
            if (port < 1024 || port > 65535) {
                // Invalid port number
                portTextView.setError("Port must be between 1024 and 65535");
                return;
            }
            
            // Save settings
            SharedPreferences prefs = getSharedPreferences("dsm_service_config", Context.MODE_PRIVATE);
            SharedPreferences.Editor editor = prefs.edit();
            editor.putString("server_port", String.valueOf(port));
            editor.apply();
            
            Log.i(TAG, "Settings saved (port: " + port + ")");
            
            // Show a toast message
            android.widget.Toast.makeText(this, "Settings saved", android.widget.Toast.LENGTH_SHORT).show();
            
            // Restart the service if it's running
            if (isServiceRunning()) {
                stopService();
                startService();
            }
        } catch (NumberFormatException e) {
            portTextView.setError("Invalid port number");
        }
    }
    
    /**
     * Loads the service settings
     */
    private void loadSettings() {
        SharedPreferences prefs = getSharedPreferences("dsm_service_config", Context.MODE_PRIVATE);
        String port = prefs.getString("server_port", "7545");
        
        portTextView.setText(port);
    }
}
