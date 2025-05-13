#!/bin/bash
# Install DSM as a standalone service
# This script creates a system service for the DSM backend

set -e

# Default installation directory
DSM_INSTALL_DIR="/opt/dsm"
DSM_CONFIG_DIR="/etc/dsm"
DSM_DATA_DIR="/var/lib/dsm"
DSM_PORT=7545

# Process arguments
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        --install-dir)
            DSM_INSTALL_DIR="$2"
            shift
            shift
            ;;
        --config-dir)
            DSM_CONFIG_DIR="$2"
            shift
            shift
            ;;
        --data-dir)
            DSM_DATA_DIR="$2"
            shift
            shift
            ;;
        --port)
            DSM_PORT="$2"
            shift
            shift
            ;;
        --help)
            echo "Usage: $0 [options]"
            echo "Options:"
            echo "  --install-dir DIR    Installation directory (default: /opt/dsm)"
            echo "  --config-dir DIR     Configuration directory (default: /etc/dsm)"
            echo "  --data-dir DIR       Data directory (default: /var/lib/dsm)"
            echo "  --port PORT          Port for DSM API (default: 7545)"
            echo "  --help               Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $key"
            exit 1
            ;;
    esac
done

# Detect OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
    if command -v systemctl &> /dev/null; then
        INIT_SYSTEM="systemd"
    elif command -v service &> /dev/null; then
        INIT_SYSTEM="sysvinit"
    else
        echo "Unsupported init system. Please install manually."
        exit 1
    fi
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
    INIT_SYSTEM="launchd"
elif [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
    OS="windows"
    INIT_SYSTEM="windows"
else
    echo "Unsupported operating system: $OSTYPE"
    exit 1
fi

echo "Installing DSM service for $OS with $INIT_SYSTEM"

# Create directories
echo "Creating directories..."
sudo mkdir -p "$DSM_INSTALL_DIR" "$DSM_CONFIG_DIR" "$DSM_DATA_DIR"

# Build the DSM binary
echo "Building DSM..."
cargo build --release --bin server

# Copy binary and configuration
echo "Installing DSM binary and configuration..."
sudo cp target/release/server "$DSM_INSTALL_DIR/dsm-server"
sudo cp .env.template "$DSM_CONFIG_DIR/dsm.env"

# Configure DSM server
sudo sed -i.bak "s/^PORT=.*/PORT=$DSM_PORT/" "$DSM_CONFIG_DIR/dsm.env"
sudo sed -i.bak "s|^DATA_DIR=.*|DATA_DIR=$DSM_DATA_DIR|" "$DSM_CONFIG_DIR/dsm.env"

# Install system service
case $INIT_SYSTEM in
    systemd)
        echo "Installing systemd service..."
        cat > dsm.service << EOL
[Unit]
Description=Decentralized State Machine Service
After=network.target

[Service]
ExecStart=$DSM_INSTALL_DIR/dsm-server --config $DSM_CONFIG_DIR/dsm.env
Restart=on-failure
User=dsm
Group=dsm
Environment=DSM_CONFIG_FILE=$DSM_CONFIG_DIR/dsm.env

[Install]
WantedBy=multi-user.target
EOL

        sudo mv dsm.service /etc/systemd/system/
        
        # Create a dedicated user for the service
        if ! id -u dsm &>/dev/null; then
            sudo useradd -r -s /bin/false dsm
        fi
        
        sudo chown -R dsm:dsm "$DSM_DATA_DIR"
        sudo chown -R dsm:dsm "$DSM_CONFIG_DIR"
        
        sudo systemctl daemon-reload
        sudo systemctl enable dsm
        sudo systemctl start dsm
        ;;
        
    sysvinit)
        echo "Installing SysVinit service..."
        cat > dsm << EOL
#!/bin/sh
### BEGIN INIT INFO
# Provides:          dsm
# Required-Start:    $remote_fs $syslog
# Required-Stop:     $remote_fs $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Decentralized State Machine Service
# Description:       Decentralized State Machine Service
### END INIT INFO

PATH=/sbin:/usr/sbin:/bin:/usr/bin
DESC="Decentralized State Machine Service"
NAME=dsm
DAEMON=$DSM_INSTALL_DIR/dsm-server
DAEMON_ARGS="--config $DSM_CONFIG_DIR/dsm.env"
PIDFILE=/var/run/\$NAME.pid
SCRIPTNAME=/etc/init.d/\$NAME

# Read configuration if it exists
[ -r /etc/default/\$NAME ] && . /etc/default/\$NAME

# Load the VERBOSE setting and other rcS variables
. /lib/init/vars.sh

# Define LSB log_* functions.
. /lib/lsb/init-functions

# Function that starts the daemon/service
do_start() {
    start-stop-daemon --start --quiet --pidfile \$PIDFILE --exec \$DAEMON --test > /dev/null || return 1
    start-stop-daemon --start --quiet --pidfile \$PIDFILE --exec \$DAEMON -- \$DAEMON_ARGS || return 2
}

# Function that stops the daemon/service
do_stop() {
    start-stop-daemon --stop --quiet --retry=TERM/30/KILL/5 --pidfile \$PIDFILE --name \$NAME
    RETVAL="\$?"
    [ "\$RETVAL" = 2 ] && return 2
    start-stop-daemon --stop --quiet --oknodo --retry=0/30/KILL/5 --exec \$DAEMON
    [ "\$?" = 2 ] && return 2
    rm -f \$PIDFILE
    return "\$RETVAL"
}

case "\$1" in
  start)
    log_daemon_msg "Starting \$DESC" "\$NAME"
    do_start
    case "\$?" in
        0|1) log_end_msg 0 ;;
        2) log_end_msg 1 ;;
    esac
    ;;
  stop)
    log_daemon_msg "Stopping \$DESC" "\$NAME"
    do_stop
    case "\$?" in
        0|1) log_end_msg 0 ;;
        2) log_end_msg 1 ;;
    esac
    ;;
  restart|force-reload)
    log_daemon_msg "Restarting \$DESC" "\$NAME"
    do_stop
    case "\$?" in
      0|1)
        do_start
        case "\$?" in
            0) log_end_msg 0 ;;
            1) log_end_msg 1 ;; # Old process is still running
            *) log_end_msg 1 ;; # Failed to start
        esac
        ;;
      *)
        # Failed to stop
        log_end_msg 1
        ;;
    esac
    ;;
  status)
      status_of_proc "\$DAEMON" "\$NAME" && exit 0 || exit \$?
      ;;
  *)
    echo "Usage: \$SCRIPTNAME {start|stop|restart|force-reload|status}" >&2
    exit 3
    ;;
esac

exit 0
EOL

        sudo mv dsm /etc/init.d/
        sudo chmod +x /etc/init.d/dsm
        sudo update-rc.d dsm defaults
        sudo service dsm start
        ;;
        
    launchd)
        echo "Installing launchd service..."
        cat > com.dsm.service.plist << EOL
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.dsm.service</string>
    <key>ProgramArguments</key>
    <array>
        <string>$DSM_INSTALL_DIR/dsm-server</string>
        <string>--config</string>
        <string>$DSM_CONFIG_DIR/dsm.env</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>/var/log/dsm.log</string>
    <key>StandardOutPath</key>
    <string>/var/log/dsm.log</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>DSM_CONFIG_FILE</key>
        <string>$DSM_CONFIG_DIR/dsm.env</string>
    </dict>
</dict>
</plist>
EOL

        sudo mv com.dsm.service.plist /Library/LaunchDaemons/
        sudo launchctl load /Library/LaunchDaemons/com.dsm.service.plist
        ;;
        
    windows)
        echo "Installing Windows service..."
        # For Windows, we use NSSM (Non-Sucking Service Manager)
        if ! command -v nssm &> /dev/null; then
            echo "NSSM not found. Please install NSSM and try again."
            exit 1
        fi
        
        nssm install DSM "$DSM_INSTALL_DIR/dsm-server" "--config $DSM_CONFIG_DIR/dsm.env"
        nssm set DSM DisplayName "Decentralized State Machine"
        nssm set DSM Description "Decentralized State Machine Service"
        nssm set DSM AppEnvironmentExtra "DSM_CONFIG_FILE=$DSM_CONFIG_DIR/dsm.env"
        nssm start DSM
        ;;
esac

echo "DSM service installed and started!"
echo "API endpoint: http://localhost:$DSM_PORT"
echo "Configuration file: $DSM_CONFIG_DIR/dsm.env"
echo "Data directory: $DSM_DATA_DIR"

# Create client library configuration
mkdir -p client_config
cat > client_config/dsm_client_config.json << EOL
{
  "backend_url": "http://localhost:$DSM_PORT",
  "api_version": "v1"
}
EOL

echo "Client configuration generated at client_config/dsm_client_config.json"
echo ""
echo "To use this configuration in your applications, copy this file to your project."
echo ""
echo "Installation complete!"