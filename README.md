# Network Mapping Tool

A Python-based network mapping tool that discovers devices on your local network and creates visual network topology graphs using built-in Python libraries and basic network scanning techniques.

## Features

- **Device Discovery**: Automatically scans your local network to find all connected devices using ping
- **Device Classification**: Identifies device types (routers, computers, servers, access points, etc.)
- **Network Visualization**: Creates beautiful network topology graphs showing device connections
- **Port Scanning**: Discovers open ports on each device for device identification
- **Multiple Interfaces**: Both command-line and GUI versions available
- **Data Export**: Export scan results to JSON format
- **No Root Required**: Works without administrator privileges or external tools

## Requirements

- Python 3.6+
- Required Python packages (see requirements.txt)
- No external tools required (no nmap installation needed)

## Installation

Install Python dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Command Line Version

Run the main script to perform a complete network scan and generate visualization:

```bash
python main.py
```

This will:
- Scan your local network for devices using ping
- Display a detailed device summary
- Generate a network topology graph (`network_map.png`)
- Export raw data (`network_data.json`)

### GUI Version

For a user-friendly interface:

```bash
python gui.py
```

The GUI provides:
- Easy network scanning with progress indication
- Tabular view of discovered devices
- Interactive map generation
- Data export functionality

### Quick Test

For a quick test of basic functionality:

```bash
python simple_main.py
```

## Device Types Detected

The tool can identify various device types based on open ports and network behavior:

- **Router/Gateway**: Default gateway or devices with web interface and SSH (ports 80/443 + 22)
- **Access Point**: Devices with "ap", "access", "wifi", or "wireless" in hostname
- **Windows Computer**: Systems with SMB/RDP services (ports 445, 3389)
- **Linux/Unix Server**: Systems with SSH service (port 22)
- **Web Server**: Devices serving HTTP/HTTPS (ports 80, 443)
- **Mobile Device**: Devices with mobile-related hostnames
- **Host/Computer**: Generic network devices

## Scanning Methods

### Quick Scan (Default)
- Ping sweep to discover live hosts
- Scans important ports (22, 80, 443, 445, 3389) for device classification
- Fast execution, good for basic network mapping

### Full Scan
- Ping sweep to discover live hosts  
- Scans all common ports for detailed device identification
- More comprehensive but slower

## Network Visualization

The generated network map uses color coding:
- 🔴 **Red**: Router/Gateway (main connection point)
- 🟠 **Orange**: Access Points
- 🔵 **Blue**: Servers
- 🟢 **Green**: Computers
- 🟣 **Purple**: Mobile Devices
- 🔵 **Light Blue**: Other devices

## Output Files

### network_map.png
Visual representation of your network topology showing:
- Device connections
- Device types (color-coded)
- IP addresses and hostnames
- Network structure

### network_data.json
Raw scan data including:
- Complete device information
- Open ports for each device
- Scan timestamps
- Network ranges scanned
- Gateway information

## Configuration Options

### Scan Types

- **Quick Scan**: `mapper.scan_network(quick_scan=True)` - Fast ping + important ports
- **Full Scan**: `mapper.scan_network(quick_scan=False)` - Ping + all common ports

### Custom Network Range

You can specify a custom network range to scan:

```python
mapper.scan_network("192.168.1.0/24")
```

## Security Considerations

- This tool uses standard network protocols (ICMP ping, TCP connect)
- No privileged operations required
- Some networks may block ping (ICMP) which will limit device discovery
- Firewall rules may prevent port scanning
- Only use on networks you own or have permission to scan

## Troubleshooting

### Common Issues

1. **No devices found**:
   - Check if you're connected to a network
   - Some networks block ICMP ping - this is normal for security
   - Try the full scan mode for better port-based detection

2. **Limited device discovery**:
   - Many modern devices don't respond to ping for security
   - Corporate networks often have strict firewall rules
   - Try scanning during peak usage times when devices are more active

3. **Slow scanning**:
   - Use quick scan mode for faster results: `quick_scan=True`
   - Reduce the network range being scanned
   - Some networks have rate limiting

4. **Matplotlib display issues**:
   - Install tkinter: `pip install tk`
   - For headless systems, the tool will save files instead of displaying

## Example Output

```
NETWORK MAPPING RESULTS
============================================================
Total devices found: 3
Networks scanned: 192.168.1.0/24
Gateway: 192.168.1.1
------------------------------------------------------------

ROUTER/GATEWAY:
  192.168.1.1     | router.local         | Ports: [80, 443]

HOST/COMPUTER:
  192.168.1.100   | desktop-pc           | Ports: []
  192.168.1.101   | laptop-user          | Ports: [22]
```

## Advantages Over nmap-based Solutions

- **No Installation Required**: Works with just Python packages
- **No Root Privileges**: Runs as regular user
- **Cross-Platform**: Works on Windows, macOS, Linux without additional setup
- **Lightweight**: Minimal dependencies
- **Safe**: Uses standard network protocols only

## License

This project is open source and available under the MIT License.

## Contributing

Feel free to submit issues, feature requests, or pull requests to improve the tool.

## Usage

### Command Line Version

Run the main script to perform a complete network scan and generate visualization:

```bash
python main.py
```

This will:
- Scan your local network for devices
- Display a detailed device summary
- Generate a network topology graph (`network_map.png`)
- Export raw data (`network_data.json`)

### GUI Version

For a user-friendly interface:

```bash
python gui.py
```

The GUI provides:
- Easy network scanning with progress indication
- Tabular view of discovered devices
- Interactive map generation
- Data export functionality

## Device Types Detected

The tool can identify various device types based on open ports and network behavior:

- **Router/Gateway**: Devices with web interface and SSH/Telnet (ports 80/443 + 22/23)
- **Access Point**: Wireless access points and WiFi devices
- **Windows Computer**: Systems with SMB/RDP services (ports 445, 139, 3389)
- **Linux/Unix Server**: Systems with SSH service (port 22)
- **Mac Computer**: Systems with AFP service (port 548)
- **Web Server**: Devices serving HTTP/HTTPS (ports 80, 443, 8080)
- **FTP Server**: File transfer servers (port 21)
- **DNS Server**: Domain name servers (port 53)
- **Network Device**: SNMP-enabled devices (port 161)

## Network Visualization

The generated network map uses color coding:
- 🔴 **Red**: Router/Gateway (main connection point)
- 🟠 **Orange**: Access Points
- 🔵 **Blue**: Servers
- 🟢 **Green**: Computers
- 🔵 **Light Blue**: Other devices

## Output Files

### network_map.png
Visual representation of your network topology showing:
- Device connections
- Device types (color-coded)
- IP addresses and hostnames
- Network structure

### network_data.json
Raw scan data including:
- Complete device information
- Open ports for each device
- MAC addresses (when available)
- Scan timestamps
- Network ranges scanned

## Configuration Options

### Quick Scan vs Full Scan

- **Quick Scan** (`-sn`): Fast ping sweep to discover hosts
- **Full Scan** (`-sS -O --top-ports 1000`): Detailed port scan with OS detection

### Custom Network Range

You can specify a custom network range to scan:

```python
mapper.scan_network("192.168.1.0/24")
```

## Security Considerations

- This tool performs network scanning which may be detected by security systems
- Only use on networks you own or have permission to scan
- Some firewalls may block or detect the scanning activity
- Administrative privileges may be required for certain scan types

## Troubleshooting

### Common Issues

1. **No devices found**:
   - Check if you're connected to a network
   - Try running with administrator/root privileges
   - Verify Nmap is properly installed

2. **Permission errors**:
   - Run with `sudo` on macOS/Linux
   - Run as Administrator on Windows

3. **Matplotlib display issues**:
   - Install tkinter: `pip install tk`
   - For headless systems, the tool will save files instead of displaying

4. **Slow scanning**:
   - Use quick scan mode for faster results
   - Reduce the network range being scanned

## Example Output

```
NETWORK MAPPING RESULTS
============================================================
Total devices found: 8
Networks scanned: 192.168.1.0/24
------------------------------------------------------------

ROUTER/GATEWAY:
  192.168.1.1     | router.local         | Ports: [22, 53, 80, 443]

WINDOWS COMPUTER:
  192.168.1.100   | desktop-pc           | Ports: [135, 139, 445]
  192.168.1.101   | laptop-user          | Ports: [135, 139, 445]

ACCESS POINT:
  192.168.1.50    | ap-livingroom        | Ports: [22, 80, 443]

HOST/COMPUTER:
  192.168.1.200   | phone-android        | Ports: []
  192.168.1.201   | tablet-ipad          | Ports: []
```

## License

This project is open source and available under the MIT License.

## Contributing

Feel free to submit issues, feature requests, or pull requests to improve the tool.
