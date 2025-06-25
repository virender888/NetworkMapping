#!/usr/bin/env python3
"""
Network Mapping Tool
Discovers devices on the local network and creates a visual graph representation
Uses ping and basic socket scanning instead of nmap
"""

import networkx as nx
import matplotlib.pyplot as plt
import netifaces
import ipaddress
import socket
import threading
import time
from collections import defaultdict
import json
import os
import subprocess
import concurrent.futures
import platform

class NetworkMapper:
    def __init__(self):
        self.devices = {}
        self.graph = nx.Graph()
        self.local_networks = self.get_local_networks()
        
    def get_local_networks(self):
        """Get all local network ranges"""
        networks = []
        for interface in netifaces.interfaces():
            try:
                addr_info = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addr_info:
                    for addr in addr_info[netifaces.AF_INET]:
                        ip = addr.get('addr')
                        netmask = addr.get('netmask')
                        if ip and netmask and not ip.startswith('127.'):
                            network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                            networks.append(str(network))
            except Exception as e:
                continue
        return networks
    
    def ping_host(self, ip, timeout=2):
        """Ping a single host to check if it's alive with longer timeout"""
        try:
            if platform.system() == "Windows":
                result = subprocess.run(['ping', '-n', '1', '-w', '2000', ip], 
                                      capture_output=True, text=True, timeout=5)
            else:
                result = subprocess.run(['ping', '-c', '1', '-W', '2', ip], 
                                      capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except:
            return False
    
    def scan_port(self, ip, port, timeout=1):
        """Scan a single port on a host"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((ip, port))
                return result == 0
        except:
            return False
    
    def scan_common_ports(self, ip):
        """Scan common ports on a host"""
        common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 548, 993, 995, 3389, 5432, 5900, 8080]
        open_ports = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            future_to_port = {executor.submit(self.scan_port, ip, port): port for port in common_ports}
            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    if future.result():
                        open_ports.append(port)
                except:
                    pass
        
        return open_ports
    
    def scan_important_ports(self, ip):
        """Scan a few important ports to identify device type"""
        important_ports = [22, 80, 443, 445, 3389]  # SSH, HTTP, HTTPS, SMB, RDP
        open_ports = []
        
        for port in important_ports:
            if self.scan_port(ip, port, timeout=0.5):
                open_ports.append(port)
        
        return open_ports
    
    def get_arp_table(self):
        """Get devices from ARP table"""
        devices = []
        try:
            if platform.system() == "Windows":
                result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=10)
            else:
                result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if line.strip():
                        # Parse ARP entries to extract IP addresses
                        parts = line.split()
                        for part in parts:
                            if self.is_valid_ip(part.strip('()')):
                                ip = part.strip('()')
                                if not ip.startswith('224.') and not ip.startswith('239.'):  # Skip multicast
                                    devices.append(ip)
        except Exception as e:
            print(f"    ARP table scan failed: {e}")
        
        return list(set(devices))  # Remove duplicates
    
    def is_valid_ip(self, ip_str):
        """Check if string is a valid IP address"""
        try:
            ipaddress.IPv4Address(ip_str)
            return True
        except:
            return False
    
    def discover_devices_comprehensive(self, network, max_hosts=254):
        """Comprehensive device discovery using multiple methods"""
        all_devices = set()
        
        try:
            network_obj = ipaddress.IPv4Network(network, strict=False)
            
            # Method 1: ARP table scan (fastest)
            print(f"  Scanning ARP table...")
            arp_devices = self.get_arp_table()
            for ip in arp_devices:
                try:
                    if ipaddress.IPv4Address(ip) in network_obj:
                        all_devices.add(ip)
                        print(f"    Found in ARP: {ip}")
                except:
                    pass
            
            # Method 2: Comprehensive ping scan
            hosts = list(network_obj.hosts())
            
            # For very large networks, intelligently sample IPs
            if len(hosts) > max_hosts:
                print(f"  Large network detected ({len(hosts)} hosts). Using intelligent sampling...")
                
                # Always include gateway
                gateway_ip = self.detect_gateway()
                important_ips = set()
                
                if gateway_ip:
                    try:
                        if ipaddress.IPv4Address(gateway_ip) in network_obj:
                            important_ips.add(gateway_ip)
                    except:
                        pass
                
                # Add commonly used IP ranges
                base_ip = str(network_obj.network_address)
                base_parts = base_ip.split('.')
                base_net = '.'.join(base_parts[:3])
                
                # Common IPs: .1, .2, .10, .100, .254, etc.
                common_last_octets = [1, 2, 3, 4, 5, 10, 11, 12, 20, 25, 50, 100, 101, 102, 200, 254]
                for octet in common_last_octets:
                    test_ip = f"{base_net}.{octet}"
                    try:
                        if ipaddress.IPv4Address(test_ip) in network_obj:
                            important_ips.add(test_ip)
                    except:
                        pass
                
                # Add first 20 and last 20 IPs
                important_ips.update([str(ip) for ip in hosts[:20]])
                important_ips.update([str(ip) for ip in hosts[-20:]])
                
                # Add every 10th IP from the middle range
                middle_start = len(hosts) // 4
                middle_end = 3 * len(hosts) // 4
                for i in range(middle_start, middle_end, 10):
                    important_ips.add(str(hosts[i]))
                
                hosts_to_check = list(important_ips)
            else:
                hosts_to_check = [str(ip) for ip in hosts]
            
            print(f"  Ping scanning {len(hosts_to_check)} IP addresses...")
            
            # Use more threads for faster scanning
            with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
                future_to_ip = {executor.submit(self.ping_host, ip): ip for ip in hosts_to_check}
                
                for future in concurrent.futures.as_completed(future_to_ip, timeout=60):
                    ip = future_to_ip[future]
                    try:
                        if future.result():
                            all_devices.add(ip)
                            print(f"    Found via ping: {ip}")
                    except:
                        pass
            
            # Method 3: Port scanning on common gateway/server IPs (for devices that don't respond to ping)
            print(f"  Port scanning potential devices...")
            potential_servers = []
            base_net = '.'.join(str(network_obj.network_address).split('.')[:3])
            server_ips = [f"{base_net}.{i}" for i in [1, 2, 10, 50, 100, 200]]
            
            for ip in server_ips:
                try:
                    if ipaddress.IPv4Address(ip) in network_obj and ip not in all_devices:
                        # Try common ports
                        if self.scan_port(ip, 80, 0.5) or self.scan_port(ip, 443, 0.5) or self.scan_port(ip, 22, 0.5):
                            all_devices.add(ip)
                            print(f"    Found via port scan: {ip}")
                except:
                    pass
                        
        except Exception as e:
            print(f"    Device discovery failed: {e}")
            
        return list(all_devices)
    
    def get_hostname(self, ip):
        """Get hostname for an IP address"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return "Unknown"
    
    def classify_device(self, ip, open_ports, hostname):
        """Classify device type based on available information"""
        device_type = "Unknown Device"
        
        # Check if it's likely the gateway
        gateway_ip = self.detect_gateway()
        if ip == gateway_ip:
            device_type = "Router/Gateway"
        # Classify based on open ports
        elif 80 in open_ports and 443 in open_ports:
            if 22 in open_ports:
                device_type = "Linux Router/Server"
            else:
                device_type = "Web Server/Router"
        elif 80 in open_ports or 443 in open_ports:
            device_type = "Web Server/Device"
        elif 22 in open_ports:
            device_type = "Linux/Unix Server"
        elif 3389 in open_ports:
            device_type = "Windows Computer"
        elif 445 in open_ports:
            device_type = "Windows Computer"
        elif 21 in open_ports:
            device_type = "FTP Server"
        elif 23 in open_ports:
            device_type = "Telnet Device"
        elif 53 in open_ports:
            device_type = "DNS Server"
        elif 135 in open_ports or 139 in open_ports:
            device_type = "Windows Computer"
        elif 548 in open_ports:
            device_type = "Mac Computer"
        elif 5900 in open_ports:
            device_type = "VNC Server"
        elif 8080 in open_ports:
            device_type = "Web Server (Alt Port)"
        else:
            # If no ports are open, it might be a client device
            device_type = "Client Device"
        
        # Check hostname for additional clues
        if hostname.lower() != "unknown":
            hostname_lower = hostname.lower()
            if any(keyword in hostname_lower for keyword in ['router', 'gateway', 'gw', 'rt-']):
                device_type = "Router/Gateway"
            elif any(keyword in hostname_lower for keyword in ['ap-', 'access', 'wifi', 'wireless']):
                device_type = "Access Point"
            elif any(keyword in hostname_lower for keyword in ['server', 'srv', 'nas']):
                device_type = "Server"
            elif any(keyword in hostname_lower for keyword in ['phone', 'mobile', 'android', 'iphone']):
                device_type = "Mobile Device"
            elif any(keyword in hostname_lower for keyword in ['laptop', 'desktop', 'pc', 'computer']):
                device_type = "Computer"
            elif any(keyword in hostname_lower for keyword in ['printer', 'print']):
                device_type = "Printer"
            elif any(keyword in hostname_lower for keyword in ['camera', 'cam', 'security']):
                device_type = "Security Camera"
            elif any(keyword in hostname_lower for keyword in ['tv', 'smart', 'media']):
                device_type = "Smart TV/Media Device"
            elif any(keyword in hostname_lower for keyword in ['iot', 'sensor', 'thermostat']):
                device_type = "IoT Device"
        
        return device_type
    
    def scan_network(self, network_range=None, quick_scan=True):
        """Scan network for devices with improved discovery"""
        print(f"Starting comprehensive network scan...")
        
        if not network_range:
            networks_to_scan = self.local_networks
        else:
            networks_to_scan = [network_range]
        
        for network in networks_to_scan:
            print(f"Scanning network: {network}")
            
            try:
                # Use comprehensive device discovery
                live_ips = self.discover_devices_comprehensive(network)
                print(f"  Found {len(live_ips)} live devices")
                
                # Process each device
                for ip in live_ips:
                    print(f"  Processing: {ip}")
                    
                    # Get hostname
                    hostname = self.get_hostname(ip)
                    
                    # Scan ports based on scan type
                    open_ports = []
                    if quick_scan:
                        # Quick scan - only scan important ports
                        open_ports = self.scan_important_ports(ip)
                    else:
                        # Full scan - scan all common ports
                        open_ports = self.scan_common_ports(ip)
                    
                    # Get MAC address if possible
                    mac_address = self.get_mac_address(ip)
                    
                    # Classify device
                    device_type = self.classify_device(ip, open_ports, hostname)
                    
                    # Store device information
                    self.devices[ip] = {
                        'hostname': hostname,
                        'device_type': device_type,
                        'open_ports': open_ports,
                        'mac_address': mac_address,
                        'network': network
                    }
                    
            except Exception as e:
                print(f"Error scanning network {network}: {e}")
    
    def get_mac_address(self, ip):
        """Try to get MAC address for an IP"""
        try:
            # First ping to ensure ARP entry exists
            self.ping_host(ip)
            
            if platform.system() == "Windows":
                result = subprocess.run(['arp', '-a', ip], capture_output=True, text=True, timeout=5)
            else:
                result = subprocess.run(['arp', '-n', ip], capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if ip in line:
                        # Extract MAC address (looks for pattern like xx:xx:xx:xx:xx:xx or xx-xx-xx-xx-xx-xx)
                        parts = line.split()
                        for part in parts:
                            if ':' in part and len(part) == 17:  # MAC format xx:xx:xx:xx:xx:xx
                                return part
                            elif '-' in part and len(part) == 17:  # MAC format xx-xx-xx-xx-xx-xx
                                return part.replace('-', ':')
        except:
            pass
        return 'Unknown'
    
    def detect_gateway(self):
        """Detect the default gateway"""
        try:
            gateways = netifaces.gateways()
            default_gateway = gateways['default'][netifaces.AF_INET][0]
            return default_gateway
        except:
            return None
    
    def build_network_graph(self):
        """Build network graph with connections"""
        print("Building network graph...")
        
        # Clear existing graph
        self.graph.clear()
        
        # Get gateway
        gateway_ip = self.detect_gateway()
        
        # Add all devices as nodes
        for ip, device_info in self.devices.items():
            node_label = f"{device_info['hostname']}\n({ip})\n{device_info['device_type']}"
            
            # Determine node color and size based on device type
            device_type = device_info['device_type'].lower()
            
            if ip == gateway_ip or 'router' in device_type or 'gateway' in device_type:
                color = 'red'
                size = 2000
            elif 'access point' in device_type or 'wifi' in device_type:
                color = 'orange'
                size = 1500
            elif 'server' in device_type:
                color = 'blue'
                size = 1200
            elif 'computer' in device_type or 'windows' in device_type or 'linux' in device_type or 'mac' in device_type:
                color = 'green'
                size = 1000
            elif 'mobile' in device_type or 'phone' in device_type:
                color = 'purple'
                size = 600
            elif 'printer' in device_type:
                color = 'brown'
                size = 800
            elif 'camera' in device_type or 'security' in device_type:
                color = 'darkred'
                size = 700
            elif 'tv' in device_type or 'media' in device_type:
                color = 'darkgreen'
                size = 900
            elif 'iot' in device_type or 'sensor' in device_type:
                color = 'pink'
                size = 500
            elif 'client' in device_type:
                color = 'lightgreen'
                size = 700
            else:
                color = 'lightblue'
                size = 600
            
            self.graph.add_node(ip, 
                              label=node_label,
                              color=color,
                              size=size,
                              device_type=device_info['device_type'])
        
        # Add connections (star topology - all devices connect through gateway)
        if gateway_ip and gateway_ip in self.devices:
            for ip in self.devices:
                if ip != gateway_ip:
                    self.graph.add_edge(gateway_ip, ip)
        else:
            # If no gateway detected, create a mesh between devices
            device_ips = list(self.devices.keys())
            for i, ip1 in enumerate(device_ips):
                for ip2 in device_ips[i+1:]:
                    self.graph.add_edge(ip1, ip2)
    
    def visualize_network(self, save_file=None):
        """Create visual representation of the network"""
        if not self.graph.nodes():
            print("No devices found to visualize!")
            return
        
        print("Creating network visualization...")
        
        # Create figure
        plt.figure(figsize=(15, 10))
        
        # Use spring layout for better visualization
        pos = nx.spring_layout(self.graph, k=3, iterations=50)
        
        # Prepare node attributes
        node_colors = [self.graph.nodes[node].get('color', 'lightblue') for node in self.graph.nodes()]
        node_sizes = [self.graph.nodes[node].get('size', 800) for node in self.graph.nodes()]
        node_labels = {node: self.graph.nodes[node].get('label', node) for node in self.graph.nodes()}
        
        # Draw the network
        nx.draw_networkx_nodes(self.graph, pos, 
                              node_color=node_colors, 
                              node_size=node_sizes,
                              alpha=0.8)
        
        nx.draw_networkx_edges(self.graph, pos, 
                              edge_color='gray', 
                              width=2,
                              alpha=0.6)
        
        nx.draw_networkx_labels(self.graph, pos, 
                               labels=node_labels,
                               font_size=8,
                               font_weight='bold')
        
        # Add legend
        legend_elements = [
            plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='red', markersize=12, label='Router/Gateway'),
            plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='orange', markersize=10, label='Access Point'),
            plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='blue', markersize=10, label='Server'),
            plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='green', markersize=8, label='Computer'),
            plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='purple', markersize=6, label='Mobile Device'),
            plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='brown', markersize=8, label='Printer'),
            plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='darkred', markersize=7, label='Security Camera'),
            plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='darkgreen', markersize=8, label='Smart TV/Media'),
            plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='pink', markersize=5, label='IoT Device'),
            plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='lightgreen', markersize=7, label='Client Device'),
            plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='lightblue', markersize=6, label='Other Device')
        ]
        
        plt.legend(handles=legend_elements, loc='upper right')
        plt.title("Network Topology Map", fontsize=16, fontweight='bold')
        plt.axis('off')
        
        # Save or show
        if save_file:
            plt.savefig(save_file, dpi=300, bbox_inches='tight')
            print(f"Network map saved to: {save_file}")
        else:
            plt.tight_layout()
            plt.show()
    
    def export_data(self, filename="network_data.json"):
        """Export discovered network data to JSON"""
        export_data = {
            'scan_time': time.ctime(),
            'networks_scanned': self.local_networks,
            'devices': self.devices,
            'total_devices': len(self.devices),
            'gateway': self.detect_gateway()
        }
        
        with open(filename, 'w') as f:
            json.dump(export_data, f, indent=2)
        
        print(f"Network data exported to: {filename}")
    
    def print_device_summary(self):
        """Print summary of discovered devices"""
        print("\n" + "="*60)
        print("NETWORK MAPPING RESULTS")
        print("="*60)
        print(f"Total devices found: {len(self.devices)}")
        print(f"Networks scanned: {', '.join(self.local_networks)}")
        print(f"Gateway: {self.detect_gateway()}")
        print("-"*60)
        
        # Group devices by type
        device_types = defaultdict(list)
        for ip, info in self.devices.items():
            device_types[info['device_type']].append((ip, info))
        
        for device_type, devices in device_types.items():
            print(f"\n{device_type.upper()}:")
            for ip, info in devices:
                ports_str = str(info['open_ports']) if info['open_ports'] else "No scan"
                mac_str = info.get('mac_address', 'Unknown')
                print(f"  {ip:15} | {info['hostname']:20} | MAC: {mac_str:17} | Ports: {ports_str}")
        
        print("\n" + "="*60)

def main():
    """Main function"""
    print("Enhanced Network Mapping Tool")
    print("=" * 50)
    
    # Create network mapper
    mapper = NetworkMapper()
    
    if not mapper.local_networks:
        print("No local networks detected!")
        return
    
    print(f"Detected networks: {', '.join(mapper.local_networks)}")
    
    # Scan network
    print("\nStarting comprehensive device discovery...")
    print("This scan uses multiple detection methods:")
    print("- ARP table scanning (fastest)")
    print("- ICMP ping scanning (comprehensive)")
    print("- Port scanning (for stealth devices)")
    print("Note: This may take a few minutes...")
    
    start_time = time.time()
    mapper.scan_network(quick_scan=True)  # Use quick scan by default for better performance
    scan_time = time.time() - start_time
    
    if not mapper.devices:
        print("\nNo devices found!")
        print("This could be due to:")
        print("- Network security settings blocking ping/scanning")
        print("- Devices configured to not respond to ICMP")
        print("- Firewall blocking network discovery")
        print("- All devices are in stealth mode")
        print("\nTry running with administrator/root privileges for better results.")
        return
    
    print(f"\nScan completed in {scan_time:.1f} seconds")
    
    # Print summary
    mapper.print_device_summary()
    
    # Build graph
    mapper.build_network_graph()
    
    # Export data
    mapper.export_data()
    
    # Visualize network
    print("\nGenerating network visualization...")
    mapper.visualize_network(save_file="network_map.png")
    
    print("\nNetwork mapping completed!")
    print("Files generated:")
    print("- network_map.png (Network visualization)")
    print("- network_data.json (Raw scan data)")
    print(f"\nTotal devices discovered: {len(mapper.devices)}")
    
    # Provide recommendations
    if len(mapper.devices) > 1:
        print("\n✅ Network scan successful! Multiple devices detected.")
    else:
        print("\n⚠️  Only one device detected. Consider:")
        print("   - Running with elevated privileges")
        print("   - Checking if devices are configured to respond to network discovery")
        print("   - Ensuring you're connected to the network you want to scan")

if __name__ == "__main__":
    main()