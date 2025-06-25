#!/usr/bin/env python3
"""
Network Mapping Tool - Simple Version
Simplified network mapper for easy import and use
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
import configparser

class SimpleNetworkMapper:
    def __init__(self, config_file="config.ini"):
        self.devices = {}
        self.graph = nx.Graph()
        self.local_networks = self.get_local_networks()
        self.config = self.load_config(config_file)
        
    def load_config(self, config_file):
        """Load configuration from INI file"""
        config = configparser.ConfigParser()
        try:
            config.read(config_file)
        except:
            # Use defaults if config file not found
            pass
        return config
    
    def get_local_networks(self):
        """Get all local network ranges"""
        networks = []
        try:
            for interface in netifaces.interfaces():
                try:
                    addr_info = netifaces.ifaddresses(interface)
                    if netifaces.AF_INET in addr_info:
                        for addr in addr_info[netifaces.AF_INET]:
                            ip = addr.get('addr')
                            netmask = addr.get('netmask')
                            if ip and netmask and not ip.startswith('127.'):
                                try:
                                    network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                                    networks.append(str(network))
                                except:
                                    pass
                except Exception:
                    continue
        except:
            pass
        return networks
    
    def ping_host(self, ip):
        """Ping a single host to check if it's alive"""
        try:
            if platform.system() == "Windows":
                result = subprocess.run(['ping', '-n', '1', '-w', '1000', ip], 
                                      capture_output=True, text=True, timeout=3)
            else:
                result = subprocess.run(['ping', '-c', '1', '-W', '1', ip], 
                                      capture_output=True, text=True, timeout=3)
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
    
    def get_default_ports(self):
        """Get default ports from config or use built-in defaults"""
        try:
            ports_str = self.config.get('scan_settings', 'default_ports', fallback='21,22,23,25,53,80,110,135,139,143,443,445,548,993,995,3389,5432,5900,8080')
            return [int(p.strip()) for p in ports_str.split(',')]
        except:
            return [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 548, 993, 995, 3389, 5432, 5900, 8080]
    
    def scan_common_ports(self, ip):
        """Scan common ports on a host"""
        common_ports = self.get_default_ports()
        open_ports = []
        
        max_threads = int(self.config.get('scan_settings', 'max_threads', fallback='10'))
        timeout = int(self.config.get('scan_settings', 'scan_timeout', fallback='30'))
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
            future_to_port = {executor.submit(self.scan_port, ip, port, 1): port for port in common_ports}
            for future in concurrent.futures.as_completed(future_to_port, timeout=timeout):
                port = future_to_port[future]
                try:
                    if future.result():
                        open_ports.append(port)
                except:
                    pass
        
        return sorted(open_ports)
    
    def scan_important_ports(self, ip):
        """Scan a few important ports to identify device type"""
        important_ports = [22, 80, 443, 445, 3389]  # SSH, HTTP, HTTPS, SMB, RDP
        open_ports = []
        
        for port in important_ports:
            if self.scan_port(ip, port, timeout=0.5):
                open_ports.append(port)
        
        return sorted(open_ports)
    
    def discover_devices_simple(self, network, max_hosts=50):
        """Simple device discovery using ping"""
        devices = []
        try:
            network_obj = ipaddress.IPv4Network(network, strict=False)
            
            # For large networks, sample a subset
            hosts = list(network_obj.hosts())
            if len(hosts) > max_hosts:
                # Sample important IPs (gateway, first/last few, etc.)
                gateway_ip = self.detect_gateway()
                important_ips = []
                
                # Add gateway if in range
                if gateway_ip:
                    try:
                        if ipaddress.IPv4Address(gateway_ip) in network_obj:
                            important_ips.append(gateway_ip)
                    except:
                        pass
                
                # Add first and last 10 IPs
                important_ips.extend([str(ip) for ip in hosts[:10]])
                important_ips.extend([str(ip) for ip in hosts[-10:]])
                
                # Remove duplicates and convert to set
                hosts_to_check = list(set(important_ips))
            else:
                hosts_to_check = [str(ip) for ip in hosts]
            
            print(f"  Checking {len(hosts_to_check)} IP addresses...")
            
            # Use threading for faster scanning
            max_threads = int(self.config.get('scan_settings', 'max_threads', fallback='10'))
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
                future_to_ip = {executor.submit(self.ping_host, ip): ip for ip in hosts_to_check}
                
                for future in concurrent.futures.as_completed(future_to_ip, timeout=60):
                    ip = future_to_ip[future]
                    try:
                        if future.result():
                            devices.append(ip)
                            print(f"    Found: {ip}")
                    except:
                        pass
                        
        except Exception as e:
            print(f"    Device discovery failed: {e}")
            
        return devices
    
    def get_hostname(self, ip):
        """Get hostname for an IP address"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return "Unknown"
    
    def get_mac_address(self, ip):
        """Get MAC address for an IP (simplified - not always available)"""
        # This is a placeholder - getting MAC addresses reliably requires
        # platform-specific implementations or elevated privileges
        return "Unknown"
    
    def classify_device(self, ip, open_ports, hostname):
        """Classify device type based on available information"""
        device_type = "Unknown Device"
        
        # Check if it's likely the gateway
        gateway_ip = self.detect_gateway()
        if ip == gateway_ip:
            device_type = "Router/Gateway"
        # Classify based on open ports
        elif 80 in open_ports or 443 in open_ports:
            if 22 in open_ports or 23 in open_ports:
                device_type = "Router/Gateway"
            else:
                device_type = "Web Server"
        elif 22 in open_ports:
            device_type = "Linux/Unix Server"
        elif 3389 in open_ports:
            device_type = "Windows Computer"
        elif 445 in open_ports or 139 in open_ports:
            device_type = "Windows Computer"
        elif 548 in open_ports:
            device_type = "Mac Computer"
        elif 21 in open_ports:
            device_type = "FTP Server"
        elif 25 in open_ports:
            device_type = "Mail Server"
        elif 53 in open_ports:
            device_type = "DNS Server"
        else:
            device_type = "Host/Computer"
        
        # Check hostname for additional clues
        if hostname and hostname.lower() != "unknown":
            hostname_lower = hostname.lower()
            if any(keyword in hostname_lower for keyword in ['router', 'gateway', 'gw']):
                device_type = "Router/Gateway"
            elif any(keyword in hostname_lower for keyword in ['ap-', 'access', 'wifi', 'wireless']):
                device_type = "Access Point"
            elif any(keyword in hostname_lower for keyword in ['server', 'srv']):
                device_type = "Server"
            elif any(keyword in hostname_lower for keyword in ['phone', 'mobile', 'android', 'iphone', 'ipad']):
                device_type = "Mobile Device"
            elif any(keyword in hostname_lower for keyword in ['printer', 'print']):
                device_type = "Printer"
            elif any(keyword in hostname_lower for keyword in ['nas', 'storage']):
                device_type = "NAS/Storage"
        
        return device_type
    
    def scan_network(self, network_range=None, quick_scan=True):
        """Scan network for devices"""
        print(f"Starting network scan... (Quick: {quick_scan})")
        
        if not network_range:
            networks_to_scan = self.local_networks
        else:
            networks_to_scan = [network_range]
        
        if not networks_to_scan:
            print("No networks to scan found!")
            return
        
        for network in networks_to_scan:
            print(f"Scanning network: {network}")
            
            try:
                # Discover live devices
                live_ips = self.discover_devices_simple(network)
                print(f"  Found {len(live_ips)} live devices")
                
                # Process each device
                for ip in live_ips:
                    print(f"  Processing: {ip}")
                    
                    # Get hostname
                    hostname = self.get_hostname(ip)
                    
                    # Get MAC address (simplified)
                    mac_address = self.get_mac_address(ip)
                    
                    # Scan ports based on scan type
                    open_ports = []
                    if quick_scan:
                        # Quick scan - only scan important ports
                        open_ports = self.scan_important_ports(ip)
                    else:
                        # Full scan - scan all common ports
                        open_ports = self.scan_common_ports(ip)
                    
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
    
    def detect_gateway(self):
        """Detect the default gateway"""
        try:
            gateways = netifaces.gateways()
            if 'default' in gateways and netifaces.AF_INET in gateways['default']:
                default_gateway = gateways['default'][netifaces.AF_INET][0]
                return default_gateway
        except:
            pass
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
            device_type = device_info['device_type']
            
            if ip == gateway_ip or 'Router' in device_type or 'Gateway' in device_type:
                color = self.config.get('visualization', 'router_color', fallback='red')
                size = int(self.config.get('visualization', 'router_size', fallback='2000'))
            elif 'Access Point' in device_type:
                color = self.config.get('visualization', 'access_point_color', fallback='orange')
                size = int(self.config.get('visualization', 'access_point_size', fallback='1500'))
            elif 'Server' in device_type:
                color = self.config.get('visualization', 'server_color', fallback='blue')
                size = int(self.config.get('visualization', 'server_size', fallback='1200'))
            elif 'Computer' in device_type:
                color = self.config.get('visualization', 'computer_color', fallback='green')
                size = int(self.config.get('visualization', 'computer_size', fallback='800'))
            elif 'Mobile' in device_type:
                color = 'purple'
                size = 600
            else:
                color = self.config.get('visualization', 'default_color', fallback='lightblue')
                size = int(self.config.get('visualization', 'default_size', fallback='600'))
            
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
            # If no gateway detected, create a simple mesh between first few devices
            device_ips = list(self.devices.keys())
            if len(device_ips) > 1:
                # Connect all to the first device (assume it's important)
                main_device = device_ips[0]
                for ip in device_ips[1:]:
                    self.graph.add_edge(main_device, ip)
    
    def visualize_network(self, save_file=None):
        """Create visual representation of the network"""
        if not self.graph.nodes():
            print("No devices found to visualize!")
            return
        
        print("Creating network visualization...")
        
        try:
            # Create figure
            width = int(self.config.get('visualization', 'figure_width', fallback='15'))
            height = int(self.config.get('visualization', 'figure_height', fallback='10'))
            plt.figure(figsize=(width, height))
            
            # Use spring layout for better visualization
            if len(self.graph.nodes()) == 1:
                # Single node - center it
                pos = {list(self.graph.nodes())[0]: (0, 0)}
            else:
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
            
            if self.graph.edges():
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
                plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='lightblue', markersize=6, label='Other Device')
            ]
            
            plt.legend(handles=legend_elements, loc='upper right')
            plt.title("Network Topology Map", fontsize=16, fontweight='bold')
            plt.axis('off')
            
            # Save or show
            if save_file:
                plt.savefig(save_file, dpi=300, bbox_inches='tight')
                print(f"Network map saved to: {save_file}")
                plt.close()
            else:
                plt.tight_layout()
                plt.show()
                
        except Exception as e:
            print(f"Error creating visualization: {e}")
            print("Make sure matplotlib is properly installed")
    
    def export_data(self, filename="network_data.json"):
        """Export discovered network data to JSON"""
        try:
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
        except Exception as e:
            print(f"Failed to export data: {e}")
    
    def print_device_summary(self):
        """Print summary of discovered devices"""
        print("\n" + "="*60)
        print("NETWORK MAPPING RESULTS")
        print("="*60)
        print(f"Total devices found: {len(self.devices)}")
        if self.local_networks:
            print(f"Networks scanned: {', '.join(self.local_networks)}")
        gateway = self.detect_gateway()
        if gateway:
            print(f"Gateway: {gateway}")
        print("-"*60)
        
        if not self.devices:
            print("No devices found!")
            return
        
        # Group devices by type
        device_types = defaultdict(list)
        for ip, info in self.devices.items():
            device_types[info['device_type']].append((ip, info))
        
        for device_type, devices in device_types.items():
            print(f"\n{device_type.upper()}:")
            for ip, info in devices:
                ports_str = str(info['open_ports']) if info['open_ports'] else "No ports"
                print(f"  {ip:15} | {info['hostname']:20} | Ports: {ports_str}")
        
        print("\n" + "="*60)

def main():
    """Main function for simple_main.py"""
    print("Simple Network Mapping Tool")
    print("=" * 50)
    
    # Create network mapper
    mapper = SimpleNetworkMapper()
    
    if not mapper.local_networks:
        print("No local networks detected!")
        print("Make sure you're connected to a network.")
        return
    
    # Show detected networks
    print("Detected networks:")
    for network in mapper.local_networks:
        print(f"  - {network}")
    
    # Scan network
    print("\nStarting network scan...")
    mapper.scan_network(quick_scan=True)
    
    if not mapper.devices:
        print("\nNo devices found!")
        print("This could be due to:")
        print("- Network security settings blocking ping")
        print("- Devices not responding to ICMP")
        print("- Firewall blocking network scanning")
        return
    
    # Print summary
    mapper.print_device_summary()
    
    # Build graph and export data
    mapper.build_network_graph()
    mapper.export_data()
    
    print("\nScan completed! Use gui.py or interactive.py for more features.")

if __name__ == "__main__":
    main()
