#!/usr/bin/env python3
"""
Network Mapping Tool - Interactive Command Line Version
Provides an interactive menu-driven interface without requiring GUI
"""

import sys
import os
from simple_main import SimpleNetworkMapper

class InteractiveNetworkMapper:
    def __init__(self):
        self.mapper = SimpleNetworkMapper()
        self.scanned = False
        
    def show_menu(self):
        """Display the main menu"""
        print("\n" + "="*50)
        print("Network Mapping Tool - Interactive Menu")
        print("="*50)
        print("1. Show detected networks")
        print("2. Start network scan")
        print("3. View scan results")
        print("4. Generate network map")
        print("5. Export data to JSON")
        print("6. Run quick demo")
        print("7. Help")
        print("8. Exit")
        print("-"*50)
        
    def show_networks(self):
        """Show detected local networks"""
        print("\nDetected Local Networks:")
        print("-"*30)
        if self.mapper.local_networks:
            for i, network in enumerate(self.mapper.local_networks, 1):
                print(f"{i}. {network}")
        else:
            print("No local networks detected")
        
        gateway = self.mapper.detect_gateway()
        if gateway:
            print(f"\nDefault Gateway: {gateway}")
        else:
            print("\nNo default gateway detected")
    
    def start_scan(self):
        """Start network scanning"""
        print("\nNetwork Scan Options:")
        print("1. Quick scan (ping only)")
        print("2. Full scan (with port scanning)")
        print("3. Custom network range")
        
        choice = input("\nSelect scan type (1-3): ").strip()
        
        if choice == "1":
            quick_scan = True
            network_range = None
            print("\nStarting quick network scan...")
        elif choice == "2":
            quick_scan = False
            network_range = None
            print("\nStarting full network scan (this may take longer)...")
        elif choice == "3":
            network_range = input("Enter network range (e.g., 192.168.1.0/24): ").strip()
            scan_type = input("Quick scan? (y/n): ").lower().strip()
            quick_scan = scan_type in ['y', 'yes']
            print(f"\nStarting scan of {network_range}...")
        else:
            print("Invalid choice")
            return
        
        try:
            self.mapper.scan_network(network_range, quick_scan)
            self.scanned = True
            
            device_count = len(self.mapper.devices)
            print(f"\nScan completed! Found {device_count} device(s)")
            
            if device_count > 0:
                print("Use option 3 to view detailed results")
            
        except KeyboardInterrupt:
            print("\nScan interrupted by user")
        except Exception as e:
            print(f"\nScan failed: {e}")
    
    def show_results(self):
        """Display scan results"""
        if not self.scanned or not self.mapper.devices:
            print("\nNo scan data available. Please run a scan first (option 2)")
            return
        
        print(f"\n{'='*70}")
        print("SCAN RESULTS")
        print(f"{'='*70}")
        print(f"Total devices found: {len(self.mapper.devices)}")
        print(f"Networks scanned: {', '.join(self.mapper.local_networks)}")
        
        gateway = self.mapper.detect_gateway()
        if gateway:
            print(f"Gateway: {gateway}")
        
        print(f"{'-'*70}")
        
        for ip, info in self.mapper.devices.items():
            print(f"\nIP Address: {ip}")
            print(f"  Hostname: {info['hostname']}")
            print(f"  Device Type: {info['device_type']}")
            if info['open_ports']:
                ports_str = ', '.join(map(str, info['open_ports'][:10]))
                if len(info['open_ports']) > 10:
                    ports_str += f" (and {len(info['open_ports']) - 10} more)"
                print(f"  Open Ports: {ports_str}")
            else:
                print("  Open Ports: None detected")
            if info['mac_address'] and info['mac_address'] != 'Unknown':
                print(f"  MAC Address: {info['mac_address']}")
        
        print(f"\n{'='*70}")
    
    def generate_map(self):
        """Generate network visualization"""
        if not self.scanned or not self.mapper.devices:
            print("\nNo scan data available. Please run a scan first (option 2)")
            return
        
        print("\nGenerating network map...")
        
        filename = input("Enter filename (or press Enter for 'network_map.png'): ").strip()
        if not filename:
            filename = "network_map.png"
        
        if not filename.endswith('.png'):
            filename += '.png'
        
        try:
            self.mapper.build_network_graph()
            self.mapper.visualize_network(save_file=filename)
            print(f"Network map saved as: {filename}")
        except Exception as e:
            print(f"Failed to generate map: {e}")
            print("Make sure matplotlib is installed: pip install matplotlib")
    
    def export_data(self):
        """Export scan data to JSON"""
        if not self.scanned or not self.mapper.devices:
            print("\nNo scan data available. Please run a scan first (option 2)")
            return
        
        filename = input("Enter filename (or press Enter for 'network_data.json'): ").strip()
        if not filename:
            filename = "network_data.json"
        
        if not filename.endswith('.json'):
            filename += '.json'
        
        try:
            self.mapper.export_data(filename)
            print(f"Network data exported to: {filename}")
        except Exception as e:
            print(f"Failed to export data: {e}")
    
    def run_demo(self):
        """Run a quick demonstration"""
        print("\nRunning quick network demo...")
        print("This will perform a quick scan and show basic information")
        
        try:
            self.mapper.scan_network(quick_scan=True)
            self.scanned = True
            
            device_count = len(self.mapper.devices)
            print(f"\nDemo scan completed! Found {device_count} device(s)")
            
            if device_count > 0:
                print("\nTop 3 devices found:")
                for i, (ip, info) in enumerate(list(self.mapper.devices.items())[:3], 1):
                    print(f"{i}. {ip} ({info['device_type']}) - {info['hostname']}")
                
                if device_count > 3:
                    print(f"... and {device_count - 3} more devices")
                
                # Ask if user wants to see full results
                show_all = input("\nShow all results? (y/n): ").lower().strip()
                if show_all in ['y', 'yes']:
                    self.show_results()
            
        except Exception as e:
            print(f"Demo failed: {e}")
    
    def show_help(self):
        """Show help information"""
        print("\n" + "="*50)
        print("HELP - Network Mapping Tool")
        print("="*50)
        print("This tool scans your local network to discover devices")
        print("and creates a visual map of the network topology.")
        print()
        print("Menu Options:")
        print("1. Show networks - Display detected local networks")
        print("2. Start scan - Begin scanning for network devices")
        print("3. View results - Show detailed scan results")
        print("4. Generate map - Create visual network map (PNG)")
        print("5. Export data - Save scan data to JSON file")
        print("6. Quick demo - Run a fast demonstration scan")
        print("7. Help - Show this help information")  
        print("8. Exit - Quit the program")
        print()
        print("Tips:")
        print("- Quick scan only pings devices (faster)")
        print("- Full scan also checks for open ports (slower)")
        print("- Some devices might not respond to ping")
        print("- Run with sudo for better results on some systems")
        print("="*50)
    
    def run(self):
        """Main interactive loop"""
        print("Welcome to the Network Mapping Tool!")
        print("This interactive version doesn't require a GUI")
        
        while True:
            self.show_menu()
            choice = input("Select an option (1-8): ").strip()
            
            if choice == "1":
                self.show_networks()
            elif choice == "2":
                self.start_scan()
            elif choice == "3":
                self.show_results()
            elif choice == "4":
                self.generate_map()
            elif choice == "5":
                self.export_data()
            elif choice == "6":
                self.run_demo()
            elif choice == "7":
                self.show_help()
            elif choice == "8":
                print("\nGoodbye!")
                break
            else:
                print("\nInvalid choice. Please select 1-8.")
            
            # Wait for user to continue
            if choice in ["1", "2", "3", "4", "5", "6", "7"]:
                input("\nPress Enter to continue...")

def main():
    try:
        app = InteractiveNetworkMapper()
        app.run()
    except KeyboardInterrupt:
        print("\n\nProgram interrupted by user. Goodbye!")
    except Exception as e:
        print(f"\nError: {e}")
        print("Please check that all dependencies are installed")

if __name__ == "__main__":
    main()
