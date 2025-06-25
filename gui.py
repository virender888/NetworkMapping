#!/usr/bin/env python3
"""
Network Mapping Tool - GUI Version
Enhanced tkinter interface for the network mapper with improved scanning
"""

import sys
import threading
import os
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import time

# Try to import tkinter with fallback
try:
    import tkinter as tk
    from tkinter import ttk, messagebox, filedialog
    TKINTER_AVAILABLE = True
except ImportError:
    TKINTER_AVAILABLE = False
    print("Error: tkinter is not available in your Python installation.")
    print("Please install tkinter or use the command-line version instead:")
    print("  python3 main.py")
    sys.exit(1)

# Import the enhanced NetworkMapper
from main import NetworkMapper

class NetworkMapperGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Enhanced Network Mapping Tool")
        self.root.geometry("900x700")
        
        self.mapper = NetworkMapper()
        self.scanning = False
        
        self.create_widgets()
    
    def create_widgets(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Title
        title_label = ttk.Label(main_frame, text="Enhanced Network Mapping Tool", 
                               font=("Arial", 16, "bold"))
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))
        
        # Network info
        info_frame = ttk.Frame(main_frame)
        info_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        
        networks_text = ", ".join(self.mapper.local_networks) if self.mapper.local_networks else "None detected"
        ttk.Label(info_frame, text=f"Detected Networks: {networks_text}", 
                 font=("Arial", 10)).grid(row=0, column=0, sticky=tk.W)
        
        # Scan options
        options_frame = ttk.LabelFrame(main_frame, text="Scan Options", padding="10")
        options_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        
        ttk.Label(options_frame, text="Network Range:").grid(row=0, column=0, sticky=tk.W)
        self.network_var = tk.StringVar(value="Auto-detect")
        network_entry = ttk.Entry(options_frame, textvariable=self.network_var, width=30)
        network_entry.grid(row=0, column=1, padx=(10, 0), sticky=(tk.W, tk.E))
        
        self.quick_scan_var = tk.BooleanVar(value=True)
        quick_scan_cb = ttk.Checkbutton(options_frame, text="Quick Scan (faster, scans important ports only)", 
                                       variable=self.quick_scan_var)
        quick_scan_cb.grid(row=1, column=0, columnspan=2, sticky=tk.W, pady=(10, 0))
        
        # Scan method info
        info_text = ("Enhanced scan uses multiple methods:\n"
                    "• ARP table scanning (fastest)\n"
                    "• ICMP ping scanning (comprehensive)\n"
                    "• Port scanning (for stealth devices)")
        ttk.Label(options_frame, text=info_text, font=("Arial", 9), 
                 foreground="gray").grid(row=2, column=0, columnspan=2, sticky=tk.W, pady=(10, 0))
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=3, column=0, columnspan=3, pady=(0, 10))
        
        self.scan_button = ttk.Button(button_frame, text="Start Scan", 
                                     command=self.start_scan)
        self.scan_button.grid(row=0, column=0, padx=(0, 10))
        
        self.visualize_button = ttk.Button(button_frame, text="Generate Map", 
                                          command=self.generate_map, state="disabled")
        self.visualize_button.grid(row=0, column=1, padx=(0, 10))
        
        self.export_button = ttk.Button(button_frame, text="Export Data", 
                                       command=self.export_data, state="disabled")
        self.export_button.grid(row=0, column=2)
        
        # Progress bar
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Results area
        results_frame = ttk.LabelFrame(main_frame, text="Scan Results", padding="10")
        results_frame.grid(row=5, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        
        # Create treeview for results with more columns
        columns = ('IP', 'Hostname', 'Device Type', 'MAC Address', 'Open Ports')
        self.tree = ttk.Treeview(results_frame, columns=columns, show='headings', height=15)
        
        # Define headings and column widths
        column_widths = {'IP': 120, 'Hostname': 180, 'Device Type': 150, 'MAC Address': 140, 'Open Ports': 200}
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=column_widths[col])
        
        # Scrollbar for treeview
        scrollbar = ttk.Scrollbar(results_frame, orient='vertical', command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready to scan network")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, 
                              relief=tk.SUNKEN, anchor=tk.W)
        status_bar.grid(row=6, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(10, 0))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(5, weight=1)  # Updated row index
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)
        options_frame.columnconfigure(1, weight=1)
    
    def start_scan(self):
        if self.scanning:
            return
        
        self.scanning = True
        self.scan_button.config(state="disabled", text="Scanning...")
        self.visualize_button.config(state="disabled")
        self.export_button.config(state="disabled")
        self.progress.start()
        
        # Clear previous results
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Start scan in separate thread
        scan_thread = threading.Thread(target=self.scan_network)
        scan_thread.daemon = True
        scan_thread.start()
    
    def scan_network(self):
        try:
            self.status_var.set("Starting comprehensive device discovery...")
            
            # Get network range
            network_range = None
            if self.network_var.get() != "Auto-detect":
                network_range = self.network_var.get()
            
            # Perform scan with timing
            start_time = time.time()
            self.mapper.scan_network(network_range, self.quick_scan_var.get())
            scan_time = time.time() - start_time
            
            # Update GUI in main thread
            self.root.after(0, lambda: self.scan_completed(scan_time))
            
        except Exception as e:
            self.root.after(0, lambda: self.scan_error(str(e)))
    
    def scan_completed(self, scan_time):
        self.scanning = False
        self.progress.stop()
        self.scan_button.config(state="normal", text="Start Scan")
        self.visualize_button.config(state="normal")
        self.export_button.config(state="normal")
        
        # Update results with enhanced information
        for ip, device_info in self.mapper.devices.items():
            ports_str = ', '.join(map(str, device_info['open_ports'][:5]))  # Show first 5 ports
            if len(device_info['open_ports']) > 5:
                ports_str += "..."
            
            mac_address = device_info.get('mac_address', 'Unknown')
            
            self.tree.insert('', tk.END, values=(
                ip,
                device_info['hostname'],
                device_info['device_type'],
                mac_address,
                ports_str
            ))
        
        device_count = len(self.mapper.devices)
        self.status_var.set(f"Scan completed in {scan_time:.1f}s. Found {device_count} device(s)")
        
        if device_count == 0:
            messagebox.showinfo("Scan Results", 
                              "No devices found on the network.\n\n"
                              "This could be due to:\n"
                              "• Network security settings blocking discovery\n"
                              "• Devices configured to not respond to ICMP\n"
                              "• Firewall blocking network scanning\n"
                              "• All devices are in stealth mode\n\n"
                              "Try running with elevated privileges for better results.")
        else:
            messagebox.showinfo("Scan Results", 
                              f"Successfully discovered {device_count} device(s) in {scan_time:.1f} seconds!\n\n"
                              f"Scan methods used:\n"
                              f"• ARP table scanning\n"
                              f"• ICMP ping scanning\n"
                              f"• Port scanning")
    
    def scan_error(self, error_msg):
        self.scanning = False
        self.progress.stop()
        self.scan_button.config(state="normal", text="Start Scan")
        self.status_var.set("Scan failed")
        messagebox.showerror("Scan Error", f"An error occurred during scanning:\n{error_msg}")
    
    def generate_map(self):
        if not self.mapper.devices:
            messagebox.showwarning("No Data", "Please run a network scan first.")
            return
        
        try:
            self.status_var.set("Generating network map...")
            
            # Build graph
            self.mapper.build_network_graph()
            
            # Ask user where to save
            filename = filedialog.asksaveasfilename(
                defaultextension=".png",
                filetypes=[("PNG files", "*.png"), ("All files", "*.*")],
                title="Save Network Map"
            )
            
            if filename:
                self.mapper.visualize_network(save_file=filename)
                messagebox.showinfo("Success", f"Network map saved to:\n{filename}")
                self.status_var.set("Network map generated successfully")
            else:
                # Show without saving
                self.mapper.visualize_network()
                self.status_var.set("Network map displayed")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate network map:\n{str(e)}")
            self.status_var.set("Map generation failed")
    
    def export_data(self):
        if not self.mapper.devices:
            messagebox.showwarning("No Data", "Please run a network scan first.")
            return
        
        try:
            filename = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
                title="Export Network Data"
            )
            
            if filename:
                self.mapper.export_data(filename)
                messagebox.showinfo("Success", f"Network data exported to:\n{filename}")
                self.status_var.set("Data exported successfully")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export data:\n{str(e)}")
            self.status_var.set("Export failed")

def main():
    if not TKINTER_AVAILABLE:
        print("GUI cannot start: tkinter is not available")
        print("Please use the command-line version instead:")
        print("  python3 main.py")
        return
    
    try:
        root = tk.Tk()
        app = NetworkMapperGUI(root)
        root.mainloop()
    except Exception as e:
        print(f"GUI failed to start: {e}")
        print("You can use the command-line version instead:")
        print("  python3 main.py")

if __name__ == "__main__":
    main()
