#!/usr/bin/env python3
"""
Test script to verify the network mapping tool functionality
"""

import sys
import os

def test_imports():
    """Test that all required modules can be imported"""
    print("Testing imports...")
    
    try:
        # Test basic imports
        import networkx as nx
        import matplotlib.pyplot as plt
        import netifaces
        import ipaddress
        import socket
        import threading
        import time
        from collections import defaultdict
        import json
        import subprocess
        import concurrent.futures
        import platform
        import configparser
        print("✓ All basic imports successful")
        
        # Test GUI imports
        try:
            import tkinter as tk
            from tkinter import ttk, messagebox, filedialog
            print("✓ GUI imports successful")
        except ImportError as e:
            print(f"⚠ GUI imports failed: {e}")
            print("  GUI functionality may not work, but command-line versions should work")
        
        # Test main project imports
        from simple_main import SimpleNetworkMapper
        print("✓ SimpleNetworkMapper import successful")
        
        from main import NetworkMapper
        print("✓ NetworkMapper import successful")
        
        return True
        
    except ImportError as e:
        print(f"✗ Import failed: {e}")
        return False

def test_basic_functionality():
    """Test basic functionality without network scanning"""
    print("\nTesting basic functionality...")
    
    try:
        from simple_main import SimpleNetworkMapper
        
        # Create mapper instance
        mapper = SimpleNetworkMapper()
        print("✓ SimpleNetworkMapper instantiation successful")
        
        # Test network detection
        networks = mapper.get_local_networks()
        print(f"✓ Network detection successful: {len(networks)} networks found")
        for network in networks:
            print(f"  - {network}")
        
        # Test gateway detection
        gateway = mapper.detect_gateway()
        if gateway:
            print(f"✓ Gateway detection successful: {gateway}")
        else:
            print("⚠ No gateway detected (this may be normal)")
        
        # Test config loading
        config = mapper.load_config("config.ini")
        print("✓ Configuration loading successful")
        
        return True
        
    except Exception as e:
        print(f"✗ Basic functionality test failed: {e}")
        return False

def test_gui_creation():
    """Test GUI creation without showing it"""
    print("\nTesting GUI creation...")
    
    try:
        import tkinter as tk
        from gui import NetworkMapperGUI
        
        # Create root window (but don't show it)
        root = tk.Tk()
        root.withdraw()  # Hide the window
        
        # Create GUI instance
        app = NetworkMapperGUI(root)
        print("✓ GUI creation successful")
        
        # Destroy the window
        root.destroy()
        
        return True
        
    except Exception as e:
        print(f"✗ GUI creation failed: {e}")
        return False

def main():
    """Run all tests"""
    print("Network Mapping Tool - Test Suite")
    print("=" * 50)
    
    success_count = 0
    total_tests = 3
    
    # Test 1: Imports
    if test_imports():
        success_count += 1
    
    # Test 2: Basic functionality
    if test_basic_functionality():
        success_count += 1
    
    # Test 3: GUI creation
    if test_gui_creation():
        success_count += 1
    
    # Results
    print("\n" + "=" * 50)
    print(f"TEST RESULTS: {success_count}/{total_tests} tests passed")
    
    if success_count == total_tests:
        print("✓ All tests passed! The network mapping tool should work correctly.")
        print("\nYou can now run:")
        print("  python simple_main.py  - For simple command-line version")
        print("  python main.py         - For full command-line version")
        print("  python gui.py          - For GUI version")
        print("  python interactive.py  - For interactive menu version")
    else:
        print("⚠ Some tests failed. Check the error messages above.")
        
        if success_count >= 2:
            print("  The command-line versions should still work.")
        
        print("\nTo install missing dependencies:")
        print("  pip install -r requirements.txt")

if __name__ == "__main__":
    main()
