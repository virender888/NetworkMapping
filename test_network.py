#!/usr/bin/env python3
"""
Quick network test to debug connectivity issues
"""

import subprocess
import platform
import netifaces
import ipaddress

def test_basic_connectivity():
    """Test basic network connectivity"""
    print("=== Basic Network Connectivity Test ===\n")
    
    # Test 1: Check network interfaces
    print("1. Network Interfaces:")
    interfaces = netifaces.interfaces()
    for interface in interfaces:
        try:
            addr_info = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addr_info:
                for addr in addr_info[netifaces.AF_INET]:
                    ip = addr.get('addr')
                    netmask = addr.get('netmask')
                    if ip and not ip.startswith('127.'):
                        print(f"   {interface}: {ip}/{netmask}")
        except:
            pass
    
    # Test 2: Check default gateway
    print("\n2. Default Gateway:")
    try:
        gateways = netifaces.gateways()
        default_gateway = gateways['default'][netifaces.AF_INET][0]
        print(f"   Gateway: {default_gateway}")
        
        # Test ping to gateway
        print(f"   Testing ping to gateway...")
        if platform.system() == "Windows":
            result = subprocess.run(['ping', '-n', '2', default_gateway], 
                                  capture_output=True, text=True, timeout=10)
        else:
            result = subprocess.run(['ping', '-c', '2', default_gateway], 
                                  capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            print(f"   ✅ Gateway ping successful")
        else:
            print(f"   ❌ Gateway ping failed")
            
    except Exception as e:
        print(f"   Error: {e}")
    
    # Test 3: ARP table
    print("\n3. ARP Table Entries:")
    try:
        if platform.system() == "Windows":
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=10)
        else:
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            arp_count = 0
            for line in lines[:10]:  # Show first 10 entries
                if line.strip() and ('.' in line or ':' in line):
                    print(f"   {line.strip()}")
                    arp_count += 1
            print(f"   Total ARP entries: {len([l for l in lines if l.strip()])}")
        else:
            print(f"   ARP command failed")
    except Exception as e:
        print(f"   Error: {e}")
    
    # Test 4: Test ping to common IPs
    print("\n4. Testing Common Local IPs:")
    common_ips = ['192.168.1.1', '192.168.1.2', '192.168.1.10', '192.168.1.100']
    
    for ip in common_ips:
        try:
            if platform.system() == "Windows":
                result = subprocess.run(['ping', '-n', '1', '-w', '1000', ip], 
                                      capture_output=True, text=True, timeout=3)
            else:
                result = subprocess.run(['ping', '-c', '1', '-W', '1', ip], 
                                      capture_output=True, text=True, timeout=3)
            
            if result.returncode == 0:
                print(f"   ✅ {ip} - Responding")
            else:
                print(f"   ❌ {ip} - Not responding")
        except:
            print(f"   ❌ {ip} - Timeout/Error")

if __name__ == "__main__":
    test_basic_connectivity()
