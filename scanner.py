#!/usr/bin/env python3
"""
Wi-Fi Security Scanner (White Hat)
Author: Alexander Kulemin
Scan networks, detect open APs, check encryption types.
"""

import os
import re
import subprocess
import time
from datetime import datetime

# ============================================================
# COLORS
# ============================================================

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
RESET = "\033[0m"

# ============================================================
# SCAN FUNCTIONS
# ============================================================

def scan_networks():
    """
    Scan for Wi-Fi networks using termux-wifi or iwlist.
    Returns list of networks with SSID, BSSID, signal, encryption.
    """
    networks = []
    
    # Try termux-wifi first (for Android)
    try:
        result = subprocess.run(["termux-wifi-scan"], capture_output=True, text=True, timeout=15)
        if result.returncode == 0 and result.stdout:
            networks = parse_termux_output(result.stdout)
    except:
        pass
    
    # If termux-wifi not available, try iwlist (requires root/rooted)
    if not networks:
        try:
            result = subprocess.run(["iwlist", "scan"], capture_output=True, text=True, timeout=15)
            if result.returncode == 0:
                networks = parse_iwlist_output(result.stdout)
        except:
            pass
    
    return networks

def parse_termux_output(output):
    """Parse termux-wifi-scan output."""
    networks = []
    try:
        import json
        data = json.loads(output)
        for ap in data:
            bssid = ap.get('bssid', 'Unknown')
            ssid = ap.get('ssid', '<Hidden>') or '<Hidden>'
            signal = ap.get('level', 0)
            encryption = ap.get('encryption', 'Unknown')
            
            # Determine encryption type
            enc_type = "Unknown"
            if encryption:
                enc_type = encryption.upper()
            
            networks.append({
                'ssid': ssid,
                'bssid': bssid,
                'signal': signal,
                'encryption': enc_type,
                'channel': 'N/A'
            })
    except:
        pass
    
    return networks

def parse_iwlist_output(output):
    """Parse iwlist scan output."""
    networks = []
    current = {}
    
    for line in output.split('\n'):
        line = line.strip()
        
        if 'Cell' in line and 'Address' in line:
            # Save previous network
            if current and current.get('ssid'):
                networks.append(current)
            current = {}
            bssid_match = re.search(r'Address: ([0-9A-Fa-f:]+)', line)
            if bssid_match:
                current['bssid'] = bssid_match.group(1)
        
        if 'ESSID' in line:
            ssid = re.search(r'ESSID:"(.+?)"', line)
            if ssid:
                current['ssid'] = ssid.group(1) or '<Hidden>'
            else:
                current['ssid'] = '<Hidden>'
        
        if 'Quality' in line:
            quality = re.search(r'Quality=(\d+)/(\d+)', line)
            if quality:
                # Normalize to dBm-like value
                current['signal'] = int(quality.group(1)) / int(quality.group(2)) * 100
        
        if 'Encryption key' in line:
            current['encryption'] = 'ON' if 'on' in line else 'OFF'
        
        if 'Channel' in line:
            channel_match = re.search(r'Channel:(\d+)', line)
            if channel_match:
                current['channel'] = channel_match.group(1)
    
    # Add last network
    if current and current.get('ssid'):
        networks.append(current)
    
    return networks

def check_security(network):
    """Analyze security of a network."""
    enc = network.get('encryption', 'Unknown').upper()
    ssid = network.get('ssid', '<Hidden>')
    
    # Check for dangerous names
    dangerous_names = ['free', 'public', 'guest', 'open', 'unsecured']
    is_dangerous = any(word in ssid.lower() for word in dangerous_names)
    
    if 'OPEN' in enc or enc == 'OFF' or enc == 'NONE':
        return {
            'level': 'CRITICAL',
            'color': RED,
            'message': f'🔴 OPEN NETWORK! No encryption. Anyone can connect and sniff traffic.',
            'fix': 'Enable WPA2/WPA3 encryption in router settings.'
        }
    elif 'WEP' in enc:
        return {
            'level': 'HIGH',
            'color': RED,
            'message': f'⚠️ WEP encryption (broken). Can be cracked in minutes.',
            'fix': 'Upgrade to WPA2 or WPA3 immediately.'
        }
    elif 'WPA2' in enc:
        if is_dangerous:
            return {
                'level': 'MEDIUM',
                'color': YELLOW,
                'message': f'🟡 WPA2 with suspicious SSID. Check if this is a rogue AP.',
                'fix': 'Verify the network owner. Change default passwords.'
            }
        else:
            return {
                'level': 'GOOD',
                'color': GREEN,
                'message': f'✅ WPA2 (good). Use a strong password (12+ chars).',
                'fix': 'Ensure firmware is updated. Disable WPS.'
            }
    elif 'WPA3' in enc:
        return {
            'level': 'EXCELLENT',
            'color': GREEN,
            'message': f'🌟 WPA3 (best). Latest standard.',
            'fix': 'All good. Keep firmware updated.'
        }
    else:
        return {
            'level': 'UNKNOWN',
            'color': YELLOW,
            'message': f'⚠️ Unknown encryption type: {enc}',
            'fix': 'Investigate manually.'
        }

def check_wps_vulnerability(network):
    """Simulate WPS vulnerability check."""
    # This is a simulation for educational purposes
    enc = network.get('encryption', '').upper()
    
    # WPS is often enabled on older routers with WPA2
    if 'WPA2' in enc or 'WPA3' in enc:
        # Simulate: 30% chance of WPS being enabled (for educational demo)
        import random
        wps_enabled = random.random() < 0.3
        if wps_enabled:
            return {
                'vulnerable': True,
                'message': '⚠️ WPS may be enabled. This can be brute-forced.',
                'fix': 'Disable WPS in router settings.'
            }
        else:
            return {
                'vulnerable': False,
                'message': '✅ WPS likely disabled.',
                'fix': 'Keep it disabled.'
            }
    else:
        return {
            'vulnerable': False,
            'message': '✅ WPS not applicable.',
            'fix': 'N/A'
        }

# ============================================================
# MAIN
# ============================================================

def main():
    print("=" * 60)
    print("      📡 WI-FI SECURITY SCANNER")
    print("      Author: Alexander Kulemin")
    print("      🕵️ White Hat Tool — Use Responsibly")
    print("=" * 60)
    print("\n⚠️  Only scan networks you own or have permission to test.")
    print("📌 For educational and security research purposes.\n")
    
    input("Press Enter to start scanning...")
    print("\n[+] Scanning for Wi-Fi networks...\n")
    
    networks = scan_networks()
    
    if not networks:
        print("❌ No networks found. Ensure Wi-Fi is on.")
        print("   On Termux: run 'termux-wifi-scan' after enabling Wi-Fi.")
        print("   Note: Requires root or termux-wifi package.")
        return
    
    print(f"[+] Found {len(networks)} networks.\n")
    
    # Sort by signal strength
    networks.sort(key=lambda x: x.get('signal', 0), reverse=True)
    
    for i, network in enumerate(networks, 1):
        ssid = network.get('ssid', '<Hidden>')
        bssid = network.get('bssid', 'N/A')
        signal = network.get('signal', 0)
        encryption = network.get('encryption', 'Unknown')
        
        security = check_security(network)
        wps = check_wps_vulnerability(network)
        
        print("-" * 60)
        print(f"  {CYAN}#{i}{RESET} {ssid}")
        print(f"  📶 Signal: {signal}%")
        print(f"  📡 BSSID: {bssid}")
        print(f"  🔒 Encryption: {encryption}")
        print(f"  {security['color']}🔐 Security: {security['message']}{RESET}")
        print(f"  🔧 Fix: {security['fix']}")
        
        if wps['vulnerable']:
            print(f"  {RED}⚠️ WPS: {wps['message']}{RESET}")
            print(f"  🔧 Fix: {wps['fix']}")
        else:
            print(f"  {GREEN}✅ WPS: {wps['message']}{RESET}")
        
        print("-" * 60)
    
    print("\n" + "=" * 60)
    print("🕵️  Recommendations:")
    print("   - Use WPA2 or WPA3 with a strong password (12+ characters)")
    print("   - Disable WPS")
    print("   - Hide SSID if possible")
    print("   - Keep router firmware updated")
    print("=" * 60)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Goodbye!")
