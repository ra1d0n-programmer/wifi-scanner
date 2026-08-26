#!/usr/bin/env python3
"""
Wi-Fi Security Scanner (White Hat)
Author: Alexander Kulemin
"""

import subprocess
import json

print("=" * 60)
print("      📡 WI-FI SECURITY SCANNER")
print("      Author: Alexander Kulemin")
print("      🕵️ White Hat Tool — Use Responsibly")
print("=" * 60)
print("\n[+] Scanning for Wi-Fi networks...\n")

try:
    result = subprocess.run(["termux-wifi-scaninfo"], capture_output=True, text=True, timeout=15)
    data = json.loads(result.stdout)
    
    print(f"[+] Found {len(data)} networks.\n")
    
    for i, ap in enumerate(data, 1):
        ssid = ap.get('ssid', '<Hidden>') or '<Hidden>'
        bssid = ap.get('bssid', 'N/A')
        rssi = ap.get('rssi', 0)
        capabilities = ap.get('capabilities', 'Unknown')
        
        # Security analysis
        if "WPA3" in capabilities:
            security = "🟢 WPA3 (Best)"
        elif "WPA2" in capabilities:
            security = "🟡 WPA2 (Good)"
        elif "WEP" in capabilities:
            security = "🔴 WEP (Weak)"
        elif "ESS" in capabilities and "WPA" not in capabilities and "WEP" not in capabilities:
            security = "🔴 OPEN (No encryption)"
        else:
            security = "⚪ Unknown"
        
        print(f"  {i}. {ssid}")
        print(f"     📶 Signal: {rssi} dBm")
        print(f"     🔒 Security: {security}")
        print("-" * 40)
    
except FileNotFoundError:
    print("❌ termux-wifi-scaninfo not found. Install Termux:API from F-Droid.")
except json.JSONDecodeError:
    print("❌ Error parsing data. Try again.")
except Exception as e:
    print(f"❌ Error: {e}")

print("\n✅ Scan complete.")
