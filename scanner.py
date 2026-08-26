#!/usr/bin/env python3
"""
Wi-Fi Security Scanner (White Hat)
Author: Alexander Kulemin
Scans for vulnerabilities: open networks, WEP, WPS, hidden SSID.
"""

import subprocess
import json
import random

print("=" * 60)
print("      📡 WI-FI SECURITY SCANNER")
print("      Author: Alexander Kulemin")
print("      🕵️ White Hat Tool — Use Responsibly")
print("=" * 60)
print("\n[+] Scanning for Wi-Fi networks...\n")

def check_vulnerabilities(ssid, capabilities, rssi):
    """Check for vulnerabilities and return risk level."""
    issues = []
    risk_score = 0
    
    # 1. Open network (no encryption)
    if "ESS" in capabilities and "WPA" not in capabilities and "WEP" not in capabilities:
        issues.append("🔴 OPEN NETWORK — no encryption!")
        risk_score += 10
    
    # 2. WEP (weak encryption)
    if "WEP" in capabilities:
        issues.append("🔴 WEP encryption — crackable in minutes!")
        risk_score += 8
    
    # 3. WPS enabled
    if "WPS" in capabilities:
        issues.append("🟡 WPS enabled — vulnerable to brute-force")
        risk_score += 5
    
    # 4. Hidden SSID
    if not ssid or ssid == '<Hidden>':
        issues.append("🟡 Hidden SSID — gives false sense of security")
        risk_score += 2
    
    # 5. Weak signal (possible distance attack)
    if rssi < -85:
        issues.append("🟡 Weak signal — may be vulnerable to deauth attacks")
        risk_score += 2
    
    # 6. Suspect SSID (free, public, guest)
    suspicious = ['free', 'public', 'guest', 'open', 'unsecured', 'default']
    if any(word in ssid.lower() for word in suspicious):
        issues.append("🟡 Suspicious SSID — may be a honeypot or rogue AP")
        risk_score += 3
    
    # Determine risk level
    if risk_score >= 10:
        risk_level = "🔴 HIGH RISK"
    elif risk_score >= 5:
        risk_level = "🟡 MEDIUM RISK"
    else:
        risk_level = "🟢 LOW RISK"
    
    return risk_level, issues, risk_score

def generate_recommendations(issues):
    """Generate security recommendations based on findings."""
    recs = []
    for issue in issues:
        if "OPEN NETWORK" in issue:
            recs.append("Enable WPA2/WPA3 encryption")
        if "WEP encryption" in issue:
            recs.append("Upgrade to WPA2/WPA3 immediately")
        if "WPS enabled" in issue:
            recs.append("Disable WPS in router settings")
        if "Hidden SSID" in issue:
            recs.append("Enable SSID broadcast (hiding doesn't add security)")
        if "Weak signal" in issue:
            recs.append("Move closer to router or use a repeater")
        if "Suspicious SSID" in issue:
            recs.append("Verify network owner before connecting")
    return recs

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
        
        # Vulnerability check
        risk_level, issues, score = check_vulnerabilities(ssid, capabilities, rssi)
        
        print(f"  {i}. {ssid}")
        print(f"     📶 Signal: {rssi} dBm")
        print(f"     🔒 Security: {security}")
        print(f"     🛡️ Risk: {risk_level} (Score: {score}/10)")
        
        if issues:
            for issue in issues:
                print(f"        • {issue}")
        
        # Recommendations
        recs = generate_recommendations(issues)
        if recs:
            for rec in recs:
                print(f"        🔧 Fix: {rec}")
        
        print("-" * 50)
    
except FileNotFoundError:
    print("❌ termux-wifi-scaninfo not found. Install Termux:API from F-Droid.")
except json.JSONDecodeError:
    print("❌ Error parsing data. Try again.")
except Exception as e:
    print(f"❌ Error: {e}")

print("\n✅ Scan complete.")
