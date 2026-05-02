#!/bin/sh
# Layer 2 scope enforcement: kernel-level network filtering for browser worker.
# Blocks RFC 1918, loopback, link-local, and cloud metadata at the kernel level.
# This is the mandatory fallback layer — CDP interception (Layer 1) is primary.
#
# Rule ordering:
# 1. ACCEPT on loopback interface (Chrome IPC via CDP, required)
# 2. DROP NEW connections to all blocked CIDRs (before ESTABLISHED rule)
# 3. ACCEPT ESTABLISHED/RELATED (for legitimate scan traffic already connected)
# 4. ACCEPT all else (external targets)
#
# This ordering ensures that even if DNS rebinding tricks Layer 1,
# the kernel blocks the actual connection to a private IP.

set -e

# 1. Allow loopback for Chrome IPC (must come first)
iptables -A OUTPUT -o lo -j ACCEPT

# 2. Block NEW connections to private/reserved ranges
# RFC 1918
iptables -A OUTPUT -m state --state NEW -d 10.0.0.0/8 -j DROP
iptables -A OUTPUT -m state --state NEW -d 172.16.0.0/12 -j DROP
iptables -A OUTPUT -m state --state NEW -d 192.168.0.0/16 -j DROP

# Loopback (non-lo-interface traffic)
iptables -A OUTPUT -m state --state NEW -d 127.0.0.0/8 -j DROP

# Link-local and cloud metadata
iptables -A OUTPUT -m state --state NEW -d 169.254.0.0/16 -j DROP

# Carrier-grade NAT
iptables -A OUTPUT -m state --state NEW -d 100.64.0.0/10 -j DROP

# Test/documentation/reserved ranges
iptables -A OUTPUT -m state --state NEW -d 192.0.0.0/24 -j DROP
iptables -A OUTPUT -m state --state NEW -d 192.0.2.0/24 -j DROP
iptables -A OUTPUT -m state --state NEW -d 198.18.0.0/15 -j DROP
iptables -A OUTPUT -m state --state NEW -d 198.51.100.0/24 -j DROP
iptables -A OUTPUT -m state --state NEW -d 203.0.113.0/24 -j DROP

# Unspecified and reserved
iptables -A OUTPUT -m state --state NEW -d 0.0.0.0/8 -j DROP
iptables -A OUTPUT -m state --state NEW -d 240.0.0.0/4 -j DROP

# 3. Allow established connections (legitimate scan traffic)
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# 4. Allow everything else (external targets)
iptables -A OUTPUT -j ACCEPT

echo "Browser worker iptables rules applied (Layer 2 scope enforcement)."
