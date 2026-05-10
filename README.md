# 🔍 Network Scanner Tool - ARP Scanner

[![Python Version](https://img.shields.io/badge/python-3.7%2B-blue)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20WSL-lightgrey)]()

A lightweight ARP-based network scanner for **educational purposes**. Discover devices on your local network using ARP requests.

## ⚠️ Legal Disclaimer

> **IMPORTANT**: This tool is for **EDUCATIONAL PURPOSES ONLY**. 
> - Only scan networks you **OWN** or have **EXPLICIT WRITTEN PERMISSION** to test
> - Unauthorized network scanning may violate laws
> - The author assumes **NO LIABILITY** for misuse of this tool

## 🎯 Features

- ✅ **ARP Scanning** - Discover devices on local network
- ✅ **MAC Address Resolution** - Get hardware addresses
- ✅ **Vendor Identification** - Identify device manufacturers
- ✅ **Simple & Fast** - No unnecessary features
- ✅ **Cross-platform** - Linux, macOS, Windows (WSL)

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/jigmasth/network-scanner-tool.git
cd network-scanner-tool

# Install arp-scan (Linux)
sudo apt update
sudo apt install arp-scan

# Make script executable
chmod +x network_scanner.py