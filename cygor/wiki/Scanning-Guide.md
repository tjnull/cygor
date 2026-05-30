# Scanning Guide

Comprehensive guide to Cygor's scanning capabilities using Masscan, Naabu, and Nmap.

## Overview

Cygor orchestrates three powerful scanning tools:

- **Masscan**: Ultra-fast port scanner (millions of packets per second)
- **Naabu**: Fast TCP port scanner with advanced features
- **Nmap**: Comprehensive network scanner with service detection

## Basic Syntax

```bash
cygor scan -i <interface> -f <scope-file> --discover <method> [options]
```

## Discovery Methods

### Masscan

Fastest discovery method, ideal for large networks.

```bash
# Basic Masscan discovery
sudo cygor scan -i eth0 -f scope.txt --discover masscan

# Discovery only (no Nmap)
sudo cygor scan -i eth0 -f scope.txt --discover masscan --discover-only

# Custom rate (packets per second)
sudo cygor scan -i eth0 -f scope.txt --discover masscan --rate 10000
```

**Best for:**
- Large networks (1000+ hosts)
- Quick discovery phase
- When speed is critical

### Naabu

Balanced speed and accuracy.

```bash
# Basic Naabu discovery
sudo cygor scan -i eth0 -f scope.txt --discover naabu

# Discovery only
sudo cygor scan -i eth0 -f scope.txt --discover naabu --discover-only

# With custom ports
sudo cygor scan -i eth0 -f scope.txt --discover naabu --ports 80,443,8080
```

**Best for:**
- Medium-sized networks (100-1000 hosts)
- When you need good balance of speed and accuracy
- General-purpose scanning

### Combined Discovery

Use both tools and merge results for maximum coverage.

```bash
# Discover with both, merge results, then Nmap
sudo cygor scan -i eth0 -f scope.txt --discover masscan naabu --nmap-source merge
```

**Best for:**
- Maximum host discovery coverage
- Critical assessments where you can't miss hosts
- When you have time for comprehensive discovery

## Scan Types

### Top Ports

Scan the most common ports (default: top 1000).

```bash
sudo cygor scan -i eth0 -f scope.txt --discover naabu --scan-type top-ports
```

### Full Port Scan

Scan all 65535 ports (very slow but comprehensive).

```bash
sudo cygor scan -i eth0 -f scope.txt --discover naabu --scan-type fullscan
```

**Warning**: Full port scans can take hours or days for large networks.

### Custom Ports

Scan specific ports.

```bash
# Single port
sudo cygor scan -i eth0 -f scope.txt --discover naabu --ports 80

# Multiple ports
sudo cygor scan -i eth0 -f scope.txt --discover naabu --ports 80,443,8080,8443

# Port range
sudo cygor scan -i eth0 -f scope.txt --discover naabu --ports 8000-8100
```

## Advanced Options

### Parallel Processing

Speed up scans with multiple parallel processes.

```bash
# Use 10 parallel processes (max 100)
sudo cygor scan -i eth0 -f scope.txt --discover naabu --processes 10
```

**Recommendations:**
- Small networks (<100 hosts): 5-10 processes
- Medium networks (100-1000 hosts): 10-20 processes
- Large networks (1000+ hosts): 20-50 processes
- Maximum: 100 processes (use with caution)

### Exclusions

Exclude specific hosts or subnets from scanning.

```bash
# Create exclusions file
cat > exclusions.txt << EOF
192.168.1.100
10.0.0.0/24
172.16.0.1
EOF

# Scan with exclusions
sudo cygor scan -i eth0 -f scope.txt --exclusions exclusions.txt --discover naabu
```

### Using Discovery Results

Reuse discovery results for different scan types.

```bash
# Step 1: Discovery only
sudo cygor scan -i eth0 -f scope.txt --discover naabu --discover-only

# Step 2: Use discovery for top ports
sudo cygor scan --use-discovery results/discovery/naabu-discovered.txt --scan-type top-ports

# Step 3: Use discovery for custom ports
sudo cygor scan --use-discovery results/discovery/naabu-discovered.txt --ports 80,443,8080
```

### IP Address Input

Provide IPs directly without a file.

```bash
# Single IP
sudo cygor scan -i eth0 --ips 192.168.1.1 --discover naabu

# Multiple IPs
sudo cygor scan -i eth0 --ips 192.168.1.1 192.168.1.5 10.0.0.1 --discover naabu

# CIDR ranges
sudo cygor scan -i eth0 --ips 192.168.1.0/24 10.0.0.0/16 --discover naabu

# Mixed
sudo cygor scan -i eth0 --ips 192.168.1.1 10.0.0.0/24 --discover naabu
```

## Workflow Examples

### Quick Reconnaissance

```bash
# Fast discovery and top ports
sudo cygor scan -i eth0 -f scope.txt --discover naabu --scan-type top-ports --processes 10
```

### Comprehensive Assessment

```bash
# Phase 1: Discovery
sudo cygor scan -i eth0 -f scope.txt --discover masscan naabu --nmap-source merge --discover-only

# Phase 2: Top ports on discovered hosts
sudo cygor scan --use-discovery results/discovery/merged-discovered.txt --scan-type top-ports

# Phase 3: Full scan on critical hosts (manual selection)
sudo cygor scan --use-discovery critical-hosts.txt --scan-type fullscan
```

### Targeted Scanning

```bash
# Web services only
sudo cygor scan -i eth0 -f scope.txt --discover naabu --ports 80,443,8080,8443

# Database services
sudo cygor scan -i eth0 -f scope.txt --discover naabu --ports 3306,5432,1433,27017

# Common services
sudo cygor scan -i eth0 -f scope.txt --discover naabu --ports 21,22,23,25,53,80,443
```

## Output and Results

### Result Locations

- **Nmap XML**: `results/nmap/scan-*.xml`
- **Discovery Results**: `results/discovery/`
  - `masscan-discovered.txt`
  - `naabu-discovered.txt`
  - `merged-discovered.txt`

### Viewing Results

```bash
# Parse results
cygor parse results/nmap

# View hostlists
cat results/parsed-hostlists/http/http-hostlist.txt

# View in web UI
cygor web start --load-dir results
```

## Performance Tips

### 1. Start Small

Test with a small scope first:
```bash
# Test with single IP
sudo cygor scan -i eth0 --ips 192.168.1.1 --discover naabu
```

### 2. Use Discovery-Only First

For large networks, do discovery first:
```bash
# Discovery phase
sudo cygor scan -i eth0 -f large-scope.txt --discover masscan --discover-only

# Then targeted scans on discovered hosts
sudo cygor scan --use-discovery results/discovery/masscan-discovered.txt --scan-type top-ports
```

### 3. Adjust Parallel Processes

More processes = faster but more resource intensive:
```bash
# Conservative
sudo cygor scan -i eth0 -f scope.txt --discover naabu --processes 5

# Aggressive
sudo cygor scan -i eth0 -f scope.txt --discover naabu --processes 50
```

### 4. Exclude Unnecessary Hosts

Use exclusions to skip known-safe hosts:
```bash
sudo cygor scan -i eth0 -f scope.txt --exclusions safe-hosts.txt --discover naabu
```

## Troubleshooting

### Permission Denied

```bash
# Ensure you have sudo/root
sudo -v

# Check interface permissions
ip link show
```

### No Results

1. Check network interface: `ip addr show`
2. Verify scope file format
3. Check firewall rules
4. Review scan logs

### Slow Performance

1. Reduce parallel processes
2. Use discovery-only first
3. Scan smaller subnets
4. Check network bandwidth

### Tool Not Found

```bash
# Install missing tools
sudo apt-get install nmap masscan

# Or download Naabu
wget https://github.com/projectdiscovery/naabu/releases/latest
```

## Next Steps

- [Parsing Results](Parsing-Results.md)
- [Enumeration Modules](Enumeration-Modules.md)
- [Web UI Quick Start](Web-UI-Quick-Start.md)

