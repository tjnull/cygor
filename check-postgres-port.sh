#!/bin/bash
# Script to check if PostgreSQL port is available and suggest an alternative

check_port() {
    local port=$1
    if command -v netstat >/dev/null 2>&1; then
        netstat -tuln | grep -q ":$port " && return 1
    elif command -v ss >/dev/null 2>&1; then
        ss -tuln | grep -q ":$port " && return 1
    elif command -v lsof >/dev/null 2>&1; then
        lsof -i :$port >/dev/null 2>&1 && return 1
    fi
    return 0
}

find_available_port() {
    local start_port=$1
    local port=$start_port
    
    while [ $port -lt 65535 ]; do
        if check_port $port; then
            echo $port
            return 0
        fi
        port=$((port + 1))
    done
    
    echo $start_port  # Fallback
    return 1
}

# Check port 5432
if check_port 5432; then
    echo "Port 5432 is available"
    echo "POSTGRES_HOST_PORT=5432"
    exit 0
else
    echo "Port 5432 is already in use, finding alternative..."
    alt_port=$(find_available_port 5433)
    echo "Using port $alt_port instead"
    echo "POSTGRES_HOST_PORT=$alt_port"
    exit 0
fi

