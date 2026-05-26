# Common Issues

Troubleshooting guide for frequently encountered problems in Cygor.

## Installation Issues

### Python Version

**Problem**: `Python 3.11+ required`

**Solution**:
```bash
# Check Python version
python3 --version

# Install Python 3.11+
# Debian/Ubuntu
sudo apt-get install python3.11

# Use specific version
python3.11 -m pip install cygor
```

### Permission Denied

**Problem**: Permission errors during installation

**Solution**:
```bash
# Use user installation (recommended)
pip install --user cygor

# Or use pipx (isolated)
pipx install cygor

# Or use virtual environment
python3 -m venv cygor-env
source cygor-env/bin/activate
pip install cygor
```

### Missing Dependencies

**Problem**: Import errors or missing modules

**Solution**:
```bash
# Reinstall with dependencies
pip install --upgrade --force-reinstall cygor

# Or install from source
git clone https://github.com/tjnull/cygor
cd cygor
pip install .
```

## Scanning Issues

### Permission Denied for Scanning

**Problem**: `Permission denied` when running scans

**Solution**:
```bash
# Use sudo (required for raw sockets)
sudo cygor scan -i eth0 -f scope.txt --discover naabu

# Verify sudo access
sudo -v
```

### Interface Not Found

**Problem**: `Interface eth0 not found`

**Solution**:
```bash
# List available interfaces
ip addr show
# or
ifconfig

# Use correct interface name
sudo cygor scan -i wlan0 -f scope.txt --discover naabu
```

### No Results

**Problem**: Scan completes but no results

**Solution**:
1. **Check scope file**:
   ```bash
   cat scope.txt
   # Verify IPs/CIDRs are correct
   ```

2. **Test with single IP**:
   ```bash
   sudo cygor scan -i eth0 -ips 127.0.0.1 --discover naabu
   ```

3. **Check firewall**:
   ```bash
   sudo ufw status
   sudo iptables -L
   ```

4. **Verify tools are installed**:
   ```bash
   which nmap
   which masscan
   which naabu
   ```

### Tool Not Found

**Problem**: `nmap: command not found` or similar

**Solution**:
```bash
# Install nmap
sudo apt-get install nmap

# Install masscan
sudo apt-get install masscan

# Download naabu
wget https://github.com/projectdiscovery/naabu/releases/latest
chmod +x naabu
sudo mv naabu /usr/local/bin/
```

## Web UI Issues

### Port Already in Use

**Problem**: `Address already in use` when starting web server

**Solution**:
```bash
# Use different port
cygor web start -p 8081

# Or find and kill process using port
sudo lsof -i :8000
sudo kill -9 <PID>
```

### Can't Access from Other Machines

**Problem**: Web UI only accessible from localhost

**Solution**:
```bash
# Bind to all interfaces
cygor web start -H 0.0.0.0 -p 8080

# Check firewall
sudo ufw allow 8080
sudo iptables -A INPUT -p tcp --dport 8080 -j ACCEPT
```

### Results Not Showing

**Problem**: Web UI shows no data

**Solution**:
1. **Verify results directory**:
   ```bash
   cygor web start --load-dir /path/to/results
   ```

2. **Check file formats**:
   - Nmap XML: `*.xml`
   - Nmap text: `*.nmap`
   - Nmap grepable: `*.gnmap`

3. **Verify file location**:
   ```bash
   ls -la results/nmap/
   ```

4. **Check server logs**:
   ```bash
   tail -f results/cygor-web.log
   ```

### Database Errors

**Problem**: Database connection errors

**Solution**:
```bash
# Reset database (WARNING: deletes data)
cygor web start --reset-db

# Use PostgreSQL
cygor web start --db-url postgresql+psycopg_async://user:pass@localhost/cygor

# Check PostgreSQL is running
sudo systemctl status postgresql
```


## Database Issues

### SQLite Locked

**Problem**: `database is locked` errors

**Solution**:
```bash
# Stop all Cygor processes
cygor web stop

# Check for lock files
ls -la results/*.db-*

# Remove lock files (if safe)
rm results/*.db-*

# Restart
cygor web start
```

### PostgreSQL Connection Failed

**Problem**: Cannot connect to PostgreSQL

**Solution**:
1. **Check PostgreSQL is running**:
   ```bash
   sudo systemctl status postgresql
   ```

2. **Verify credentials**:
   ```bash
   psql -U cygor -d cygor -h localhost
   ```

3. **Check connection string**:
   ```bash
   echo $CYGOR_DB_URL
   ```

4. **Test connection**:
   ```bash
   cygor web start --db-url postgresql+psycopg_async://user:pass@localhost/cygor
   ```

### Migration Errors

**Problem**: Database migration fails

**Solution**:
```bash
# Backup database first
cp results/cygor.db results/cygor.db.backup

# Reset database (WARNING: deletes data)
cygor web start --reset-db

# Or manually migrate
# See Database Configuration guide
```

## Docker Issues

### Container Won't Start

**Problem**: Docker container exits immediately

**Solution**:
```bash
# Check logs
docker compose logs cygor

# Check PostgreSQL health
docker compose ps postgres

# Verify volumes
docker volume ls

# Rebuild
docker compose up --build
```

### Volume Permission Issues

**Problem**: Permission denied in volumes

**Solution**:
```bash
# Fix permissions
sudo chown -R $USER:$USER ./results
sudo chown -R $USER:$USER ./cygor-config

# Or run container as user
# Edit docker-compose.yaml to add user: "${UID}:${GID}"
```

### Database Connection in Docker

**Problem**: Can't connect to PostgreSQL in Docker

**Solution**:
1. **Check service name**: Use `postgres` (not `localhost`)
2. **Verify connection string**:
   ```yaml
   CYGOR_DB_URL=postgresql+psycopg_async://cygor:cygorpass@postgres:5432/cygor
   ```
3. **Check health status**:
   ```bash
   docker compose ps postgres
   ```

## Performance Issues

### Slow Scans

**Problem**: Scans take too long

**Solution**:
1. **Reduce scope**: Scan smaller subnets
2. **Use discovery-only first**: Then targeted scans
3. **Adjust parallel processes**: `--processes 10`
4. **Use faster discovery**: Masscan instead of Naabu
5. **Exclude unnecessary hosts**: `--exclusions`

### Web UI Slow

**Problem**: Web interface is slow to load

**Solution**:
1. **Reduce data**: Use smaller result sets
2. **Use PostgreSQL**: Better performance than SQLite
3. **Increase resources**: More CPU/RAM for server
4. **Optimize database**: Run VACUUM on SQLite

### High Memory Usage

**Problem**: Cygor uses too much memory

**Solution**:
1. **Reduce parallel processes**: Lower `--processes`
2. **Use discovery-only**: Less memory intensive
3. **Scan in batches**: Smaller scope files
4. **Increase system memory**: Add swap if needed

## Getting Help

### Check Logs

```bash
# Web server logs
tail -f results/cygor-web.log

# Docker logs
docker compose logs -f cygor

# System logs
journalctl -u cygor
```

### Enable Debug Mode

```bash
# Verbose output
cygor web start -vv

# Debug mode
cygor web start --debug

# Docker debug
CYGOR_DEBUG=1 docker compose up
```

### Report Issues

If issue persists:
1. Check existing GitHub issues
2. Create new issue with:
   - Error messages
   - Steps to reproduce
   - System information
   - Relevant logs

## Next Steps

- [Installation Guide](Installation-Guide.md)
- [Scanning Guide](Scanning-Guide.md)
- [Web UI Quick Start](Web-UI-Quick-Start.md)
- [Docker Deployment Guide](Docker-Deployment-Guide.md)

