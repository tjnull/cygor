# cygor

README is still in works... 10/2/2025

Unified CLI wrapper around existing Cygor scripts.

---

##  Quickstart

### Run a Scan (CLI)
```bash
cygor scan -i eth0 -ips 192.168.1.0/24 --discover masscan --scan-type top-ports --parse
```

### Run the Web UI
```bash
cygor web start --host 0.0.0.0 --port 8080 --load-dir results
```

Then visit:
```
http://localhost:8080
```

---

## 🔧 Installation (Editable)
Install Cygor locally in editable mode:
```bash
pip install -e .
```

---

## 📖 Usage
```bash
cygor scan --help
cygor parse --help
cygor enum --help
cygor web --help
```

---

## Running Cygor with Docker

You can run Cygor inside a Docker container without installing dependencies directly on your host system. This ensures a clean, portable setup.

### 1. Build the Docker Image
From the root of the `cygor-beta` project:
```bash
docker build -t cygor .
```

### 2. Run Cygor in Docker
Run Cygor the same way as on your host:
```bash
docker run --rm -it   --network host   -v /path/to/results:/app/results   cygor scan -i eth0 -ips 192.168.1.0/24 --discover masscan --scan-type top-ports --parse
```

Replace `/path/to/results` with the directory on your host containing scan XML files.

### 3. Add a Shell Alias (Optional)
Add this alias to your shell config (`~/.bashrc` or `~/.zshrc`):

```bash
alias cygor='docker run --rm -it   --network host   -v ${CYGOR_RESULTS_PATH:-$(pwd)/results}:/app/results   cygor'
```

Reload your shell:
```bash
source ~/.bashrc   # or ~/.zshrc
```

Now you can run scans and point to your results directory by setting `CYGOR_RESULTS_PATH`:
```bash
CYGOR_RESULTS_PATH=/home/user/scans cygor scan -i eth0 -ips 192.168.1.0/24 --discover masscan
```

---

##  Running Cygor Web with Docker Compose

You can also launch the Cygor Web UI using Docker Compose.

### 1. Create a `.env` file
In the same directory as your `docker-compose.yml`, create `.env`:

```env
CYGOR_RESULTS_PATH=/absolute/path/to/your/results
CYGOR_PORT=8080
```

Example:
```env
CYGOR_RESULTS_PATH=/home/tjnull/Documents/scripts/cygor-beta/results
CYGOR_PORT=8080
```

### 2. Start the Web UI
```bash
docker compose up -d
```

### 3. Access the Interface
Open your browser and go to:
```
http://localhost:${CYGOR_PORT:-8080}
```

### 4. Stop the Web UI
```bash
docker compose down
```

### 5. Change the Port or Results Directory
Simply edit `.env` and restart:
```bash
docker compose down
docker compose up -d
```

---

## 📦 Tools Included in the Docker Image

The Cygor Docker image comes preloaded with:

- **nmap**
- **masscan**
- **naabu**
- **playwright + chromium** (for gowitness-style modules)

This ensures **all Cygor modules work out-of-the-box** inside the container.

---

## 📊 Architecture Diagram

```mermaid
flowchart TD
    A[User] --> B[Cygor CLI/Web]
    B --> C[Nmap]
    B --> D[Masscan]
    B --> E[Naabu]
    B --> F[Modules (e.g., gowitness)]
    C & D & E & F --> G[Results Directory / Database]
    G --> H[Web UI]
```
