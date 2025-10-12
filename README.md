# Cygor

<div align="center">

[![bbot_banner](https://github.com/tjnull/cygor/blob/main/images/cygor-banner.jpg)](https://github.com/tjnull/cygor)

</div>

## General Overview
Cygor is a modular asset discovery framework that brings scanning, parsing, and service enumeration together in one workflow. It replaces the patchwork of separate tools with an automated process that handles discovery, enrichment, and targeted enumeration seamlessly — reducing manual overhead and letting you focus on results instead of tool management.

Cygor’s Web UI takes the chaos of raw scan data and organizes it into a single, visual command center. Instead of combing through endless XML, JSON, or flat text, results are automatically parsed, enriched, and displayed in one space that’s built for fast triage and decision-making.

Powered by FastAPI and Bootstrap 5, the dashboard makes it easy to:
- See the big picture at a glance — counters and summaries reveal service distributions, status code trends, and OS fingerprints.
- Dive deep instantly — pivot from high-level metrics into per-host details, ports, and module results with just a click.
- Visualize exposure — One of Cygor's modules called Lockon takes screenshots of active web services and outputs are embedded directly, giving immediate context without leaving the dashboard.
- Stay organized during triage — mark reviewed vs. unreviewed findings, filter and sort results, and zero in on the highest-value targets.

The Web UI isn’t just for presentation — it’s about efficiency and clarity. By bringing all collected data into a single, interactive workspace, it cuts down the time spent parsing files or reconciling outputs and lets testers focus on what matters: understanding the environment and acting on it.

## Why is it Called Cygor?
A lot of tools, techniques, and tradecrafts that I create are inspired from the Spawn Universe. If you have never read a Spawn comic, it's okay as I will share some information as to why I selected the character to be the name of this tool.

The name Cygor draws from Cy-Gor, a tragic anti-hero in the Spawn universe. Once Michael Konieczny — a government operative and close friend of Al Simmons — he tried to expose corruption after Simmons’s murder. However, he was captured and forced into Project Sim, the Simian experiments of Dr. Frederick Willheim, where a gorilla’s body was merged with Konieczny’s mind through invasive cybernetics. The result was the beast known as Cy-Gor — short for Cybernetic Gorilla.

After escaping captivity, Cy-Gor went on violent rampages, even tearing through government data centers in fits of confusion and rage. Though hunted and recaptured multiple times, he eventually fought back against the systems that sought to control him — removing tracking implants and breaking free to forge his own path, torn between machine, beast, and man.

- Reference: https://www.spawnworld.com/encyclopedia/Cygor.htm

## Who Should Use Cygor?
- Red Teams & Pentesters – Automate discovery, streamline enumeration, and maintain context across large engagements
- Blue Teams & System Administrators – Uncover unknown assets, validate inventories, and spot misconfigurations that expand attack surface.
- Security Researchers – Rapidly parse and analyze scan data to identify trends, overlooked services, and identify patterned anomalies.
- Students & Instructors – Learn real-world recon and enumeration techniques in a structured, repeatable environment.

# Tools that Cygor uses:
- Nmap – Reliable service and version detection; XML output is parsed into structured host/service data.
- Masscan – High-speed port scanning for rapid discovery across large networks.
- Naabu – Simple, fast TCP port scanner that complements Masscan/Nmap workflows.
- Playwright – Browser automation engine leveraged by Lockon to capture web screenshots.
- Python libraries – (requests, colorama, SQLModel, etc.) for parsing, enrichment, output formatting, and database handling.

# Installing Cygor
There are a few methods that are supported to install Cygor: pip, pipx, uv, and docker.

## Installing With pipx
```bash
# Stable version:
pipx install cygor

# Install from source:
git clone https://github.com/tjnull/cygor
cd cygor
pipx install .
```

## Deploying Cygor Using Docker
To build the Docker image, you can run the following command:

```bash
$ docker build -t cygor .
```

This will build the image `cygor`, which can be executed using `docker run`:

```bash
$ docker run --rm -v ./results:/opt/cygor/results cygor web --host 0.0.0.0 --port 8080 --load-dir /opt/cygor/results
```

Using `docker-compose.yaml`, the web UI could be started using `docker compose`:

```bash
$ docker compose up --build
```

From there, the `docker run` could be used to run commands and write outputs to the desired folder using the `-v` flag.

If you want to contribute to Cygor and its development, it might be a good idea to use the `docker-compose-dev.yaml` file instead, which mounts the `cygor` folder to the image:

```bash
$ docker compose -f docker-compose-dev.yaml up --build
```

# Running Cygor
Use the top-level Cygor command to access the available tools. Each subcommand has its own help screen (Cygor <command> --help) that documents flags and actions.

```bash
tjnull@kali:~$ cygor
Usage:
  cygor <command> [args]

Commands:
  banner  Cygor tool banner (Warning it is large!)
  scan    Automated scanner to discover hosts and services. (Will require root/sudo privileges for scanning).
  parse   Analyze a NMAP scan file (nmap, gnmap, xml) and extract each host that is running a common service. Will create seperate hostlists for each service.
  enum    Loads enumeration modules that are located in the Cygor modules directory.
  web     Loads Cygor's Web UI and will allow you to interact with it by supplying data you have collected with Cygor.
```

## Cygor scanner
You will need `sudo` (`root`) privileges to run the scanner in `cygor`:

```bash
    Run host discovery with Masscan only:

    cygor scan -i eth0 -f scope.txt --discover masscan

    Run host discovery with both Masscan and Naabu, then Nmap on merged results:

    cygor scan -i eth0 -f scope.txt --discover masscan naabu --nmap-source merge

    Discovery only (no Nmap), save results in results/discovery/:

    cygor scan -i eth0 -f scope.txt --discover masscan naabu --discover-only

    Reuse saved discovery results for Nmap top ports scan:

    cygor scan --use-discovery results/discovery/merged-discovered.txt --scan-type top-ports

    Run Nmap with custom ports on discovered hosts:

    cygor scan --use-discovery results/discovery/masscan-discovered.txt --ports 80,443,8443

    Run Nmap with 10 parallel processes on full scope (Max is 100):

    \cygor scan -i eth0 -f scope.txt --discover naabu --processes 10 --scan-type fullscan:

    Run Cygor to discover hosts and scan them with Nmap with a provided lists of IP Addresses or CDRs:

    cygor scan -i eth0 -ips 10.10.10.1 10.10.10.5 10.10.20.0/24 --discover naabu --processes 10 --scan-type fullscan

    Exclude specific subnets or hosts from scan:

    cygor scan -i eth0 -f scope.txt --exclusions exclusions.txt --discover masscan

```

## Cygor Parser:
```bash
    Parse a directory of Nmap results and print hostlists:

    cygor parse results/nmap

    Parse a single XML and write hostlists to results/parsed-hostlists:

    cygor parse results/nmap/scan1.xml -o results

    Recursively parse .xml/.nmap/.gnmap files and write outputs:

    cygor parse /path/to/scans --out-dir results
```

## Cygor Enumeration Modules
As of now, cygor comes with three enumeration modules to help enumerate services from your scans to see if they are active.
- Lockon – A web discovery module that captures screenshots of HTTP/S services and organizes them for fast visual triage.
    - NOTE: if on Kali Linux, prior to first run of the LockOn module, you will have to install required chromium dependencies with, `apt install libasound2t64` and `apt install unifont`
    - then run `apt install libasound2t64 /root/.local/share/pipx/venvs/cygor/bin/python -m playwright install --with-deps chromium`
- SMB Explorer – Enumerates SMB shares, permissions, and accessible files to identify weak or misconfigured access.
- NFS Explorer – Interacts with NFS exports to analyze access levels, test UID/GID mappings, and uncover insecure configurations.

```bash
    List all available modules:

    cygor enum --list

    Run lockon module against http hostlist:

    cygor enum lockon -f results/parsed-hostlists/http/http-hostlist.txt -o results/enum/lockon

    Run nfsexplorer against NFS targets:

    cygor enum nfsexplorer --targets results/parsed-hostlists/nfs/nfs-hostlist.txt --exports-only

    Run smbexplorer with 8 threads:

    cygor enum smbexplorer --targets results/parsed-hostlists/smb/smb-hostlist.txt --threads 8
```

## Cygor Web UI
After collecting data, you can load it into Cygor’s Web UI to transform scan results into a clear visualization of hosts, services, and other key findings. Cygor will create a file called cygor.db that will contain the necessary data to model into Cygor's Web UI

```bash
tjnull@conops:~$ cygor web -h
usage: cygor web start [-h] [-H HOST] [-p PORT] [--reset-db] [--load-dir LOAD_DIR] [-v]

options:
  -h, --help           show this help message and exit
  -H, --host HOST
  -p, --port PORT
  --reset-db           Drop and recreate the database, then exit
  --load-dir LOAD_DIR  Preload results directory in the background
  -v, --verbose        Increase verbosity (-v shows more, -vv shows debug details)
```

# Disclaimer:
Cygor is a security research and educational framework. It is intended to be used only in environments where you have explicit, written authorization — such as penetration testing engagements, red team operations, classroom labs, or personal test ranges.

This software must not be used for unauthorized access, intrusion, or disruption of systems you do not own or control. Doing so may violate laws and regulations in your jurisdiction, and could result in criminal prosecution or civil penalties.

By downloading, running, or modifying Cygor, you agree that:
- You are solely responsible for how you use it.
- You will restrict its use to legal and ethical scenarios.

The authors and contributors of Cygor accept no liability for misuse, damage, or consequences arising from the use of this software.

If you are uncertain whether you are authorized to use Cygor in a given environment, do not run it.
