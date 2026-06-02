# NIDS - Network-Based Detection System

**NIDS** is a lightweight network security tool designed for **Debian-based Linux systems**. It provides real-time traffic monitoring, intrusion detection, and automatic prevention capabilities (IPS mode) using `iptables`. The system is backed by a PostgreSQL database running in Docker for logging events.

> **Note:** This project is compatible with **Linux Debian-based distributions only** (e.g., Ubuntu, Debian, Kali Linux).

## 🛡️ Features & Detection Capabilities

This tool operates in two modes, configured via `PREVENTION_MODE` in `nids_threshold.conf`:
- **Detection Mode** (`PREVENTION_MODE=0`) — Alerts only, no blocking.
- **Prevention Mode** (`PREVENTION_MODE=1`) — Alerts and automatically blocks the attacker's IP using `iptables`.

> **Note:** Port scans (Null, Xmas, Full Xmas) are alert-only in both modes. Only SYN Scan triggers a block in Prevention Mode, as single-packet scans are too easily spoofed.

---

### 1. Brute Force Attacks
| Attack | Detection | Prevention |
|---|---|---|
| SSH Brute Force | Alert | Block |
| FTP Brute Force | Alert | Block |
| Web Brute Force (HTTP) | Alert | Block |

### 2. Network Scanning (Reconnaissance)
| Attack | Detection | Prevention |
|---|---|---|
| SYN Scan | Alert | Block |
| Null Scan | Alert | Alert only |
| Xmas Scan | Alert | Alert only |
| Full Xmas Scan | Alert | Alert only |

### 3. Denial of Service (DoS/DDoS)
| Attack | Detection | Prevention |
|---|---|---|
| SYN Flood | Alert | Block |
| ICMP Flood | Alert | Block |
| UDP Flood | Alert | Block |

### 4. Web Application Attacks
| Attack | Detection | Prevention |
|---|---|---|
| SQL Injection (SQLi) | Alert | Block |
| Cross-Site Scripting (XSS) | Alert | Block |
| Directory Traversal | Alert | Block |

---
## ⚙️ Setup & Installation

### 1. Configuration
Before installation, you must configure the environment variables. Rename the example file and update it with your settings (e.g., Database credentials, Grafana passwords).

```bash
# Rename the example file
mv .env.example .env

# Edit the .env file with your preferred text editor (e.g., nano, vim)
nano .env
```

### 2. Build & Run
Follow these commands to install dependencies, start the services, and compile the project:

```bash
# 1. Run the installation script to setup system dependencies
./install.sh

# 2. Start the PostgreSQL and Grafana containers
docker compose up -d --build

# 3. Compile the source code
make

# 4. Verify installation and check version
sudo ./nids -v
```

---

## 📊 Monitoring & Dashboard

This project utilizes **Grafana** to visualize attack statistics and network traffic in real-time, pulling data directly from the PostgreSQL database.

### Accessing the Dashboard
1.  Open your web browser and navigate to:
    ```
    http://<YOUR_SERVER_IP>:<GRAFANA_PORT>
    ```
    *(Default port is usually 3000, unless changed in your .env file)*

2.  **Login** using the credentials you defined in the `.env` file.

3.  Navigate to **Dashboards**. You will see a pre-configured dashboard displaying detected threats.

### Customization
You are not limited to the default view. You can create custom panels and dashboards by writing your own **PostgreSQL queries** within Grafana to analyze specific attack vectors or timeframes.
