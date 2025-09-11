# Network Monitor & Demo Attack

This project is a **network sniffer with real-time attack detection**, with a Node.js server for visualization and Python scripts to simulate network attacks for demo purposes.

It also includes an interactive script to launch attacks one by one or all together.

---

## Requirements

- Docker and Docker Compose  
- Python 3.12+  
- pip  
- Root/sudo privileges to sniff the network

---

## Installation

Clone the repository:

```bash
git clone https://github.com/ameelleea/network_monitor.git
cd network-monitor/network_monitor
```
All following commands should be run from the network_monitor directory.

## Usage
### 1. Start Node Server and Sniffer

Run the following script to start both the server and the sniffer:
 ```bash
./run-networkmonitor.sh
```

This script will:

Clean up any leftover Docker containers.

Start the Node.js server in Docker.

Create a Python virtual environment (venv) and install the netsniffer package.

Launch the sniffer on the local network (requires sudo).

Note: The sniffer requires root privileges to capture packets. The script automatically handles the virtual environment.

### 2. View Web Dashboard
The network monitor comes complete with a Dashboard that allows the user to see stats and data about traffic on the local network.

Due to time constraint, the dashboard is currently limited to data about IP packets. It will be expanded in the future.

To see the data via the web dashboard, after running the bash script and starting up the node server and netsniffer, open you browser and navigate to
```http://localhost:300```.

Users can customise the URL by changing the HOST and PORT setting in the ```run-networkmonitor.sh``` script.

### 3. Run Demo Attacks

To launch demo attacks (ARP spoofing, SYN flood, ICMP flood, etc.) separately, use:
```bash
./run-demoattack.sh
```

This script provides an interactive menu:

1) ARP Spoofing
2) SYN Flood
3) ICMP Flood
4) TCP Reset Attack
5) UDP Amplification
6) DNS Tunneling
7) DDoS Simulation
8) All attacks
0) Exit


Select the desired attack and press ENTER to launch it.
You can also choose “All attacks” to run them sequentially.

Warning: These attacks are simulated and should be executed only on a test network or your local machine.

## Repository Structure
```bash
network_monitor/
├── run-networkmonitor.sh    # Starts Node server + sniffer
├── run-demoattack.sh        # Launches interactive demo attack
├── server/                  # Node.js server code
├── sniffer/                 # Python sniffer code
├── demo_attack/             # Demo attack scripts
├── venv/                    # Python virtual environment (created automatically)
├── pyproject.toml           # Python package configuration
├── requirements.txt
├── docker-compose.yml
└── README.md
```
### Notes

All Python commands are executed within the virtual environment created by ```run-networkmonitor.sh```.

The sniffer captures traffic only when run with ```sudo```.

Demo attacks send simulated packets to the target machine configured in ```demo_attack.py```.
