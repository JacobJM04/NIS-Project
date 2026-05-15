# Network Intrusion Detection System (NIS)

A real-time network intrusion detection system that captures live traffic, detects anomalies using entropy analysis, and visualizes connections through an interactive dashboard.

## Features

- Live packet sniffing (TCP/UDP/Other) using Scapy
- Entropy-based anomaly detection with configurable thresholds
- Interactive network graph visualization (vis-network)
- Real-time Streamlit dashboard with attack alerts
- Attack simulation for testing detection
- SQLite storage with WAL mode for concurrent access

## Tech Stack

| Component | Library |
|-----------|---------|
| Packet capture | Scapy |
| Dashboard | Streamlit |
| Graph visualization | pyvis + vis-network |
| Graph analysis | NetworkX |
| Data processing | pandas, numpy |
| Storage | SQLite |

## Setup

**Requirements:** Python 3.8+, run as administrator/root (required for packet sniffing)

```bash
pip install -r requirements.txt
```

## Usage

**1. Start the sniffer** (in a terminal with admin/root privileges):
```bash
python sniffer.py
# or specify a network interface:
python sniffer.py eth0
```

**2. Launch the dashboard** (in a separate terminal):
```bash
streamlit run dashboard.py
```

**3. Simulate an attack** (optional, for testing):
```bash
python attack_sim.py
```

Open `http://localhost:8501` in your browser to view the dashboard.

## Configuration

Edit `config.py` to tune detection settings:

| Setting | Default | Description |
|---------|---------|-------------|
| `MAX_PACKETS` | 10000 | Max packets retained in DB |
| `ENTROPY_THRESHOLD` | 3.0 | Anomaly detection sensitivity |
| `ENTROPY_WINDOW` | 500 | Packets window for entropy calc |
| `BATCH_SIZE` | 50 | Packets per DB write batch |
| `GRAPH_LIMIT` | 200 | Max nodes in network graph |

## Project Structure

```
NIS-Project/
├── sniffer.py          # Packet capture and DB storage
├── anomaly_detector.py # Entropy-based anomaly detection
├── dashboard.py        # Streamlit visualization dashboard
├── attack_sim.py       # Attack traffic simulator
├── config.py           # Configuration constants
├── requirements.txt    # Python dependencies
└── lib/                # Frontend JS libraries (vis-network, tom-select)
```

## Notes

- Requires administrator/root privileges to capture raw packets
- `traffic.db` is excluded from version control (generated at runtime)
- Tested on Windows and Linux
