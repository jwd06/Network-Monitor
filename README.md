# Network Monitor

A lightweight Python tool that monitors active network connections in real time, logs traffic snapshots, and detects sudden spikes in activity.

## Features

- Displays active TCP/UDP connections grouped by process, IP, and port
- Logs periodic snapshots to a `.jsonl` file
- Detects traffic spikes (new connections or sudden multiplier increases)
- `reader.py` aggregates and summarizes historical log data

## Requirements

- Python 3.8+
- macOS or Linux (uses `psutil.net_connections`, may require root on some systems)

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

**Start monitoring:**
```bash
sudo python network_monitor.py
```

Displays the top 50 active connections, then enters a live loop that refreshes every 5 seconds, prints top apps/IPs/ports, and alerts on spikes. Press `Ctrl+C` to stop.

**Analyze logs:**
```bash
python reader.py
```

Reads `log_data_entry.jsonl` and prints aggregated top apps, IPs, and ports over the full logged time range.

## Output

`network_monitor.py` appends one JSON line per snapshot to `log_data_entry.jsonl`:

```json
{"Timestamp": "2026-01-26T18:41:00", "Top apps": [["Chrome", 12], ...], "Top IPs": [...], "Top ports": [...]}
```

## Notes

- `sudo` is required on macOS to read connections from all processes
- `log_data_entry.jsonl` is excluded from version control via `.gitignore`
