# NetFlowLite
**Network Traffic Analysis Engine — Day 10/100**

NetFlowLite is an offline-first Python CLI for summarizing authorized packet captures (`.pcap`, `.pcapng`) and deterministic JSON lab records. It aggregates protocol, endpoint, port, and conversation statistics; flags configurable traffic patterns for analyst review; and exports JSON/CSV reports.

**Scope:** It does not sniff live interfaces, transmit packets, scan hosts, or treat a heuristic as proof of compromise. Only analyze captures you own or are authorized to inspect.

## Features
- Offline PCAP/PCAPNG parsing through Scapy
- Packet/byte counts, time span, protocol distribution, top endpoints/ports, conversation summaries
- Transparent heuristics for destination-port fan-out, source packet bursts, and service-source concentration
- Configurable thresholds, JSON and CSV exports, helpful errors
- Synthetic sample data and unit tests that do not require Scapy

## Install
Python 3.10+ is recommended.

### Windows PowerShell
```powershell
git clone https://github.com/devanshshukla-3004/NetFlowLite.git
cd NetFlowLite
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python netflowlite.py analyze samples/lab_capture.json --json reports/demo-report.json --csv reports/demo-flows.csv
```
If activation is blocked, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` in that terminal, or use `.venv\Scripts\python.exe` directly.

### Linux / Kali / macOS
```bash
git clone https://github.com/devanshshukla-3004/NetFlowLite.git
cd NetFlowLite
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python netflowlite.py analyze samples/lab_capture.json --json reports/demo-report.json --csv reports/demo-flows.csv
```

Analyze a capture you are authorized to inspect:
```bash
python netflowlite.py analyze path/to/capture.pcap --json reports/report.json --csv reports/flows.csv
```
Scapy's official offline PCAP reading documentation: https://scapy.readthedocs.io/en/stable/usage.html

## CLI options
```text
python netflowlite.py analyze INPUT
  --json PATH                JSON report path
  --csv PATH                 Conversation CSV path
  --port-fanout N            Flag a source reaching N unique destination ports (default 12)
  --source-packet-limit N    Flag a source appearing in N packets (default 1000)
  --service-source-limit N   Flag a common service port contacted by N unique sources (default 20)
```

## Detection caveats
Port fan-out can be caused by legitimate administrative activity. High packet volume is not inherently malicious. Common service concentration may be normal. Findings contain evidence and suggested triage steps; validate them against your environment's baseline. The tool summarizes packet metadata; it does not decrypt TLS, inspect application payloads, or reconstruct full sessions.

## Tests
```bash
python -m unittest discover -s tests -v
```
The bundled JSON capture is synthetic, not a real network capture.

## Layout
```text
NetFlowLite/
├── netflowlite.py
├── netflowlite/ (capture, analysis, detections, reporting)
├── samples/lab_capture.json
├── tests/test_netflowlite.py
├── reports/
├── requirements.txt
└── README.md
```

**Devansh Shukla** · https://github.com/devanshshukla-3004
