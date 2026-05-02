# LocalNetworkReport

LocalNetworkReport is a lightweight Flask web application that displays local machine information and discovers devices on the same local network.

## Application Functionality

The app provides a browser dashboard with two sections:

1. Local PC Data
- PC name
- Operating system
- Local IP address
- MAC address
- Current machine time
- Processor string
- Total RAM

2. Devices on Network
- Discovered IP addresses and MAC addresses
- Current scan source status (for example: `Scapy scan` or `ARP fallback + ping sweep`)
- `Rescan` button that clears visible results and runs a fresh scan

## Programming / Technical Design

### Stack
- Python 3
- Flask (web server and routing)
- psutil (host/network interface details)
- Scapy (best-effort packet-based network scan on supported systems)
- Standard library modules (`socket`, `subprocess`, `ipaddress`, `concurrent.futures`, etc.)

### Runtime Flow
- `GET /`
  - Collects local machine data.
  - Performs device discovery.
  - Renders dashboard HTML.
- `GET /scan`
  - Performs device discovery.
  - Returns JSON for frontend rescan updates.

### Device Discovery Strategy
The app uses a resilient multi-path approach:

1. Windows default path
- Uses ARP-table based discovery with a ping sweep warm-up.
- Avoids hard dependency on packet-capture drivers.

2. Non-Windows preferred path
- Attempts Scapy L2 ARP scan first.
- If unavailable or unsuccessful, falls back to ARP-table + ping sweep.

3. ARP fallback
- Executes `arp -a`.
- Parses output in both Windows and Linux-like formats.

## Extensibility

The project is intentionally small and easy to extend.

### Suggested extension points
- Add hostnames via reverse DNS lookups for each discovered IP.
- Add vendor/OUI lookup for MAC addresses.
- Add scan history persistence (SQLite/JSON) and change tracking.
- Add subnet selection UI (manual CIDR input).
- Add API auth and user sessions for shared/internal deployment.
- Split inline HTML/JS into templates and static assets for maintainability.
- Add background task queue for long scans (Celery/RQ) and progress updates.

### Code structure opportunities
- Move scan logic into a dedicated module (for example `scanner.py`).
- Introduce service classes for `SystemInfoService` and `NetworkScanService`.
- Add unit tests for parser and subnet logic.

## Limitations

- ARP-based discovery only finds devices that respond and are visible on the local Layer-2 segment.
- Networks with client isolation, VLAN segmentation, or strict firewall policies may hide devices.
- Very large subnets are capped for scan duration predictability (host probing is limited).
- Scapy path on Windows typically requires Npcap/WinPcap for full Layer-2 behavior.
- MAC addresses are generally only obtainable on local broadcast domains, not routed networks.
- Current UI is server-rendered with inline CSS/JS and no authentication.

## Run Locally

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Start the app:
```bash
python app.py
```

3. Open:
- `http://127.0.0.1:5000`

## Repository Notes

- Python cache files are excluded via `.gitignore`.
- The repository currently tracks the `master` branch.
