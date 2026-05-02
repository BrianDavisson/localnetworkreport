import platform
import socket
import uuid
import datetime
import subprocess
import re
import ipaddress
import concurrent.futures
import psutil
from flask import Flask, jsonify, render_template_string

app = Flask(__name__)


def get_local_ip():
    """Resolve the active local IP in a cross-platform way."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # No traffic is sent; this only asks the OS which interface it would use.
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except OSError:
        return socket.gethostbyname(socket.gethostname())
    finally:
        sock.close()


def parse_arp_output(output):
    """Parse arp command output for both Windows and Linux-like formats."""
    devices = []
    seen_ips = set()
    ip_pattern = r"(\d{1,3}(?:\.\d{1,3}){3})"
    mac_pattern = r"((?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2})"

    for line in output.splitlines():
        ip_match = re.search(ip_pattern, line)
        mac_match = re.search(mac_pattern, line)
        if not ip_match or not mac_match:
            continue

        ip_addr = ip_match.group(1)
        mac_addr = mac_match.group(1).replace("-", ":").lower()
        if ip_addr in seen_ips:
            continue
        seen_ips.add(ip_addr)
        devices.append({"ip": ip_addr, "mac": mac_addr})

    return devices


def get_local_network():
    """Determine the active local IPv4 network."""
    local_ip = get_local_ip()
    local_addr = ipaddress.ip_address(local_ip)

    for _iface_name, addresses in psutil.net_if_addrs().items():
        for addr in addresses:
            if addr.family != socket.AF_INET:
                continue
            if addr.address != local_ip or not addr.netmask:
                continue
            try:
                return ipaddress.ip_network(f"{addr.address}/{addr.netmask}", strict=False)
            except ValueError:
                break

    # Fallback for environments where interface netmask resolution is unavailable.
    return ipaddress.ip_network(f"{local_addr}/24", strict=False)


def ping_host(ip_addr):
    """Send a single ICMP echo request for ARP cache warm-up."""
    if platform.system().lower().startswith("win"):
        command = ["ping", "-n", "1", "-w", "250", ip_addr]
    else:
        command = ["ping", "-c", "1", "-W", "1", ip_addr]

    completed = subprocess.run(
        command,
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return completed.returncode == 0


def warmup_arp_cache():
    """Probe local hosts so they appear in ARP output."""
    local_ip = get_local_ip()
    network = get_local_network()

    hosts = [str(host) for host in network.hosts() if str(host) != local_ip]
    # Keep scan duration predictable on very large subnets.
    hosts = hosts[:254]

    with concurrent.futures.ThreadPoolExecutor(max_workers=64) as executor:
        list(executor.map(ping_host, hosts))


def scan_network_via_arp(force_refresh=False):
    """Fallback network discovery that works without raw packet access."""
    if force_refresh:
        warmup_arp_cache()

    try:
        completed = subprocess.run(
            ["arp", "-a"],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return [], "ARP fallback (command unavailable)"

    return parse_arp_output(completed.stdout), "ARP fallback"

def get_pc_data():
    """Gather local system information."""
    return {
        "PC Name": platform.node(),
        "OS": f"{platform.system()} {platform.release()}",
        "Local IP": get_local_ip(),
        "MAC Address": ':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff) for ele in range(0, 8*6, 8)][::-1]),
        "Machine Time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Processor": platform.processor(),
        "RAM": f"{round(psutil.virtual_memory().total / (1024**3), 2)} GB"
    }

def scan_network():
    """Scan the local network and degrade gracefully on restricted platforms."""
    # On Windows, prefer command-based ARP parsing to avoid layer-2 driver requirements.
    if platform.system().lower().startswith("win"):
        devices, _source = scan_network_via_arp(force_refresh=True)
        return devices, "ARP fallback + ping sweep"

    local_ip = get_local_ip()
    network_prefix = ".".join(local_ip.split(".")[:3])
    target_ip = f"{network_prefix}.1/24"

    try:
        from scapy.all import ARP, Ether, srp

        arp = ARP(pdst=target_ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        result = srp(packet, timeout=3, verbose=0)[0]

        devices = []
        for _sent, received in result:
            devices.append({"ip": received.psrc, "mac": received.hwsrc})
        if devices:
            return devices, "Scapy scan"
    except Exception:
        pass

    devices, _source = scan_network_via_arp(force_refresh=True)
    return devices, "ARP fallback + ping sweep"

# HTML Template
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Network Dashboard</title>
    <style>
        body { font-family: sans-serif; margin: 40px; background: #f4f4f9; }
        .card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #007bff; color: white; }
    </style>
</head>
<body>
    <h1>💻 Local PC Data</h1>
    <div class="card">
        <table>
            {% for key, value in pc_info.items() %}
            <tr><th>{{ key }}</th><td>{{ value }}</td></tr>
            {% endfor %}
        </table>
    </div>

    <h1>🌐 Devices on Network</h1>
    <div class="card">
        <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 12px; gap: 12px;">
            <p id="scan-source" style="margin: 0; color: #555; font-size: 14px;"><strong>Scan Source:</strong> {{ scan_source }}</p>
            <button id="rescan-btn" type="button" style="border: none; background: #007bff; color: #fff; padding: 8px 14px; border-radius: 6px; cursor: pointer; font-size: 14px;">Rescan</button>
        </div>
        <table>
            <tr><th>IP Address</th><th>MAC Address</th></tr>
            <tbody id="devices-body">
                {% for device in devices %}
                <tr><td>{{ device.ip }}</td><td>{{ device.mac }}</td></tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
    <script>
        const rescanButton = document.getElementById("rescan-btn");
        const devicesBody = document.getElementById("devices-body");
        const scanSource = document.getElementById("scan-source");

        function renderNoResults(message) {
            devicesBody.innerHTML = `<tr><td colspan="2">${message}</td></tr>`;
        }

        function renderDevices(devices) {
            if (!devices.length) {
                renderNoResults("No devices found.");
                return;
            }

            devicesBody.innerHTML = devices
                .map((device) => `<tr><td>${device.ip}</td><td>${device.mac}</td></tr>`)
                .join("");
        }

        async function rescanNetwork() {
            rescanButton.disabled = true;
            rescanButton.textContent = "Scanning...";
            scanSource.innerHTML = "<strong>Scan Source:</strong> Scanning...";
            renderNoResults("Rescanning network...");

            try {
                const response = await fetch("/scan", { method: "GET" });
                if (!response.ok) {
                    throw new Error("Scan request failed");
                }

                const data = await response.json();
                renderDevices(data.devices || []);
                scanSource.innerHTML = `<strong>Scan Source:</strong> ${data.scan_source || "Unknown"}`;
            } catch (_err) {
                renderNoResults("Rescan failed. Please try again.");
                scanSource.innerHTML = "<strong>Scan Source:</strong> Error";
            } finally {
                rescanButton.disabled = false;
                rescanButton.textContent = "Rescan";
            }
        }

        rescanButton.addEventListener("click", rescanNetwork);
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    pc_info = get_pc_data()
    devices, scan_source = scan_network()
    return render_template_string(
        HTML_TEMPLATE,
        pc_info=pc_info,
        devices=devices,
        scan_source=scan_source,
    )


@app.route('/scan')
def scan_endpoint():
    devices, scan_source = scan_network()
    return jsonify({"devices": devices, "scan_source": scan_source})

if __name__ == '__main__':
    app.run(debug=True, port=5000)