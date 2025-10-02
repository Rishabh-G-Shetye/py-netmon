# sniffer.py
import pyshark
import netifaces
import subprocess
import ipaddress
import requests
from datetime import datetime


class Pckt:
    def __init__(
        self,
        time_stamp: str = '',
        ipsrc: str = '',
        ipdst: str = '',
        srcport: str = '',
        dstport: str = '',
        transport_layer: str = '',
        highest_layer: str = ''
    ):
        self.time_stamp = time_stamp
        self.ipsrc = ipsrc
        self.ipdst = ipdst
        self.srcport = srcport
        self.dstport = dstport
        self.transport_layer = transport_layer
        self.highest_layer = highest_layer


class ApiServer:
    def __init__(self, ip: str, port: str):
        self.ip = ip
        self.port = port


# Use localhost for dev
server = ApiServer(ip='127.0.0.1', port='5000')

# Adjust TSHARK_PATH if needed
TSHARK_PATH = r"C:\Program Files\Wireshark\\tshark.exe"

# Find friendly interface name and corresponding NPF device
friendly_name = netifaces.gateways()['default'][netifaces.AF_INET][1]
interfaces = subprocess.check_output([TSHARK_PATH, "-D"]).decode().splitlines()

device = None
for line in interfaces:
    if friendly_name in line:
        parts = line.split()
        if len(parts) > 1:
            device = parts[1]  # \Device\NPF_{GUID}
        else:
            device = parts[0]
        break

if not device:
    raise ValueError(f"No matching device found for {friendly_name}")

print("Using device:", device)
capture = pyshark.LiveCapture(interface=device)


def is_api_server(packet, server: ApiServer) -> bool:
    if hasattr(packet, 'ip'):
        try:
            return packet.ip.src == server.ip or packet.ip.dst == server.ip
        except Exception:
            return False
    return False


def is_private_ip(ip_address: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_address)
        return ip.is_private
    except Exception:
        return False

def report(message: Pckt):
    payload = message.__dict__
    try:
        resp = requests.post(
            'http://127.0.0.1:5000/report',
            json=payload,
            timeout=3
        )
        if resp.status_code != 200:
            print("Server error:", resp.status_code, resp.text)
    except requests.exceptions.RequestException as e:
        print("Failed to send to local server:", e)


def filter_packet(packet):
    # Skip if packet is to/from server (optional)
    if is_api_server(packet, server):
        return None

    try:
        # Handle ICMP
        if hasattr(packet, 'icmp'):
            dg = Pckt()
            dg.ipdst = getattr(packet.ip, 'dst', '')
            dg.ipsrc = getattr(packet.ip, 'src', '')
            dg.highest_layer = packet.highest_layer
            dg.time_stamp = packet.sniff_time.isoformat()
            report(dg)
            return

        # Handle TCP/UDP
        if packet.transport_layer in ['TCP', 'UDP']:
            if hasattr(packet, 'ipv6'):
                return None
            if hasattr(packet, 'ip'):
                #if is_private_ip(packet.ip.src) and is_private_ip(packet.ip.dst):
                    dg = Pckt()
                    dg.ipsrc = packet.ip.src
                    dg.ipdst = packet.ip.dst
                    dg.time_stamp = packet.sniff_time.isoformat()
                    dg.highest_layer = packet.highest_layer
                    dg.transport_layer = packet.transport_layer

                    if hasattr(packet, 'udp'):
                        dg.srcport = packet.udp.srcport
                        dg.dstport = packet.udp.dstport
                    if hasattr(packet, 'tcp'):
                        dg.srcport = packet.tcp.srcport
                        dg.dstport = packet.tcp.dstport

                    report(dg)
    except Exception as e:
        print("Filter error:", e)


# Main loop
for pkt in capture.sniff_continuously():
    filter_packet(pkt)
