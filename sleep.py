#!/usr/bin/env python3

import socket
import time
import os
import subprocess

# Konfiguration
MONITORED_IPS = ["192.168.1.200", "192.168.1.75"]  # Ziel-IPs, die überwacht werden
ROUTER_IP = "192.168.1.1"  # Router-IP, die ignoriert wird
PACKET_SIZE = 65565
INTERFACE = "eth0"  # Ihre Netzwerkschnittstelle
IDLE_THRESHOLD = 10  # Anzahl der inaktiven Zyklen, bevor Standby eingeleitet wird
MIN_IDLE_TIME = 30  # Minimalzeit (Sekunden) zwischen Standby-Checks
LOAD_THRESHOLD = 0.7  # Maximale Last für Standby
CONTAINER_ID = "116"  # TrueNAS-Container-ID

def check_load():
    """Prüft die Systemlast"""
    with open("/proc/loadavg") as f:
        return float(f.read().split()[1])

def check_active_connections():
    """Prüft SMB- und NFS-Verbindungen im Container"""
    try:
        smb_output = subprocess.check_output(
            ["pct", "exec", CONTAINER_ID, "smbstatus -b | grep -c 'active'"], stderr=subprocess.DEVNULL, text=True
        ).strip()
        nfs_output = subprocess.check_output(
            ["pct", "exec", CONTAINER_ID, "showmount -a | grep -c ."], stderr=subprocess.DEVNULL, text=True
        ).strip()
        smb_connections = int(smb_output) if smb_output.isdigit() else 0
        nfs_connections = int(nfs_output) if nfs_output.isdigit() else 0
        return smb_connections, nfs_connections
    except subprocess.CalledProcessError:
        return 0, 0

def monitor_network():
    """Überwacht Netzwerkverkehr und überprüft Leerlaufbedingungen"""
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        sock.bind((INTERFACE, 0))
    except PermissionError:
        print("Fehler: Root-Rechte erforderlich!")
        return
    except Exception as e:
        print(f"Fehler beim Erstellen des Sockets: {e}")
        return

    print("Überwachung gestartet...")
    print(f"Überwache Pakete für Ziel-IPs {', '.join(MONITORED_IPS)} (Router-IP {ROUTER_IP} wird ignoriert)")

    idle_count = 0

    try:
        while True:
            has_traffic = False
            try:
                packet = sock.recvfrom(PACKET_SIZE)[0]

                # Ethernet-Header
                eth_length = 14
                if len(packet) < eth_length + 28:  # ARP/IP hat mindestens 28 Bytes
                    continue

                eth_protocol = int.from_bytes(packet[12:14], "big")

                # Prüfen, ob es ein IP-Paket ist
                if eth_protocol == 0x0800:  # IPv4
                    ip_header = packet[eth_length:eth_length + 20]
                    src_ip = socket.inet_ntoa(ip_header[12:16])  # Absender-IP
                    dst_ip = socket.inet_ntoa(ip_header[16:20])  # Ziel-IP

                    # Prüfen, ob Ziel-IP überwacht wird und Absender nicht die Router-IP ist
                    if dst_ip in MONITORED_IPS and src_ip != ROUTER_IP:
                        print(f"Relevanter Traffic erkannt: Von {src_ip} -> An {dst_ip}")
                        has_traffic = True
                        idle_count = 0  # Traffic erkannt, Idle-Zähler zurücksetzen

            except socket.timeout:
                pass  # Keine Pakete empfangen
            except Exception as e:
                print(f"Fehler beim Verarbeiten eines Pakets: {e}")
                continue

            # Prüfen auf aktive SMB- und NFS-Verbindungen
            smb_connections, nfs_connections = check_active_connections()

            # Prüfen der Systemlast
            load_avg = check_load()
            print(f"SMB-Verbindungen: {smb_connections}, NFS-Verbindungen: {nfs_connections}, Systemlast: {load_avg:.2f}")

            # Standby-Bedingungen prüfen
            if not has_traffic and smb_connections == 0 and nfs_connections == 0 and load_avg < LOAD_THRESHOLD:
                idle_count += 1
                print(f"Keine Aktivität erkannt. Idle Count: {idle_count}/{IDLE_THRESHOLD}")
                if idle_count >= IDLE_THRESHOLD:
                    print("System wird in den Standby-Modus versetzt...")
                    os.system("systemctl suspend")
                    idle_count = 0  # Zähler nach Standby zurücksetzen
            else:
                print("Aktivität erkannt. Idle Count zurückgesetzt.")
                idle_count = 0

            time.sleep(MIN_IDLE_TIME)

    except KeyboardInterrupt:
        print("\nÜberwachung beendet.")
    finally:
        sock.close()

if __name__ == "__main__":
    monitor_network()
