import socket
import time

# Konfiguration
TARGET_MAC = "b0:6e:bf:c7:2c:29"  # MAC-Adresse für Wake-on-LAN
MONITORED_IPS = ["192.168.1.200", "192.168.1.75"]  # Ziel-IPs, die überwacht werden
ROUTER_IP = "192.168.1.1"  # Router-IP, die ignoriert wird
PACKET_SIZE = 65565
INTERFACE = "eth0"  # Ihre Netzwerkschnittstelle
MIN_WOL_INTERVAL = 5  # Minimaler Zeitabstand zwischen WoL-Paketen

def create_magic_packet(mac_addr):
    """Erstellt ein Wake-on-LAN Magic Packet"""
    mac_bytes = bytes.fromhex(mac_addr.replace(':', ''))
    return b'\xff' * 6 + mac_bytes * 16

def send_wol(mac_addr):
    """Sendet Wake-on-LAN Packet"""
    magic_packet = create_magic_packet(mac_addr)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try:
            sock.sendto(magic_packet, ('255.255.255.255', 9))
            print("Wake-on-LAN Packet gesendet an {}".format(mac_addr))
        except Exception as e:
            print("Fehler beim Senden des WoL-Pakets: {}".format(e))

def monitor_network():
    """Überwacht das Netzwerk auf relevante ARP-Anfragen"""
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        sock.bind((INTERFACE, 0))
    except PermissionError:
        print("Fehler: Root-Rechte erforderlich!")
        return
    except Exception as e:
        print("Fehler beim Erstellen des Sockets: {}".format(e))
        return

    print("Netzwerküberwachung gestartet...")
    print("Überwache ARP-Anfragen für Ziel-IPs {} (Router-IP {} wird ignoriert)".format(", ".join(MONITORED_IPS), ROUTER_IP))

    last_wol_time = 0

    try:
        while True:
            try:
                packet = sock.recvfrom(PACKET_SIZE)[0]

                # Ethernet-Header
                eth_length = 14
                if len(packet) < eth_length + 28:  # ARP hat mindestens 28 Bytes
                    continue

                eth_protocol = int.from_bytes(packet[12:14], "big")

                # Prüfen, ob es ein ARP-Paket ist
                if eth_protocol == 0x0806:  # ARP
                    arp_header = packet[eth_length:eth_length + 28]
                    src_ip = socket.inet_ntoa(arp_header[14:18])  # Absender-IP
                    dst_ip = socket.inet_ntoa(arp_header[24:28])  # Ziel-IP

                    # Prüfen, ob Ziel-IP überwacht wird und Absender nicht die Router-IP ist
                    if dst_ip in MONITORED_IPS and src_ip != ROUTER_IP:
                        current_time = time.time()
                        if current_time - last_wol_time >= MIN_WOL_INTERVAL:
                            print("Relevante ARP-Anfrage erkannt:")
                            print("  Von: {} -> An: {}".format(src_ip, dst_ip))
                            send_wol(TARGET_MAC)
                            last_wol_time = current_time
                    else:
                        print("ARP-Anfrage ignoriert: Absender {}, Ziel {}".format(src_ip, dst_ip))

            except Exception as e:
                print("Fehler beim Verarbeiten eines Pakets: {}".format(e))
                continue

    except KeyboardInterrupt:
        print("\nÜberwachung beendet.")
    finally:
        sock.close()

if __name__ == "__main__":
    monitor_network()
