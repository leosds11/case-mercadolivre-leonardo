from scapy.all import sniff, IP
from collections import defaultdict
import json
import socket
import sqlite3
import signal
import sys

class TrafficAnalyzer:
    def __init__(self):
        self.packet_count = 0
        self.protocol_counts = defaultdict(int)
        self.ip_src_counts = defaultdict(int)
        self.ip_dst_counts = defaultdict(int)
        self.ip_to_hostname = {}
        self.conn = sqlite3.connect('traffic_analyzer.db')
        self.create_tables()
    
    def create_tables(self):
        with self.conn:
            self.conn.execute('''
                CREATE TABLE IF NOT EXISTS packets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_src TEXT,
                    ip_dst TEXT,
                    protocol INTEGER
                )
            ''')
    
    def resolve_hostname(self, ip):
        if ip in self.ip_to_hostname:
            return self.ip_to_hostname[ip]
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except socket.herror:
            hostname = ip
        self.ip_to_hostname[ip] = hostname
        return hostname
    
    def packet_callback(self, packet):
        try:
            if packet.haslayer(IP):
                ip_src = packet[IP].src
                ip_dst = packet[IP].dst
                protocol = packet[IP].proto
                self.packet_count += 1
                self.protocol_counts[protocol] += 1
                self.ip_src_counts[ip_src] += 1
                self.ip_dst_counts[ip_dst] += 1
                print(f"Pacote capturado: IP origem {ip_src}, IP destino {ip_dst}, Protocolo {protocol}")
                self.store_packet(ip_src, ip_dst, protocol)
        except IndexError:
            pass
    
    def store_packet(self, ip_src, ip_dst, protocol):
        with self.conn:
            self.conn.execute('''
                INSERT INTO packets (ip_src, ip_dst, protocol)
                VALUES (?, ?, ?)
            ''', (ip_src, ip_dst, protocol))
    
    def generate_report(self):
        top_src = sorted(self.ip_src_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        top_dst = sorted(self.ip_dst_counts.items(), key=lambda x: x[1], reverse=True)[:5]

        top_src_hosts = [(ip, self.resolve_hostname(ip)) for ip, count in top_src]
        top_dst_hosts = [(ip, self.resolve_hostname(ip)) for ip, count in top_dst]

        protocol_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
        protocol_counts_named = {protocol_map.get(proto, proto): count for proto, count in self.protocol_counts.items()}

        report = {
            'Total de Pacotes': self.packet_count,
            'Contagem por Protocolo': protocol_counts_named,
            'Top 5 IPs de Origem': top_src_hosts,
            'Top 5 IPs de Destino': top_dst_hosts
        }
        return json.dumps(report, indent=4, ensure_ascii=False)

def signal_handler(sig, frame):
    print("\nInterrupção detectada, gerando relatório...")
    print(analyzer.generate_report())
    analyzer.conn.close()  # Fechar a conexão com o banco de dados
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

analyzer = TrafficAnalyzer()
print("Capturando pacotes... Pressione Ctrl+C para interromper.")
# Substitua "INTERFACE_CORRETA" pela sua interface WiFi identificada
sniff(iface="INTERFACE_CORRETA", prn=analyzer.packet_callback)
