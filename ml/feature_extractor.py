#!/usr/bin/env python3
"""
Extraction de caractéristiques pour le ML
Transforme les paquets réseau en vecteurs numériques
Celestis_IA - Module ML
"""

import numpy as np
from typing import Dict, List, Any, Tuple
from collections import Counter
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS
from scapy.packet import Raw
import hashlib

class NetworkFeatureExtractor:
    """Extrait des features numériques des paquets réseau"""
    
    def __init__(self):
        # Ports connus (services standard)
        self.well_known_ports = {
            20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 123, 
            143, 161, 194, 443, 465, 587, 993, 995, 3306, 3389, 
            5432, 5900, 8080, 8443
        }
        
        # Protocoles
        self.protocol_map = {
            'TCP': 0, 'UDP': 1, 'ICMP': 2, 'DNS': 3, 'OTHER': 4
        }
        
        # Flags TCP
        self.tcp_flags = ['F', 'S', 'R', 'P', 'A', 'U', 'E', 'C']
        
    def extract_packet_features(self, packet: Any) -> np.ndarray:
        """
        Extrait les features d'un paquet individuel
        
        Returns:
            Array numpy de 50+ features
        """
        features = []
        
        # === FEATURES DE BASE ===
        # 1. Taille du paquet
        features.append(len(packet))
        
        # 2. Protocole (one-hot encoding)
        protocol = self._get_protocol(packet)
        for proto in ['TCP', 'UDP', 'ICMP', 'DNS', 'OTHER']:
            features.append(1 if protocol == proto else 0)
        
        # 3-4. Ports source et destination
        src_port, dst_port = self._get_ports(packet)
        features.append(src_port)
        features.append(dst_port)
        
        # 5-6. Ports bien connus (booléen)
        features.append(1 if src_port in self.well_known_ports else 0)
        features.append(1 if dst_port in self.well_known_ports else 0)
        
        # === FEATURES TCP ===
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            # 7-14. Flags TCP (8 features)
            flags_str = str(tcp.flags)
            for flag in self.tcp_flags:
                features.append(1 if flag in flags_str else 0)
            
            # 15-17. Window size, sequence, acknowledgment
            features.append(tcp.window)
            features.append(tcp.seq % 100000)  # Normalisé
            features.append(tcp.ack % 100000)
        else:
            features.extend([0] * 11)  # Padding si pas TCP
        
        # === FEATURES PAYLOAD ===
        payload_features = self._extract_payload_features(packet)
        features.extend(payload_features)  # 18-35 (18 features)
        
        # === FEATURES IP ===
        if packet.haslayer(IP):
            ip = packet[IP]
            # 36-37. TTL et longueur
            features.append(ip.ttl)
            features.append(ip.len)
            
            # 38-41. Fragments
            features.append(ip.frag)
            features.append(1 if ip.flags.MF else 0)  # More Fragments
            features.append(1 if ip.flags.DF else 0)  # Don't Fragment
            features.append(ip.id)
        else:
            features.extend([0] * 6)
        
        # === FEATURES STATISTIQUES ===
        # 42. Entropie du payload (randomness)
        entropy = self._calculate_entropy(packet)
        features.append(entropy)
        
        # 43-45. Ratio ASCII, binaire, printable
        ratios = self._get_character_ratios(packet)
        features.extend(ratios)
        
        # 46-50. Features temporelles (si disponibles)
        # Ces features seront calculées au niveau du flow
        features.extend([0] * 5)  # Placeholder
        
        return np.array(features, dtype=np.float32)
    
    def extract_flow_features(self, packets: List[Any]) -> np.ndarray:
        """
        Extrait les features d'un flux (ensemble de paquets)
        
        Returns:
            Array numpy de 85+ features
        """
        if not packets:
            return np.zeros(85, dtype=np.float32)
        
        features = []
        
        # === STATISTIQUES DE BASE ===
        # 1-5. Compteurs
        features.append(len(packets))  # Nombre de paquets
        
        sizes = [len(p) for p in packets]
        features.append(np.mean(sizes))  # Taille moyenne
        features.append(np.std(sizes))   # Écart-type
        features.append(np.min(sizes))   # Min
        features.append(np.max(sizes))   # Max
        
        # 6-10. Durée et timing
        if len(packets) > 1:
            timestamps = [float(p.time) for p in packets]
            duration = timestamps[-1] - timestamps[0]
            features.append(duration)
            
            # Inter-arrival times
            iats = np.diff(timestamps)
            features.append(np.mean(iats))
            features.append(np.std(iats))
            features.append(np.min(iats))
            features.append(np.max(iats))
        else:
            features.extend([0] * 5)
        
        # === FEATURES PROTOCOLE ===
        # 11-13. Distribution des protocoles
        protocols = [self._get_protocol(p) for p in packets]
        protocol_counts = Counter(protocols)
        
        features.append(protocol_counts.get('TCP', 0) / len(packets))
        features.append(protocol_counts.get('UDP', 0) / len(packets))
        features.append(protocol_counts.get('ICMP', 0) / len(packets))
        
        # === FEATURES TCP ===
        tcp_packets = [p for p in packets if p.haslayer(TCP)]
        if tcp_packets:
            # 14-18. Flags TCP
            syn_count = sum(1 for p in tcp_packets if 'S' in str(p[TCP].flags))
            fin_count = sum(1 for p in tcp_packets if 'F' in str(p[TCP].flags))
            rst_count = sum(1 for p in tcp_packets if 'R' in str(p[TCP].flags))
            psh_count = sum(1 for p in tcp_packets if 'P' in str(p[TCP].flags))
            ack_count = sum(1 for p in tcp_packets if 'A' in str(p[TCP].flags))
            
            features.append(syn_count / len(tcp_packets))
            features.append(fin_count / len(tcp_packets))
            features.append(rst_count / len(tcp_packets))
            features.append(psh_count / len(tcp_packets))
            features.append(ack_count / len(tcp_packets))
        else:
            features.extend([0] * 5)
        
        # === FEATURES PAYLOAD ===
        # 19-23. Statistiques de payload
        payloads = []
        for p in packets:
            if p.haslayer(Raw):
                payloads.append(len(p[Raw].load))
            else:
                payloads.append(0)
        
        features.append(np.mean(payloads))
        features.append(np.std(payloads))
        features.append(np.min(payloads))
        features.append(np.max(payloads))
        features.append(sum(1 for p in payloads if p > 0) / len(payloads))
        
        # === FEATURES AVANCÉES ===
        # 24-28. Entropie et complexité
        entropies = [self._calculate_entropy(p) for p in packets]
        features.append(np.mean(entropies))
        features.append(np.std(entropies))
        features.append(np.max(entropies))
        
        # Ratio de paquets avec haute entropie (> 7.0)
        features.append(sum(1 for e in entropies if e > 7.0) / len(entropies))
        
        # Ratio de paquets avec payload
        features.append(sum(1 for p in packets if p.haslayer(Raw)) / len(packets))
        
        # === FEATURES PORTS ===
        # 29-33. Analyse des ports
        src_ports = set()
        dst_ports = set()
        for p in packets:
            sp, dp = self._get_ports(p)
            if sp > 0:
                src_ports.add(sp)
            if dp > 0:
                dst_ports.add(dp)
        
        features.append(len(src_ports))  # Nombre de ports source uniques
        features.append(len(dst_ports))  # Nombre de ports dest uniques
        
        # Ratio de ports well-known
        well_known_count = sum(1 for p in dst_ports if p in self.well_known_ports)
        features.append(well_known_count / max(len(dst_ports), 1))
        
        # Port le plus fréquent
        if dst_ports:
            port_counts = Counter([self._get_ports(p)[1] for p in packets])
            most_common_port = port_counts.most_common(1)[0][0]
            features.append(most_common_port)
            features.append(port_counts[most_common_port] / len(packets))
        else:
            features.extend([0, 0])
        
        # === FEATURES BIDIRECTIONNELLES ===
        # 34-38. Analyse forward/backward
        forward_packets = []
        backward_packets = []
        
        if packets and packets[0].haslayer(IP):
            src_ip = packets[0][IP].src
            for p in packets:
                if p.haslayer(IP):
                    if p[IP].src == src_ip:
                        forward_packets.append(p)
                    else:
                        backward_packets.append(p)
            
            # Ratios
            features.append(len(forward_packets) / len(packets))
            features.append(len(backward_packets) / len(packets))
            
            # Tailles moyennes
            if forward_packets:
                features.append(np.mean([len(p) for p in forward_packets]))
            else:
                features.append(0)
            
            if backward_packets:
                features.append(np.mean([len(p) for p in backward_packets]))
            else:
                features.append(0)
            
            # Ratio de bytes
            total_bytes = sum(len(p) for p in packets)
            forward_bytes = sum(len(p) for p in forward_packets)
            features.append(forward_bytes / max(total_bytes, 1))
        else:
            features.extend([0] * 5)
        
        # === FEATURES COMPORTEMENTALES ===
        # 39-43. Patterns suspects
        
        # Scan de ports (beaucoup de ports différents)
        features.append(1 if len(dst_ports) > 20 else 0)
        
        # Burst (beaucoup de paquets en peu de temps)
        if len(packets) > 1:
            timestamps = [float(p.time) for p in packets]
            duration = timestamps[-1] - timestamps[0]
            pps = len(packets) / max(duration, 0.001)  # Packets per second
            features.append(min(pps / 1000, 1.0))  # Normalisé
        else:
            features.append(0)
        
        # Paquets de taille inhabituelle
        unusual_size_count = sum(1 for s in sizes if s < 40 or s > 1400)
        features.append(unusual_size_count / len(packets))
        
        # Flags TCP suspects (SYN sans ACK, etc.)
        if tcp_packets:
            syn_no_ack = sum(1 for p in tcp_packets 
                           if 'S' in str(p[TCP].flags) and 'A' not in str(p[TCP].flags))
            features.append(syn_no_ack / len(tcp_packets))
        else:
            features.append(0)
        
        # Ratio de RST (connexions refusées)
        if tcp_packets:
            rst_ratio = sum(1 for p in tcp_packets if 'R' in str(p[TCP].flags)) / len(tcp_packets)
            features.append(rst_ratio)
        else:
            features.append(0)
        
        # Padding pour atteindre 85 features
        while len(features) < 85:
            features.append(0)
        
        return np.array(features[:85], dtype=np.float32)
    
    def _get_protocol(self, packet: Any) -> str:
        """Détermine le protocole du paquet"""
        if packet.haslayer(TCP):
            return 'TCP'
        elif packet.haslayer(UDP):
            if packet.haslayer(DNS):
                return 'DNS'
            return 'UDP'
        elif packet.haslayer(ICMP):
            return 'ICMP'
        return 'OTHER'
    
    def _get_ports(self, packet: Any) -> Tuple[int, int]:
        """Extrait les ports source et destination"""
        src_port, dst_port = 0, 0
        
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        
        return src_port, dst_port
    
    def _extract_payload_features(self, packet: Any) -> List[float]:
        """Extrait 18 features du payload"""
        features = []
        
        if packet.haslayer(Raw):
            payload = bytes(packet[Raw].load)
            
            # 1. Taille du payload
            features.append(len(payload))
            
            # 2-9. Comptage de caractères spéciaux
            features.append(payload.count(b'\x00') / max(len(payload), 1))  # Null bytes
            features.append(payload.count(b'\n') / max(len(payload), 1))   # Newlines
            features.append(payload.count(b'\r') / max(len(payload), 1))   # Carriage returns
            features.append(payload.count(b' ') / max(len(payload), 1))    # Spaces
            
            # Caractères suspects
            features.append(payload.count(b'%') / max(len(payload), 1))    # URL encoding
            features.append(payload.count(b'<') / max(len(payload), 1))    # HTML/XML
            features.append(payload.count(b'>') / max(len(payload), 1))
            features.append(payload.count(b';') / max(len(payload), 1))    # SQL/Commands
            
            # 10-12. Distribution des bytes
            byte_counts = Counter(payload)
            most_common_byte_freq = byte_counts.most_common(1)[0][1] / len(payload) if payload else 0
            features.append(most_common_byte_freq)
            features.append(len(byte_counts) / 256.0)  # Diversité des bytes
            
            # Ratio de bytes haute/basse valeur
            high_bytes = sum(1 for b in payload if b > 127)
            features.append(high_bytes / max(len(payload), 1))
            
            # 13-15. Patterns de strings
            try:
                payload_str = payload.decode('utf-8', errors='ignore')
                features.append(1 if 'http' in payload_str.lower() else 0)
                features.append(1 if 'select' in payload_str.lower() or 'union' in payload_str.lower() else 0)
                features.append(1 if '<script' in payload_str.lower() else 0)
            except:
                features.extend([0, 0, 0])
            
            # 16-18. Longueur des tokens
            tokens = payload.split(b' ')
            if tokens:
                token_lens = [len(t) for t in tokens]
                features.append(np.mean(token_lens))
                features.append(np.max(token_lens))
                features.append(len(tokens))
            else:
                features.extend([0, 0, 0])
        else:
            # Pas de payload
            features.extend([0] * 18)
        
        return features
    
    def _calculate_entropy(self, packet: Any) -> float:
        """Calcule l'entropie de Shannon du paquet"""
        data = bytes(packet)
        if len(data) == 0:
            return 0.0
        
        byte_counts = Counter(data)
        entropy = 0.0
        
        for count in byte_counts.values():
            p = count / len(data)
            if p > 0:
                entropy -= p * np.log2(p)
        
        return entropy
    
    def _get_character_ratios(self, packet: Any) -> List[float]:
        """Calcule les ratios de types de caractères"""
        data = bytes(packet)
        if len(data) == 0:
            return [0.0, 0.0, 0.0]
        
        ascii_count = sum(1 for b in data if 32 <= b < 127)
        binary_count = sum(1 for b in data if b < 32 or b >= 127)
        printable_count = sum(1 for b in data if 32 <= b < 127 or b in [9, 10, 13])
        
        return [
            ascii_count / len(data),
            binary_count / len(data),
            printable_count / len(data)
        ]
