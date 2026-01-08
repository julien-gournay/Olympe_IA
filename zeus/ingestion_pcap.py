#!/usr/bin/env python3
"""
Module d'ingestion et d'analyse de fichiers PCAP
Celestis_IA - Module Zeus
"""

import argparse
import json
import logging
import os
import sqlite3
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

try:
    from scapy.utils import rdpcap
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.dns import DNS
    from scapy.packet import Raw
    from scapy.layers.http import HTTPRequest, HTTPResponse
except ImportError:
    print("Erreur: Scapy n'est pas installé. Installez-le avec: pip install scapy")
    exit(1)

try:
    from threat_analyzer import ThreatAnalyzer
    THREAT_ANALYSIS_AVAILABLE = True
except ImportError:
    THREAT_ANALYSIS_AVAILABLE = False
    print("Avertissement: threat_analyzer non disponible. L'analyse de menaces sera désactivée.")


class PcapIngestion:
    """Classe pour l'ingestion et l'analyse de fichiers PCAP"""
    
    def __init__(self, db_path: str = "pcap_database.db", log_dir: str = "logs",
                 enable_yara: bool = True, yara_rules_path: str = "config/yara_rules.yar"):
        """
        Initialise le module d'ingestion
        
        Args:
            db_path: Chemin vers la base de données SQLite
            log_dir: Répertoire pour les logs
            enable_yara: Activer l'analyse YARA
            yara_rules_path: Chemin vers les règles YARA
        """
        self.db_path = Path(db_path)
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.enable_yara = enable_yara and THREAT_ANALYSIS_AVAILABLE

        self._setup_logging()
        self._init_database()
        
        # Initialiser l'analyseur de menaces si disponible
        self.yara_analyzer = None
        if self.enable_yara:
            try:
                self.yara_analyzer = ThreatAnalyzer(
                    rules_path=yara_rules_path,
                    db_path=str(self.db_path),
                    log_dir=str(self.log_dir)
                )
                self.logger.info("Analyseur de menaces initialisé")
            except Exception as e:
                self.logger.warning(f"Impossible d'initialiser l'analyseur de menaces: {e}")
                self.yara_analyzer = None

    def _setup_logging(self):
        """Configure le système de logging"""
        log_file = self.log_dir / f"ingestion_{datetime.now().strftime('%Y%m%d')}.log"
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def _init_database(self):
        """Initialise la base de données SQLite"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Table des fichiers PCAP ingérés
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS pcap_files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    filename TEXT NOT NULL UNIQUE,
                    file_path TEXT NOT NULL,
                    file_size INTEGER,
                    ingestion_date TEXT,
                    packet_count INTEGER,
                    start_time TEXT,
                    end_time TEXT,
                    duration REAL
                )
            """)
            
            # Table des paquets
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS packets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pcap_file_id INTEGER,
                    packet_number INTEGER,
                    timestamp TEXT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    protocol TEXT,
                    packet_size INTEGER,
                    payload_size INTEGER,
                    flags TEXT,
                    FOREIGN KEY (pcap_file_id) REFERENCES pcap_files(id)
                )
            """)
            
            # Table des statistiques
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS statistics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pcap_file_id INTEGER,
                    metric_name TEXT,
                    metric_value TEXT,
                    FOREIGN KEY (pcap_file_id) REFERENCES pcap_files(id)
                )
            """)
            
            # Index pour améliorer les performances
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_packets_pcap_file 
                ON packets(pcap_file_id)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_packets_ips 
                ON packets(src_ip, dst_ip)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_packets_protocol 
                ON packets(protocol)
            """)
            
            conn.commit()
            self.logger.info(f"Base de données initialisée: {self.db_path}")
    
    def ingest_pcap(self, pcap_file: str, analyze: bool = True) -> Optional[int]:
        """
        Ingère un fichier PCAP dans la base de données
        
        Args:
            pcap_file: Chemin vers le fichier PCAP
            analyze: Si True, effectue une analyse complète
            
        Returns:
            ID du fichier PCAP dans la base de données ou None si erreur
        """
        pcap_path = Path(pcap_file)
        
        if not pcap_path.exists():
            self.logger.error(f"Fichier introuvable: {pcap_file}")
            return None
            
        self.logger.info(f"Début de l'ingestion: {pcap_file}")
        
        try:
            # Charger le fichier PCAP
            packets = rdpcap(str(pcap_path))
            packet_count = len(packets)
            
            if packet_count == 0:
                self.logger.warning(f"Aucun paquet dans le fichier: {pcap_file}")
                return None
            
            self.logger.info(f"Paquets chargés: {packet_count}")
            
            # Calculer les métadonnées temporelles
            start_time = datetime.fromtimestamp(float(packets[0].time))
            end_time = datetime.fromtimestamp(float(packets[-1].time))
            duration = (end_time - start_time).total_seconds()
            
            # Insérer le fichier PCAP dans la base de données
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Vérifier si le fichier existe déjà
                cursor.execute("SELECT id FROM pcap_files WHERE filename = ?", (pcap_path.name,))
                existing = cursor.fetchone()
                if existing:
                    # Si c'est training_ai.pcap, supprimer l'ancienne entrée pour la remplacer
                    if pcap_path.name == "training_ai.pcap":
                        self.logger.info(f"Fichier training_ai.pcap détecté - suppression de l'ancienne ingestion (ID: {existing[0]})")
                        # Supprimer les paquets associés
                        cursor.execute("DELETE FROM packets WHERE pcap_file_id = ?", (existing[0],))
                        # Supprimer les statistiques associées
                        cursor.execute("DELETE FROM statistics WHERE pcap_file_id = ?", (existing[0],))
                        # Supprimer le fichier PCAP
                        cursor.execute("DELETE FROM pcap_files WHERE id = ?", (existing[0],))
                        self.logger.info("Ancienne ingestion supprimée, nouvelle ingestion en cours...")
                    else:
                        self.logger.warning(f"Le fichier {pcap_path.name} a déjà été ingéré (ID: {existing[0]})")
                        return existing[0]
                
                cursor.execute("""
                    INSERT INTO pcap_files 
                    (filename, file_path, file_size, ingestion_date, packet_count, 
                     start_time, end_time, duration)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    pcap_path.name,
                    str(pcap_path.absolute()),
                    pcap_path.stat().st_size,
                    datetime.now().isoformat(),
                    packet_count,
                    start_time.isoformat(),
                    end_time.isoformat(),
                    duration
                ))
                
                pcap_file_id = cursor.lastrowid
                
                if analyze and pcap_file_id is not None:
                    self.logger.info("Analyse des paquets en cours...")
                    self._analyze_packets(cursor, pcap_file_id, packets)
                
                conn.commit()

            # Analyse de menaces si activée
            if self.yara_analyzer and pcap_file_id is not None:
                self.logger.info("Analyse de menaces en cours...")
                alerts = self.yara_analyzer.analyze_pcap(str(pcap_path), pcap_file_id, verbose=False)
                if alerts:
                    self.logger.warning(f"[!] {len(alerts)} alerte(s) de menace detectee(s)!")
                else:
                    self.logger.info("[OK] Aucune menace detectee")

            self.logger.info(f"Ingestion terminée. ID: {pcap_file_id}, Paquets: {packet_count}")
            return pcap_file_id
            
        except Exception as e:
            self.logger.error(f"Erreur lors de l'ingestion: {e}")
            return None
    
    def _analyze_packets(self, cursor, pcap_file_id: int, packets: Any):
        """
        Analyse les paquets et les insère dans la base de données
        
        Args:
            cursor: Curseur de la base de données
            pcap_file_id: ID du fichier PCAP
            packets: Liste des paquets Scapy (PacketList)
        """
        protocol_count = Counter()
        src_ips = set()
        dst_ips = set()
        total_size = 0
        
        for i, packet in enumerate(packets, 1):
            try:
                # Extraire les informations du paquet
                timestamp = datetime.fromtimestamp(float(packet.time)).isoformat()
                packet_size = len(packet)
                total_size += packet_size
                
                src_ip = None
                dst_ip = None
                src_port = None
                dst_port = None
                protocol = "OTHER"
                flags = None
                payload_size = 0
                
                # Analyser la couche IP
                if packet.haslayer(IP):
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    src_ips.add(src_ip)
                    dst_ips.add(dst_ip)
                
                # Analyser la couche TCP
                if packet.haslayer(TCP):
                    protocol = "TCP"
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                    flags = str(packet[TCP].flags)
                    if packet.haslayer(Raw):
                        payload_size = len(packet[Raw].load)
                
                # Analyser la couche UDP
                elif packet.haslayer(UDP):
                    protocol = "UDP"
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                    if packet.haslayer(Raw):
                        payload_size = len(packet[Raw].load)
                
                # Analyser la couche ICMP
                elif packet.haslayer(ICMP):
                    protocol = "ICMP"
                
                # Analyser DNS
                elif packet.haslayer(DNS):
                    protocol = "DNS"
                    if packet.haslayer(UDP):
                        src_port = packet[UDP].sport
                        dst_port = packet[UDP].dport
                
                protocol_count[protocol] += 1
                
                # Insérer le paquet dans la base de données
                cursor.execute("""
                    INSERT INTO packets 
                    (pcap_file_id, packet_number, timestamp, src_ip, dst_ip, 
                     src_port, dst_port, protocol, packet_size, payload_size, flags)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    pcap_file_id, i, timestamp, src_ip, dst_ip,
                    src_port, dst_port, protocol, packet_size, payload_size, flags
                ))
                
                # Afficher la progression
                if i % 1000 == 0:
                    self.logger.info(f"  Paquets analysés: {i}")
                    
            except Exception as e:
                self.logger.warning(f"Erreur lors de l'analyse du paquet {i}: {e}")
        
        # Insérer les statistiques
        stats = {
            'total_packets': len(packets),
            'unique_src_ips': len(src_ips),
            'unique_dst_ips': len(dst_ips),
            'total_bytes': total_size,
            'avg_packet_size': total_size / len(packets) if packets else 0
        }
        
        # Ajouter les statistiques de protocoles
        for protocol, count in protocol_count.items():
            stats[f'protocol_{protocol.lower()}'] = count
        
        # Insérer dans la table statistics
        for metric_name, metric_value in stats.items():
            cursor.execute("""
                INSERT INTO statistics (pcap_file_id, metric_name, metric_value)
                VALUES (?, ?, ?)
            """, (pcap_file_id, metric_name, str(metric_value)))
        
        self.logger.info(f"Analyse terminée: {len(packets)} paquets")
    
    def extract_flows(self, pcap_path: str) -> Dict[tuple, Dict]:
        """
        Extrait les flux (flows) d'un fichier PCAP.
        Regroupe les paquets par (src_ip, dst_ip, src_port, dst_port, protocol).
        
        Args:
            pcap_path: Chemin vers le fichier PCAP
            
        Returns:
            Dictionnaire des flux identifiés par un tuple (src_ip, dst_ip, src_port, dst_port, protocol)
        """
        flows = {}
        pcap_path_obj = Path(pcap_path)
        
        if not pcap_path_obj.exists():
            self.logger.error(f"Fichier introuvable pour l'extraction de flux: {pcap_path}")
            return {}
            
        self.logger.info(f"Extraction des flux pour: {pcap_path}")
        
        try:
            # Utilisation de rdpcap (attention à la mémoire pour les gros fichiers)
            packets = rdpcap(str(pcap_path))
            
            for packet in packets:
                # On s'intéresse principalement aux paquets IP
                if not packet.haslayer(IP):
                    continue
                    
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                # Le champ proto de IP donne le numéro de protocole (6 pour TCP, 17 pour UDP, etc.)
                # On peut le mapper vers un nom si nécessaire, mais le numéro est plus sûr pour la clé
                proto_num = packet[IP].proto
                
                src_port = 0
                dst_port = 0
                protocol_name = "IP"
                
                if packet.haslayer(TCP):
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                    protocol_name = "TCP"
                elif packet.haslayer(UDP):
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                    protocol_name = "UDP"
                elif packet.haslayer(ICMP):
                    protocol_name = "ICMP"
                
                # Clé unique pour le flux (unidirectionnel)
                flow_key = (src_ip, dst_ip, src_port, dst_port, protocol_name)
                
                timestamp = float(packet.time)
                packet_len = len(packet)
                
                if flow_key not in flows:
                    flows[flow_key] = {
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'src_port': src_port,
                        'dst_port': dst_port,
                        'protocol': protocol_name,
                        'packet_count': 0,
                        'byte_count': 0,
                        'start_time': timestamp,
                        'end_time': timestamp,
                        'duration': 0.0
                    }
                
                flow = flows[flow_key]
                flow['packet_count'] += 1
                flow['byte_count'] += packet_len
                
                # Mise à jour des temps
                if timestamp < flow['start_time']:
                    flow['start_time'] = timestamp
                if timestamp > flow['end_time']:
                    flow['end_time'] = timestamp
                    
                flow['duration'] = flow['end_time'] - flow['start_time']
            
            self.logger.info(f"Flux extraits: {len(flows)}")
            return flows
            
        except Exception as e:
            self.logger.error(f"Erreur lors de l'extraction des flux: {e}")
            return {}

    def ingest_directory(self, directory: str, pattern: str = "*.pcap"):
        """
        Ingère tous les fichiers PCAP d'un répertoire
        
        Args:
            directory: Chemin vers le répertoire
            pattern: Pattern de fichiers (défaut: *.pcap)
        """
        dir_path = Path(directory)
        
        if not dir_path.exists():
            self.logger.error(f"Répertoire introuvable: {directory}")
            return
        
        pcap_files = list(dir_path.glob(pattern))
        
        if not pcap_files:
            self.logger.warning(f"Aucun fichier {pattern} trouvé dans {directory}")
            return
        
        self.logger.info(f"Fichiers PCAP trouvés: {len(pcap_files)}")
        
        success_count = 0
        for pcap_file in pcap_files:
            pcap_id = self.ingest_pcap(str(pcap_file))
            if pcap_id:
                success_count += 1
        
        self.logger.info(f"Ingestion terminée: {success_count}/{len(pcap_files)} fichiers")
    
    def get_statistics(self, pcap_file_id: Optional[int] = None) -> Dict:
        """
        Récupère les statistiques d'un ou plusieurs fichiers PCAP
        
        Args:
            pcap_file_id: ID du fichier PCAP (None = tous les fichiers)
            
        Returns:
            Dictionnaire des statistiques
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            if pcap_file_id:
                cursor.execute("""
                    SELECT metric_name, metric_value 
                    FROM statistics 
                    WHERE pcap_file_id = ?
                """, (pcap_file_id,))
            else:
                cursor.execute("""
                    SELECT metric_name, SUM(CAST(metric_value AS INTEGER))
                    FROM statistics
                    GROUP BY metric_name
                """)
            
            stats = dict(cursor.fetchall())
            return stats
    
    def list_ingested_files(self):
        """Liste tous les fichiers PCAP ingérés"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, filename, ingestion_date, packet_count, file_size, duration
                FROM pcap_files
                ORDER BY ingestion_date DESC
            """)
            
            results = cursor.fetchall()
            
            if not results:
                self.logger.info("Aucun fichier PCAP ingéré")
                return
            
            self.logger.info("\n=== Fichiers PCAP ingérés ===")
            for row in results:
                pcap_id, filename, ingestion_date, packet_count, file_size, duration = row
                size_kb = file_size / 1024 if file_size else 0
                self.logger.info(f"\nID: {pcap_id}")
                self.logger.info(f"  Fichier: {filename}")
                self.logger.info(f"  Date: {ingestion_date}")
                self.logger.info(f"  Paquets: {packet_count}")
                self.logger.info(f"  Taille: {size_kb:.2f} KB")
                self.logger.info(f"  Durée: {duration:.2f}s")
    
    def export_to_json(self, pcap_file_id: int, output_file: str):
        """
        Exporte les données d'un fichier PCAP en JSON
        
        Args:
            pcap_file_id: ID du fichier PCAP
            output_file: Chemin du fichier JSON de sortie
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Récupérer les informations du fichier
            cursor.execute("SELECT * FROM pcap_files WHERE id = ?", (pcap_file_id,))
            pcap_info = dict(cursor.fetchone())
            
            # Récupérer les statistiques
            cursor.execute("""
                SELECT metric_name, metric_value 
                FROM statistics 
                WHERE pcap_file_id = ?
            """, (pcap_file_id,))
            stats = dict(cursor.fetchall())
            
            # Récupérer un échantillon de paquets (100 premiers)
            cursor.execute("""
                SELECT * FROM packets 
                WHERE pcap_file_id = ? 
                ORDER BY packet_number 
                LIMIT 100
            """, (pcap_file_id,))
            
            packets = [dict(row) for row in cursor.fetchall()]
            
            # Créer le document JSON
            export_data = {
                'pcap_info': pcap_info,
                'statistics': stats,
                'sample_packets': packets
            }
            
            # Écrire le fichier JSON
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"Export JSON créé: {output_path}")
    
    def query_packets(self, pcap_file_id: Optional[int] = None, 
                     protocol: Optional[str] = None,
                     src_ip: Optional[str] = None,
                     dst_ip: Optional[str] = None,
                     limit: int = 100) -> List[Dict]:
        """
        Requête personnalisée sur les paquets
        
        Args:
            pcap_file_id: Filtrer par fichier PCAP
            protocol: Filtrer par protocole
            src_ip: Filtrer par IP source
            dst_ip: Filtrer par IP destination
            limit: Nombre maximum de résultats
            
        Returns:
            Liste de paquets correspondants
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            query = "SELECT * FROM packets WHERE 1=1"
            params = []
            
            if pcap_file_id:
                query += " AND pcap_file_id = ?"
                params.append(pcap_file_id)
            
            if protocol:
                query += " AND protocol = ?"
                params.append(protocol.upper())
            
            if src_ip:
                query += " AND src_ip = ?"
                params.append(src_ip)
            
            if dst_ip:
                query += " AND dst_ip = ?"
                params.append(dst_ip)
            
            query += f" LIMIT {limit}"
            
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]


def main():
    """Fonction principale"""
    parser = argparse.ArgumentParser(
        description="Ingestion et analyse de fichiers PCAP - Celestis_IA",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation:
  # Ingérer un fichier PCAP
  python ingestion_pcap.py -f capture.pcap
  
  # Ingérer tous les fichiers d'un répertoire
  python ingestion_pcap.py -d ./captures
  
  # Lister les fichiers ingérés
  python ingestion_pcap.py --list
  
  # Exporter en JSON
  python ingestion_pcap.py --export 1 -o export.json
  
  # Requête sur les paquets TCP
  python ingestion_pcap.py --query --protocol TCP
        """
    )
    
    parser.add_argument('-f', '--file', 
                        help='Fichier PCAP à ingérer')
    parser.add_argument('-d', '--directory',
                        help='Répertoire contenant des fichiers PCAP')
    parser.add_argument('--pattern',
                        default='*.pcap',
                        help='Pattern de fichiers (défaut: *.pcap)')
    parser.add_argument('--db',
                        default='pcap_database.db',
                        help='Chemin vers la base de données (défaut: pcap_database.db)')
    parser.add_argument('--log-dir',
                        default='logs',
                        help='Répertoire des logs (défaut: logs)')
    parser.add_argument('--enable-yara',
                        action='store_true',
                        default=True,
                        help='Activer l\'analyse YARA (activé par défaut)')
    parser.add_argument('--disable-yara',
                        action='store_true',
                        help='Désactiver l\'analyse YARA')
    parser.add_argument('--yara-rules',
                        default='config/yara_rules.yar',
                        help='Chemin vers les règles YARA (défaut: config/yara_rules.yar)')
    parser.add_argument('--yara-alerts',
                        type=int,
                        metavar='PCAP_ID',
                        help='Afficher les alertes YARA pour un fichier PCAP')
    parser.add_argument('--yara-severity',
                        choices=['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
                        help='Filtrer les alertes YARA par sévérité')
    parser.add_argument('--list',
                        action='store_true',
                        help='Lister les fichiers PCAP ingérés')
    parser.add_argument('--export',
                        type=int,
                        metavar='ID',
                        help='Exporter un fichier PCAP en JSON')
    parser.add_argument('-o', '--output',
                        help='Fichier de sortie pour l\'export JSON')
    parser.add_argument('--query',
                        action='store_true',
                        help='Effectuer une requête sur les paquets')
    parser.add_argument('--protocol',
                        help='Filtrer par protocole (TCP, UDP, ICMP)')
    parser.add_argument('--src-ip',
                        help='Filtrer par IP source')
    parser.add_argument('--dst-ip',
                        help='Filtrer par IP destination')
    parser.add_argument('--pcap-id',
                        type=int,
                        help='ID du fichier PCAP pour la requête')
    parser.add_argument('--flows',
                        action='store_true',
                        help='Extraire et afficher les flux du fichier spécifié par -f')
    
    args = parser.parse_args()
    
    # Déterminer si YARA doit être activé
    enable_yara = args.enable_yara and not args.disable_yara

    # Créer l'instance d'ingestion
    ingestion = PcapIngestion(
        db_path=args.db,
        log_dir=args.log_dir,
        enable_yara=enable_yara,
        yara_rules_path=args.yara_rules
    )

    # Afficher les alertes de menaces
    if args.yara_alerts:
        if not ingestion.yara_analyzer:
            print("Erreur: Analyseur de menaces non disponible")
            return

        if args.yara_severity:
            alerts = ingestion.yara_analyzer.get_alerts_by_severity(
                args.yara_alerts, args.yara_severity
            )
            print(f"\n=== Alertes de menaces - Sévérité: {args.yara_severity} ({len(alerts)}) ===")
        else:
            alerts = ingestion.yara_analyzer.get_all_alerts(args.yara_alerts)
            print(f"\n=== Toutes les alertes de menaces ({len(alerts)}) ===")

        for alert in alerts:
            print(f"\n{'='*70}")
            print(f"🚨 {alert['rule_name']} - Sévérité: {alert['severity']}")
            print(f"{'='*70}")
            print(f"Description: {alert['description']}")
            print(f"Paquet: #{alert['packet_number']}")
            print(f"Timestamp: {alert['timestamp']}")
            print(f"Protocole: {alert['protocol']}")
            if alert['src_ip'] and alert['dst_ip']:
                print(f"Flux: {alert['src_ip']}:{alert['src_port']} -> {alert['dst_ip']}:{alert['dst_port']}")

        return

    # Lister les fichiers ingérés
    if args.list:
        ingestion.list_ingested_files()
        return

    # Extraire les flux
    if args.flows and args.file:
        flows = ingestion.extract_flows(args.file)
        print(f"\n=== Flux extraits ({len(flows)}) ===")
        # Trier par nombre de paquets décroissant
        sorted_flows = sorted(flows.values(), key=lambda x: x['packet_count'], reverse=True)
        
        for i, flow in enumerate(sorted_flows[:20]):  # Top 20
            print(f"\nFlux #{i+1}")
            print(f"  {flow['src_ip']}:{flow['src_port']} -> {flow['dst_ip']}:{flow['dst_port']} ({flow['protocol']})")
            print(f"  Paquets: {flow['packet_count']}, Octets: {flow['byte_count']}")
            print(f"  Durée: {flow['duration']:.4f}s")
        
        if len(flows) > 20:
            print(f"\n... et {len(flows) - 20} autres flux")
        return
    
    # Exporter en JSON
    if args.export:
        if not args.output:
            args.output = f"export_{args.export}.json"
        ingestion.export_to_json(args.export, args.output)
        return
    
    # Effectuer une requête
    if args.query:
        results = ingestion.query_packets(
            pcap_file_id=args.pcap_id,
            protocol=args.protocol,
            src_ip=args.src_ip,
            dst_ip=args.dst_ip
        )
        
        print(f"\n=== Résultats de la requête ({len(results)} paquets) ===")
        for packet in results[:10]:  # Afficher les 10 premiers
            print(f"\nPaquet #{packet['packet_number']}")
            print(f"  Temps: {packet['timestamp']}")
            print(f"  {packet['src_ip']}:{packet['src_port']} -> {packet['dst_ip']}:{packet['dst_port']}")
            print(f"  Protocole: {packet['protocol']}")
            print(f"  Taille: {packet['packet_size']} bytes")
        
        if len(results) > 10:
            print(f"\n... et {len(results) - 10} autres paquets")
        return
    
    # Ingérer un fichier
    if args.file:
        pcap_id = ingestion.ingest_pcap(args.file)
        if pcap_id:
            stats = ingestion.get_statistics(pcap_id)
            print("\n=== Statistiques ===")
            for key, value in stats.items():
                print(f"{key}: {value}")
        return
    
    # Ingérer un répertoire
    if args.directory:
        ingestion.ingest_directory(args.directory, pattern=args.pattern)
        return
    
    # Si aucune action n'est spécifiée, afficher l'aide
    parser.print_help()


if __name__ == "__main__":
    main()
