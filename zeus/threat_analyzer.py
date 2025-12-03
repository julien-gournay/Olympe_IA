#!/usr/bin/env python3
"""
Module d'analyse pour la détection de trames réseau problématiques
Celestis_IA - Module Zeus
Utilise des patterns regex pour détecter les menaces (compatible toutes plateformes)
"""

import logging
import re
import sqlite3
import yaml
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple

try:
    from scapy.utils import rdpcap
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.packet import Raw
except ImportError:
    print("Erreur: Scapy n'est pas installé. Installez-le avec: pip install scapy")
    exit(1)


class ThreatAnalyzer:
    """Classe pour l'analyse de menaces dans les paquets réseau (basée sur regex)"""

    # Niveaux de sévérité
    SEVERITY_INFO = "INFO"
    SEVERITY_LOW = "LOW"
    SEVERITY_MEDIUM = "MEDIUM"
    SEVERITY_HIGH = "HIGH"
    SEVERITY_CRITICAL = "CRITICAL"

    def __init__(self, rules_path: str = "config/threat_rules.yaml",
                 db_path: str = "pcap_database.db",
                 log_dir: str = "logs"):
        """
        Initialise le module d'analyse de menaces

        Args:
            rules_path: Chemin vers le fichier de règles YAML
            db_path: Chemin vers la base de données SQLite
            log_dir: Répertoire pour les logs
        """
        self.rules_path = Path(rules_path)
        self.db_path = Path(db_path)
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        self._setup_logging()
        self._init_database()
        self.rules = []

        # Charger les règles si elles existent
        if self.rules_path.exists():
            self.load_rules(str(self.rules_path))
        else:
            self.logger.warning(f"Fichier de règles introuvable: {self.rules_path}")
            self.logger.info("Utilisation des règles par défaut")
            self._create_default_rules()

    def _setup_logging(self):
        """Configure le système de logging"""
        log_file = self.log_dir / f"threat_analysis_{datetime.now().strftime('%Y%m%d')}.log"

        # Créer un logger spécifique
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)

        # Éviter les doublons de handlers
        if not self.logger.handlers:
            # Handler pour fichier
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(logging.INFO)

            # Handler pour console
            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.INFO)

            # Format
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            file_handler.setFormatter(formatter)
            console_handler.setFormatter(formatter)

            self.logger.addHandler(file_handler)
            self.logger.addHandler(console_handler)

    def _init_database(self):
        """Initialise les tables pour les alertes"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            # Table des alertes
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS threat_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pcap_file_id INTEGER,
                    packet_id INTEGER,
                    packet_number INTEGER,
                    timestamp TEXT,
                    rule_name TEXT,
                    severity TEXT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    protocol TEXT,
                    matched_pattern TEXT,
                    matched_data TEXT,
                    description TEXT,
                    detection_time TEXT,
                    FOREIGN KEY (pcap_file_id) REFERENCES pcap_files(id),
                    FOREIGN KEY (packet_id) REFERENCES packets(id)
                )
            """)

            # Index pour améliorer les performances
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_threat_alerts_pcap 
                ON threat_alerts(pcap_file_id)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_threat_alerts_severity 
                ON threat_alerts(severity)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_threat_alerts_rule 
                ON threat_alerts(rule_name)
            """)

            conn.commit()
            self.logger.info("Tables d'alertes initialisées")

    def _create_default_rules(self):
        """Crée un fichier de règles YAML par défaut"""
        self.rules_path.parent.mkdir(parents=True, exist_ok=True)

        default_rules_dict = {
            'rules': [
                {
                    'name': 'Suspicious_SQL_Injection',
                    'description': 'Détecte des tentatives d\'injection SQL potentielles',
                    'severity': 'HIGH',
                    'patterns': [
                        'UNION\\s+SELECT',
                        "'\\s+OR\\s+'1'='1",
                        "'\\s*;\\s*DROP\\s+TABLE",
                        "'\\s+OR\\s+1=1--",
                        "admin'--",
                        "1'\\s+UNION\\s+SELECT\\s+NULL"
                    ],
                    'case_sensitive': False
                },
                {
                    'name': 'Suspicious_XSS_Attempt',
                    'description': 'Détecte des tentatives de Cross-Site Scripting (XSS)',
                    'severity': 'MEDIUM',
                    'patterns': [
                        '<script>',
                        'javascript:',
                        'onerror=',
                        'onload=',
                        '<iframe',
                        'document\\.cookie'
                    ],
                    'case_sensitive': False
                },
                {
                    'name': 'Suspicious_Command_Injection',
                    'description': 'Détecte des tentatives d\'injection de commandes',
                    'severity': 'HIGH',
                    'patterns': [
                        ';/bin/sh',
                        '\\|/bin/bash',
                        '&&\\s+cat\\s+/etc/passwd',
                        '\\|\\s+nc\\s+',
                        '/bin/ls',
                        'wget\\s+http',
                        'curl\\s+http'
                    ],
                    'case_sensitive': False
                },
                {
                    'name': 'Suspicious_Path_Traversal',
                    'description': 'Détecte des tentatives de path traversal',
                    'severity': 'MEDIUM',
                    'patterns': [
                        '\\.\\./\\.\\./\\.\\./',
                        '\\.\\.\\\\.\\.\\\\.\\.',
                        '/etc/passwd',
                        '/etc/shadow',
                        'c:\\\\windows\\\\system32'
                    ],
                    'case_sensitive': False
                },
                {
                    'name': 'Malware_UserAgent',
                    'description': 'Détecte des User-Agent suspects associés à des malwares',
                    'severity': 'HIGH',
                    'patterns': [
                        'Gh0st',
                        'ZmEu',
                        'Nikto',
                        'sqlmap',
                        'Metasploit',
                        'python-requests/2\\.6'
                    ],
                    'case_sensitive': False
                },
                {
                    'name': 'Suspicious_Executable_Transfer',
                    'description': 'Détecte le transfert de fichiers exécutables suspects',
                    'severity': 'CRITICAL',
                    'patterns': [
                        '\\.exe',
                        '\\.dll',
                        '\\.scr',
                        '\\.bat',
                        '\\.vbs',
                        '\\.ps1'
                    ],
                    'case_sensitive': False
                },
                {
                    'name': 'Suspicious_Encoded_Payload',
                    'description': 'Détecte des payloads encodés suspects',
                    'severity': 'MEDIUM',
                    'patterns': [
                        'eval\\s*\\(',
                        'base64_decode',
                        'FromBase64String',
                        'atob\\('
                    ],
                    'case_sensitive': False
                },
                {
                    'name': 'Suspicious_Reverse_Shell',
                    'description': 'Détecte des indicateurs de reverse shell',
                    'severity': 'CRITICAL',
                    'patterns': [
                        '/bin/bash\\s+-i',
                        'nc\\s+-e\\s+/bin/sh',
                        'bash\\s+-c',
                        'python\\s+-c\\s+[\'"]import\\s+socket',
                        'perl\\s+-e\\s+[\'"]use\\s+Socket',
                        '/dev/tcp/'
                    ],
                    'case_sensitive': False
                },
                {
                    'name': 'Suspicious_Credentials_Leak',
                    'description': 'Détecte des fuites potentielles d\'identifiants',
                    'severity': 'HIGH',
                    'patterns': [
                        'password=',
                        'passwd=',
                        'pwd=',
                        'api_key=',
                        'apikey=',
                        'token=',
                        'Authorization:\\s+Bearer'
                    ],
                    'case_sensitive': False
                },
                {
                    'name': 'Suspicious_Port_Scan',
                    'description': 'Détecte des patterns de scan de ports',
                    'severity': 'LOW',
                    'patterns': [
                        'nmap',
                        'masscan'
                    ],
                    'case_sensitive': False
                }
            ]
        }

        try:
            with open(self.rules_path, 'w', encoding='utf-8') as f:
                yaml.dump(default_rules_dict, f, default_flow_style=False, allow_unicode=True)
            self.logger.info(f"Règles par défaut créées: {self.rules_path}")
            self.load_rules(str(self.rules_path))
        except Exception as e:
            self.logger.error(f"Erreur lors de la création des règles par défaut: {e}")
            # Utiliser les règles en mémoire
            self.rules = self._compile_rules(default_rules_dict['rules'])

    def load_rules(self, rules_path: str) -> bool:
        """
        Charge les règles depuis un fichier YAML

        Args:
            rules_path: Chemin vers le fichier de règles

        Returns:
            True si chargement réussi, False sinon
        """
        try:
            with open(rules_path, 'r', encoding='utf-8') as f:
                rules_data = yaml.safe_load(f)

            if not rules_data or 'rules' not in rules_data:
                self.logger.error("Format de règles invalide")
                return False

            self.rules = self._compile_rules(rules_data['rules'])
            self.logger.info(f"Règles chargées: {len(self.rules)} règle(s)")
            return True
        except Exception as e:
            self.logger.error(f"Erreur lors du chargement des règles: {e}")
            return False

    def _compile_rules(self, rules_list: List[Dict]) -> List[Dict]:
        """
        Compile les patterns regex des règles

        Args:
            rules_list: Liste des règles

        Returns:
            Liste des règles compilées
        """
        compiled_rules = []

        for rule in rules_list:
            compiled_patterns = []
            case_sensitive = rule.get('case_sensitive', False)
            flags = 0 if case_sensitive else re.IGNORECASE

            for pattern in rule.get('patterns', []):
                try:
                    compiled_patterns.append(re.compile(pattern, flags))
                except re.error as e:
                    self.logger.warning(f"Pattern invalide '{pattern}' dans {rule['name']}: {e}")

            if compiled_patterns:
                compiled_rules.append({
                    'name': rule['name'],
                    'description': rule.get('description', ''),
                    'severity': rule.get('severity', self.SEVERITY_MEDIUM),
                    'patterns': compiled_patterns,
                    'original_patterns': rule.get('patterns', [])
                })

        return compiled_rules

    def analyze_packet(self, packet: Any, packet_number: int) -> List[Dict]:
        """
        Analyse un paquet avec les règles

        Args:
            packet: Paquet Scapy à analyser
            packet_number: Numéro du paquet

        Returns:
            Liste des alertes détectées
        """
        if not self.rules:
            return []

        alerts = []

        try:
            # Extraire le payload du paquet
            payload_bytes = bytes(packet)

            # Essayer de décoder en texte
            try:
                payload_str = payload_bytes.decode('utf-8', errors='ignore')
            except:
                payload_str = payload_bytes.decode('latin-1', errors='ignore')

            # Analyser avec chaque règle
            for rule in self.rules:
                matches = []

                for pattern in rule['patterns']:
                    match = pattern.search(payload_str)
                    if match:
                        matches.append({
                            'pattern': pattern.pattern,
                            'match': match.group(0)[:100]  # Limiter à 100 caractères
                        })

                if matches:
                    # Extraire les informations du paquet
                    src_ip = packet[IP].src if packet.haslayer(IP) else None
                    dst_ip = packet[IP].dst if packet.haslayer(IP) else None
                    src_port = None
                    dst_port = None
                    protocol = "OTHER"

                    if packet.haslayer(TCP):
                        protocol = "TCP"
                        src_port = packet[TCP].sport
                        dst_port = packet[TCP].dport
                    elif packet.haslayer(UDP):
                        protocol = "UDP"
                        src_port = packet[UDP].sport
                        dst_port = packet[UDP].dport

                    alert = {
                        'packet_number': packet_number,
                        'timestamp': datetime.fromtimestamp(float(packet.time)).isoformat(),
                        'rule_name': rule['name'],
                        'severity': rule['severity'],
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'src_port': src_port,
                        'dst_port': dst_port,
                        'protocol': protocol,
                        'matched_pattern': matches[0]['pattern'],
                        'matched_data': matches[0]['match'],
                        'description': rule['description'],
                        'detection_time': datetime.now().isoformat(),
                        'all_matches': len(matches)
                    }

                    alerts.append(alert)

        except Exception as e:
            self.logger.warning(f"Erreur lors de l'analyse du paquet {packet_number}: {e}")

        return alerts

    def analyze_pcap(self, pcap_file: str, pcap_file_id: Optional[int] = None,
                     verbose: bool = True) -> List[Dict]:
        """
        Analyse un fichier PCAP complet

        Args:
            pcap_file: Chemin vers le fichier PCAP
            pcap_file_id: ID du fichier PCAP dans la base de données
            verbose: Afficher les détails des alertes

        Returns:
            Liste de toutes les alertes détectées
        """
        pcap_path = Path(pcap_file)

        if not pcap_path.exists():
            self.logger.error(f"Fichier PCAP introuvable: {pcap_file}")
            return []

        if not self.rules:
            self.logger.error("Aucune règle chargée")
            return []

        self.logger.info(f"Début de l'analyse: {pcap_file}")

        all_alerts = []

        try:
            packets = rdpcap(str(pcap_path))
            total_packets = len(packets)

            self.logger.info(f"Analyse de {total_packets} paquets avec {len(self.rules)} règle(s)...")

            for i, packet in enumerate(packets, 1):
                alerts = self.analyze_packet(packet, i)

                if alerts:
                    all_alerts.extend(alerts)

                    if verbose:
                        for alert in alerts:
                            self._print_alert(alert)

                # Afficher la progression
                if i % 1000 == 0:
                    self.logger.info(f"  Paquets analysés: {i}/{total_packets} - Alertes: {len(all_alerts)}")

            # Sauvegarder les alertes dans la base de données
            if pcap_file_id is not None and all_alerts:
                self._save_alerts(pcap_file_id, all_alerts)

            self.logger.info(f"Analyse terminée: {len(all_alerts)} alerte(s) détectée(s) sur {total_packets} paquets")

            # Afficher un résumé
            if all_alerts:
                self._print_summary(all_alerts)

            return all_alerts

        except Exception as e:
            self.logger.error(f"Erreur lors de l'analyse: {e}")
            return []

    def _save_alerts(self, pcap_file_id: int, alerts: List[Dict]):
        """
        Sauvegarde les alertes dans la base de données

        Args:
            pcap_file_id: ID du fichier PCAP
            alerts: Liste des alertes
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                for alert in alerts:
                    cursor.execute("""
                        INSERT INTO threat_alerts 
                        (pcap_file_id, packet_number, timestamp, rule_name, 
                         severity, src_ip, dst_ip, src_port, dst_port, protocol, 
                         matched_pattern, matched_data, description, detection_time)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        pcap_file_id,
                        alert['packet_number'],
                        alert['timestamp'],
                        alert['rule_name'],
                        alert['severity'],
                        alert['src_ip'],
                        alert['dst_ip'],
                        alert['src_port'],
                        alert['dst_port'],
                        alert['protocol'],
                        alert['matched_pattern'],
                        alert['matched_data'],
                        alert['description'],
                        alert['detection_time']
                    ))

                conn.commit()
                self.logger.info(f"{len(alerts)} alerte(s) sauvegardée(s) dans la base de données")

        except Exception as e:
            self.logger.error(f"Erreur lors de la sauvegarde des alertes: {e}")

    def _print_alert(self, alert: Dict):
        """Affiche une alerte de manière formatée"""
        severity_icons = {
            self.SEVERITY_INFO: "ℹ️",
            self.SEVERITY_LOW: "⚪",
            self.SEVERITY_MEDIUM: "🟡",
            self.SEVERITY_HIGH: "🟠",
            self.SEVERITY_CRITICAL: "🔴"
        }

        icon = severity_icons.get(alert['severity'], "⚠️")

        print(f"\n{'='*70}")
        print(f"{icon} ALERTE - Sévérité: {alert['severity']}")
        print(f"{'='*70}")
        print(f"Règle: {alert['rule_name']}")
        print(f"Description: {alert['description']}")
        print(f"Paquet: #{alert['packet_number']}")
        print(f"Timestamp: {alert['timestamp']}")
        print(f"Protocole: {alert['protocol']}")

        if alert['src_ip'] and alert['dst_ip']:
            src = f"{alert['src_ip']}"
            if alert['src_port']:
                src += f":{alert['src_port']}"
            dst = f"{alert['dst_ip']}"
            if alert['dst_port']:
                dst += f":{alert['dst_port']}"
            print(f"Flux: {src} -> {dst}")

        print(f"Données détectées: {alert['matched_data']}")
        print(f"{'='*70}\n")

    def _print_summary(self, alerts: List[Dict]):
        """Affiche un résumé des alertes"""
        print(f"\n{'='*70}")
        print(f"📊 RÉSUMÉ DE L'ANALYSE")
        print(f"{'='*70}")

        # Comptage par sévérité
        severity_count = {}
        for alert in alerts:
            severity = alert['severity']
            severity_count[severity] = severity_count.get(severity, 0) + 1

        print(f"\nAlertes par sévérité:")
        for severity in [self.SEVERITY_CRITICAL, self.SEVERITY_HIGH,
                        self.SEVERITY_MEDIUM, self.SEVERITY_LOW, self.SEVERITY_INFO]:
            count = severity_count.get(severity, 0)
            if count > 0:
                print(f"  {severity}: {count}")

        # Comptage par règle
        rule_count = {}
        for alert in alerts:
            rule = alert['rule_name']
            rule_count[rule] = rule_count.get(rule, 0) + 1

        print(f"\nTop 5 des règles déclenchées:")
        sorted_rules = sorted(rule_count.items(), key=lambda x: x[1], reverse=True)
        for rule, count in sorted_rules[:5]:
            print(f"  {rule}: {count}")

        print(f"{'='*70}\n")

    def get_alerts_by_severity(self, pcap_file_id: int, severity: str) -> List[Dict]:
        """
        Récupère les alertes par niveau de sévérité

        Args:
            pcap_file_id: ID du fichier PCAP
            severity: Niveau de sévérité

        Returns:
            Liste des alertes
        """
        alerts = []

        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT * FROM threat_alerts 
                    WHERE pcap_file_id = ? AND severity = ?
                    ORDER BY timestamp
                """, (pcap_file_id, severity))

                columns = [desc[0] for desc in cursor.description]
                for row in cursor.fetchall():
                    alerts.append(dict(zip(columns, row)))

        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération des alertes: {e}")

        return alerts

    def get_all_alerts(self, pcap_file_id: Optional[int] = None) -> List[Dict]:
        """
        Récupère toutes les alertes

        Args:
            pcap_file_id: ID du fichier PCAP (optionnel)

        Returns:
            Liste des alertes
        """
        alerts = []

        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                if pcap_file_id is not None:
                    cursor.execute("""
                        SELECT * FROM threat_alerts 
                        WHERE pcap_file_id = ?
                        ORDER BY timestamp
                    """, (pcap_file_id,))
                else:
                    cursor.execute("SELECT * FROM threat_alerts ORDER BY timestamp")

                columns = [desc[0] for desc in cursor.description]
                for row in cursor.fetchall():
                    alerts.append(dict(zip(columns, row)))

        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération des alertes: {e}")

        return alerts


# Alias pour compatibilité
YaraAnalyzer = ThreatAnalyzer


def main():
    """Fonction principale pour les tests"""
    import argparse

    parser = argparse.ArgumentParser(description="Analyse de menaces dans les fichiers PCAP")
    parser.add_argument('-f', '--file', help='Fichier PCAP à analyser')
    parser.add_argument('-r', '--rules', default='config/threat_rules.yaml',
                       help='Fichier de règles YAML')
    parser.add_argument('--list-alerts', action='store_true',
                       help='Lister toutes les alertes de la base')
    parser.add_argument('--severity', choices=['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
                       help='Filtrer par sévérité')
    parser.add_argument('--pcap-id', type=int, help='ID du fichier PCAP')

    args = parser.parse_args()

    analyzer = ThreatAnalyzer(rules_path=args.rules)

    if args.list_alerts:
        alerts = analyzer.get_all_alerts(args.pcap_id)
        print(f"\nTotal des alertes: {len(alerts)}")
        for alert in alerts:
            print(f"\n{alert['rule_name']} - {alert['severity']}")
            print(f"  Paquet: #{alert['packet_number']}")
            print(f"  {alert['src_ip']}:{alert['src_port']} -> {alert['dst_ip']}:{alert['dst_port']}")

    elif args.file:
        analyzer.analyze_pcap(args.file, verbose=True)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()

