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


class YaraAnalyzer:
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
        log_file = self.log_dir / f"yara_analysis_{datetime.now().strftime('%Y%m%d')}.log"

        # Créer un logger spécifique pour YARA
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)

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
        """Initialise les tables pour les alertes YARA"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            # Table des alertes YARA
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS yara_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pcap_file_id INTEGER,
                    packet_id INTEGER,
                    packet_number INTEGER,
                    timestamp TEXT,
                    rule_name TEXT,
                    rule_tags TEXT,
                    severity TEXT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    protocol TEXT,
                    matched_strings TEXT,
                    description TEXT,
                    detection_time TEXT,
                    FOREIGN KEY (pcap_file_id) REFERENCES pcap_files(id),
                    FOREIGN KEY (packet_id) REFERENCES packets(id)
                )
            """)

            # Index pour améliorer les performances
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_yara_alerts_pcap 
                ON yara_alerts(pcap_file_id)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_yara_alerts_severity 
                ON yara_alerts(severity)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_yara_alerts_rule 
                ON yara_alerts(rule_name)
            """)

            conn.commit()
            self.logger.info("Tables YARA initialisées")

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
                        '\\'\\s+OR\\s+\\'1\\'=\\'1',
                        '\\'\\s*;\\s*DROP\\s+TABLE',
                        '\\'\\s+OR\\s+1=1--',
                        'admin\\'--',
                        '1\\'\\s+UNION\\s+SELECT\\s+NULL'
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
                    'name': 'Suspicious_Command_Injection
{
    meta:
        description = "Détecte des tentatives d'injection SQL potentielles"
        severity = "HIGH"
        author = "Celestis_IA"

    strings:
        $sql1 = "UNION SELECT" nocase
        $sql2 = "' OR '1'='1" nocase
        $sql3 = "'; DROP TABLE" nocase
        $sql4 = "' OR 1=1--" nocase
        $sql5 = "admin'--" nocase
        $sql6 = "1' UNION SELECT NULL" nocase

    condition:
        any of ($sql*)
}

rule Suspicious_XSS_Attempt
{
    meta:
        description = "Détecte des tentatives de Cross-Site Scripting (XSS)"
        severity = "MEDIUM"
        author = "Celestis_IA"

    strings:
        $xss1 = "<script>" nocase
        $xss2 = "javascript:" nocase
        $xss3 = "onerror=" nocase
        $xss4 = "onload=" nocase
        $xss5 = "<iframe" nocase
        $xss6 = "document.cookie" nocase

    condition:
        any of ($xss*)
}

rule Suspicious_Command_Injection
{
    meta:
        description = "Détecte des tentatives d'injection de commandes"
        severity = "HIGH"
        author = "Celestis_IA"

    strings:
        $cmd1 = ";/bin/sh" nocase
        $cmd2 = "|/bin/bash" nocase
        $cmd3 = "&& cat /etc/passwd" nocase
        $cmd4 = "| nc " nocase
        $cmd5 = "/bin/ls" nocase
        $cmd6 = "wget http" nocase
        $cmd7 = "curl http" nocase

    condition:
        any of ($cmd*)
}

rule Suspicious_Path_Traversal
{
    meta:
        description = "Détecte des tentatives de path traversal"
        severity = "MEDIUM"
        author = "Celestis_IA"

    strings:
        $path1 = "../../../"
        $path2 = "..\\..\\...\\"
        $path3 = "/etc/passwd" nocase
        $path4 = "/etc/shadow" nocase
        $path5 = "c:\\windows\\system32" nocase

    condition:
        any of ($path*)
}

rule Malware_UserAgent
{
    meta:
        description = "Détecte des User-Agent suspects associés à des malwares"
        severity = "HIGH"
        author = "Celestis_IA"

    strings:
        $ua1 = "Gh0st" nocase
        $ua2 = "ZmEu" nocase
        $ua3 = "Nikto" nocase
        $ua4 = "sqlmap" nocase
        $ua5 = "Metasploit" nocase
        $ua6 = "python-requests/2.6" // Version utilisée par certains malwares

    condition:
        any of ($ua*)
}

rule Suspicious_Executable_Transfer
{
    meta:
        description = "Détecte le transfert de fichiers exécutables suspects"
        severity = "CRITICAL"
        author = "Celestis_IA"

    strings:
        $exe1 = { 4D 5A } // MZ header (EXE)
        $exe2 = ".exe" nocase
        $exe3 = ".dll" nocase
        $exe4 = ".scr" nocase
        $exe5 = ".bat" nocase
        $exe6 = ".vbs" nocase
        $exe7 = ".ps1" nocase

    condition:
        $exe1 at 0 or any of ($exe2, $exe3, $exe4, $exe5, $exe6, $exe7)
}

rule Suspicious_Encoded_Payload
{
    meta:
        description = "Détecte des payloads encodés suspects"
        severity = "MEDIUM"
        author = "Celestis_IA"

    strings:
        $enc1 = /eval\s*\(/ nocase
        $enc2 = "base64_decode" nocase
        $enc3 = "FromBase64String" nocase
        $enc4 = "atob(" nocase // JavaScript base64 decode

    condition:
        any of ($enc*)
}

rule Suspicious_Reverse_Shell
{
    meta:
        description = "Détecte des indicateurs de reverse shell"
        severity = "CRITICAL"
        author = "Celestis_IA"

    strings:
        $shell1 = "/bin/bash -i" nocase
        $shell2 = "nc -e /bin/sh" nocase
        $shell3 = "bash -c" nocase
        $shell4 = "python -c 'import socket" nocase
        $shell5 = "perl -e 'use Socket" nocase
        $shell6 = "/dev/tcp/" nocase

    condition:
        any of ($shell*)
}

rule Suspicious_Credentials_Leak
{
    meta:
        description = "Détecte des fuites potentielles d'identifiants"
        severity = "HIGH"
        author = "Celestis_IA"

    strings:
        $cred1 = "password=" nocase
        $cred2 = "passwd=" nocase
        $cred3 = "pwd=" nocase
        $cred4 = "api_key=" nocase
        $cred5 = "apikey=" nocase
        $cred6 = "token=" nocase
        $cred7 = "Authorization: Bearer" nocase

    condition:
        any of ($cred*)
}

rule Suspicious_Port_Scan
{
    meta:
        description = "Détecte des patterns de scan de ports"
        severity = "LOW"
        author = "Celestis_IA"

    strings:
        $scan1 = "nmap" nocase
        $scan2 = "masscan" nocase

    condition:
        any of ($scan*)
}
'''

        try:
            with open(self.rules_path, 'w', encoding='utf-8') as f:
                f.write(default_rules)
            self.logger.info(f"Règles YARA par défaut créées: {self.rules_path}")
            self.load_rules(str(self.rules_path))
        except Exception as e:
            self.logger.error(f"Erreur lors de la création des règles par défaut: {e}")

    def load_rules(self, rules_path: str) -> bool:
        """
        Charge les règles YARA depuis un fichier

        Args:
            rules_path: Chemin vers le fichier de règles

        Returns:
            True si chargement réussi, False sinon
        """
        try:
            self.rules = yara.compile(filepath=rules_path)
            self.logger.info(f"Règles YARA chargées: {rules_path}")
            return True
        except Exception as e:
            self.logger.error(f"Erreur lors du chargement des règles YARA: {e}")
            return False

    def analyze_packet(self, packet: Any, packet_number: int) -> List[Dict]:
        """
        Analyse un paquet avec les règles YARA

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
            payload = bytes(packet)

            # Analyser avec YARA
            matches = self.rules.match(data=payload)

            for match in matches:
                # Extraire les métadonnées
                severity = match.meta.get('severity', self.SEVERITY_MEDIUM)
                description = match.meta.get('description', 'Aucune description')

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

                # Extraire les chaînes correspondantes
                matched_strings = []
                for string in match.strings:
                    matched_strings.append({
                        'identifier': string.identifier,
                        'instances': [(s[0], s[2].decode('utf-8', errors='replace')) for s in string.instances]
                    })

                alert = {
                    'packet_number': packet_number,
                    'timestamp': datetime.fromtimestamp(float(packet.time)).isoformat(),
                    'rule_name': match.rule,
                    'rule_tags': ','.join(match.tags),
                    'severity': severity,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'protocol': protocol,
                    'matched_strings': str(matched_strings),
                    'description': description,
                    'detection_time': datetime.now().isoformat()
                }

                alerts.append(alert)

        except Exception as e:
            self.logger.warning(f"Erreur lors de l'analyse YARA du paquet {packet_number}: {e}")

        return alerts

    def analyze_pcap(self, pcap_file: str, pcap_file_id: Optional[int] = None,
                     verbose: bool = True) -> List[Dict]:
        """
        Analyse un fichier PCAP complet avec YARA

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
            self.logger.error("Aucune règle YARA chargée")
            return []

        self.logger.info(f"Début de l'analyse YARA: {pcap_file}")

        all_alerts = []

        try:
            packets = rdpcap(str(pcap_path))
            total_packets = len(packets)

            self.logger.info(f"Analyse de {total_packets} paquets...")

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

            self.logger.info(f"Analyse terminée: {len(all_alerts)} alertes détectées sur {total_packets} paquets")

            # Afficher un résumé
            if all_alerts:
                self._print_summary(all_alerts)

            return all_alerts

        except Exception as e:
            self.logger.error(f"Erreur lors de l'analyse YARA: {e}")
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
                        INSERT INTO yara_alerts 
                        (pcap_file_id, packet_number, timestamp, rule_name, rule_tags, 
                         severity, src_ip, dst_ip, src_port, dst_port, protocol, 
                         matched_strings, description, detection_time)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        pcap_file_id,
                        alert['packet_number'],
                        alert['timestamp'],
                        alert['rule_name'],
                        alert['rule_tags'],
                        alert['severity'],
                        alert['src_ip'],
                        alert['dst_ip'],
                        alert['src_port'],
                        alert['dst_port'],
                        alert['protocol'],
                        alert['matched_strings'],
                        alert['description'],
                        alert['detection_time']
                    ))

                conn.commit()
                self.logger.info(f"{len(alerts)} alertes sauvegardées dans la base de données")

        except Exception as e:
            self.logger.error(f"Erreur lors de la sauvegarde des alertes: {e}")

    def _print_alert(self, alert: Dict):
        """Affiche une alerte de manière formatée"""
        severity_colors = {
            self.SEVERITY_INFO: "INFO",
            self.SEVERITY_LOW: "LOW",
            self.SEVERITY_MEDIUM: "MEDIUM",
            self.SEVERITY_HIGH: "HIGH",
            self.SEVERITY_CRITICAL: "CRITICAL"
        }

        severity_label = severity_colors.get(alert['severity'], alert['severity'])

        print(f"\n{'='*70}")
        print(f"🚨 ALERTE YARA - Sévérité: {severity_label}")
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

        print(f"{'='*70}\n")

    def _print_summary(self, alerts: List[Dict]):
        """Affiche un résumé des alertes"""
        print(f"\n{'='*70}")
        print(f"📊 RÉSUMÉ DE L'ANALYSE YARA")
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
                    SELECT * FROM yara_alerts 
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
                        SELECT * FROM yara_alerts 
                        WHERE pcap_file_id = ?
                        ORDER BY timestamp
                    """, (pcap_file_id,))
                else:
                    cursor.execute("SELECT * FROM yara_alerts ORDER BY timestamp")

                columns = [desc[0] for desc in cursor.description]
                for row in cursor.fetchall():
                    alerts.append(dict(zip(columns, row)))

        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération des alertes: {e}")

        return alerts


def main():
    """Fonction principale pour les tests"""
    import argparse

    parser = argparse.ArgumentParser(description="Analyse YARA de fichiers PCAP")
    parser.add_argument('-f', '--file', help='Fichier PCAP à analyser')
    parser.add_argument('-r', '--rules', default='config/yara_rules.yar',
                       help='Fichier de règles YARA')
    parser.add_argument('--list-alerts', action='store_true',
                       help='Lister toutes les alertes de la base')
    parser.add_argument('--severity', choices=['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
                       help='Filtrer par sévérité')
    parser.add_argument('--pcap-id', type=int, help='ID du fichier PCAP')

    args = parser.parse_args()

    analyzer = YaraAnalyzer(rules_path=args.rules)

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

