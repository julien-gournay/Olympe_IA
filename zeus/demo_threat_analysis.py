#!/usr/bin/env python3
"""
Script de démonstration - Analyse de menaces réseau
Celestis_IA - Module Zeus
"""

from threat_analyzer import ThreatAnalyzer
from ingestion_pcap import PcapIngestion
import sys

def demo_basic_analysis():
    """Démo d'analyse basique"""
    print("\n" + "="*70)
    print("DÉMONSTRATION - Analyse de menaces réseau")
    print("="*70 + "\n")

    # Initialiser l'analyseur
    print("[1/3] Initialisation de l'analyseur de menaces...")
    analyzer = ThreatAnalyzer()
    print(f"      -> {len(analyzer.rules)} règles de détection chargées")

    # Afficher les règles disponibles
    print("\n[2/3] Règles de détection disponibles:")
    for i, rule in enumerate(analyzer.rules, 1):
        print(f"      {i:2d}. {rule['name']:40s} [{rule['severity']}]")
        print(f"          {rule['description']}")

    print("\n[3/3] Prêt pour l'analyse de fichiers PCAP")
    print("      Utilisez: python threat_analyzer.py -f <fichier.pcap>\n")

def demo_with_pcap(pcap_file):
    """Démo avec un fichier PCAP réel"""
    print("\n" + "="*70)
    print("ANALYSE DE MENACES - Fichier PCAP")
    print("="*70 + "\n")

    analyzer = ThreatAnalyzer()

    print(f"Fichier: {pcap_file}")
    print(f"Règles: {len(analyzer.rules)}")
    print("\nAnalyse en cours...\n")

    alerts = analyzer.analyze_pcap(pcap_file, verbose=True)

    if not alerts:
        print("\n✓ Aucune menace détectée dans le fichier PCAP")
        print("  Le trafic réseau semble normal.\n")
    else:
        print(f"\n⚠️  {len(alerts)} alerte(s) détectée(s)!")
        print("\nRecommandations:")

        critical_count = sum(1 for a in alerts if a['severity'] == 'CRITICAL')
        high_count = sum(1 for a in alerts if a['severity'] == 'HIGH')

        if critical_count > 0:
            print(f"  - URGENT: {critical_count} alerte(s) CRITIQUE(S) nécessitent une action immédiate")
        if high_count > 0:
            print(f"  - ATTENTION: {high_count} alerte(s) de niveau ÉLEVÉ à investiguer")

        print("\nActions suggérées:")
        print("  1. Examiner les alertes critiques en priorité")
        print("  2. Identifier les adresses IP sources suspectes")
        print("  3. Bloquer le trafic malveillant si confirmé")
        print("  4. Mettre à jour les règles de firewall")
        print()

def demo_custom_rules():
    """Démo de création de règles personnalisées"""
    print("\n" + "="*70)
    print("EXEMPLE - Création de règles personnalisées")
    print("="*70 + "\n")

    example_rule = """
# Exemple de règle personnalisée (config/threat_rules.yaml)

rules:
  - name: Detection_Bitcoin_Mining
    description: Détecte des indicateurs de minage de cryptomonnaie
    severity: MEDIUM
    patterns:
      - 'stratum\\+tcp://'
      - 'mining\\.pool'
      - 'xmr-node'
      - 'cryptonight'
    case_sensitive: false
    
  - name: Detection_Data_Exfiltration
    description: Détecte des signes d'exfiltration de données
    severity: HIGH
    patterns:
      - 'pastebin\\.com/raw'
      - 'transfer\\.sh'
      - 'anonfiles\\.com'
      - 'Content-Disposition:.*\\.zip'
    case_sensitive: false
    
  - name: Detection_C2_Communication
    description: Détecte des communications avec des serveurs C&C
    severity: CRITICAL
    patterns:
      - '/beacon'
      - '/gate\\.php'
      - '/panel/cmd'
      - 'cmd=download'
    case_sensitive: false
"""

    print(example_rule)
    print("\nPour utiliser vos règles personnalisées:")
    print("  1. Créez un fichier YAML avec vos règles")
    print("  2. Lancez: python threat_analyzer.py -f capture.pcap -r mes_regles.yaml")
    print()

def demo_integration():
    """Démo d'intégration avec l'ingestion"""
    print("\n" + "="*70)
    print("INTÉGRATION - Analyse automatique lors de l'ingestion")
    print("="*70 + "\n")

    code_example = '''
# Exemple d'utilisation avec l'ingestion automatique

from ingestion_pcap import PcapIngestion

# Créer l'instance avec analyse de menaces activée
ingestion = PcapIngestion(
    db_path='pcap_database.db',
    enable_yara=True,
    yara_rules_path='config/threat_rules.yaml'
)

# Ingérer et analyser automatiquement
pcap_id = ingestion.ingest_pcap('captures/traffic.pcap')

# Récupérer les alertes
if ingestion.yara_analyzer:
    alerts = ingestion.yara_analyzer.get_all_alerts(pcap_id)
    
    critical = [a for a in alerts if a['severity'] == 'CRITICAL']
    if critical:
        print(f"ALERTE: {len(critical)} menace(s) critique(s) détectée(s)!")
        # Envoyer notification, email, etc.
'''

    print(code_example)
    print("\nOu en ligne de commande:")
    print("  python ingestion_pcap.py -f capture.pcap --enable-yara")
    print("  python ingestion_pcap.py --yara-alerts 1 --yara-severity CRITICAL")
    print()

def main():
    """Fonction principale"""
    if len(sys.argv) > 1 and sys.argv[1] == '--with-pcap':
        if len(sys.argv) > 2:
            demo_with_pcap(sys.argv[2])
        else:
            print("Usage: python demo_threat_analysis.py --with-pcap <fichier.pcap>")
    elif len(sys.argv) > 1 and sys.argv[1] == '--custom-rules':
        demo_custom_rules()
    elif len(sys.argv) > 1 and sys.argv[1] == '--integration':
        demo_integration()
    else:
        # Menu principal
        print("\n" + "="*70)
        print("DÉMONSTRATION - Système d'analyse de menaces réseau")
        print("Celestis_IA - Module Zeus")
        print("="*70)

        print("\nOptions disponibles:")
        print("  1. python demo_threat_analysis.py")
        print("     -> Affiche les règles disponibles")
        print()
        print("  2. python demo_threat_analysis.py --with-pcap <fichier.pcap>")
        print("     -> Analyse un fichier PCAP")
        print()
        print("  3. python demo_threat_analysis.py --custom-rules")
        print("     -> Montre comment créer des règles personnalisées")
        print()
        print("  4. python demo_threat_analysis.py --integration")
        print("     -> Montre l'intégration avec l'ingestion")
        print()

        # Afficher la démo basique par défaut
        demo_basic_analysis()

if __name__ == "__main__":
    main()

