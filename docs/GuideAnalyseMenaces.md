# Guide d'utilisation - Analyse de menaces réseau

## Vue d'ensemble

Le module d'analyse de menaces de Celestis_IA permet de détecter automatiquement des comportements suspects et des menaces potentielles dans les captures réseau (fichiers PCAP). Il utilise un système de règles basées sur des patterns regex pour identifier :

- Injections SQL
- Cross-Site Scripting (XSS)
- Injections de commandes
- Path Traversal
- Malwares (User-Agent suspects)
- Transferts de fichiers exécutables
- Payloads encodés
- Reverse shells
- Fuites d'identifiants
- Scans de ports

## Installation

### Prérequis

```bash
pip install -r requirements.txt
```

Les dépendances incluent :
- `scapy` : Pour l'analyse des paquets réseau
- `pyyaml` : Pour la gestion des règles
- `python-dateutil` : Pour la gestion des dates

## Configuration

### Fichier de configuration (config.yaml)

```yaml
analysis:
  enable_export: false
  enable_statistics: true
  export_format: json
  yara:
    enabled: true
    rules_path: config/threat_rules.yaml
    alert_on_detection: true
    min_severity: LOW
```

### Fichier de règles (config/threat_rules.yaml)

Le fichier de règles est créé automatiquement au premier lancement avec des règles par défaut. Vous pouvez le personnaliser selon vos besoins.

Structure d'une règle :

```yaml
rules:
  - name: Ma_Regle_Personnalisee
    description: Description de la menace détectée
    severity: HIGH  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    patterns:
      - 'pattern_regex_1'
      - 'pattern_regex_2'
    case_sensitive: false  # true ou false
```

## Utilisation

### 1. Analyse d'un fichier PCAP avec détection de menaces

```bash
# Analyse simple
python ingestion_pcap.py -f captures/capture.pcap

# Analyse avec règles personnalisées
python ingestion_pcap.py -f captures/capture.pcap --yara-rules config/mes_regles.yaml

# Désactiver l'analyse de menaces
python ingestion_pcap.py -f captures/capture.pcap --disable-yara
```

### 2. Afficher les alertes détectées

```bash
# Toutes les alertes pour un fichier PCAP (ID 1)
python ingestion_pcap.py --yara-alerts 1

# Alertes par sévérité
python ingestion_pcap.py --yara-alerts 1 --yara-severity HIGH
python ingestion_pcap.py --yara-alerts 1 --yara-severity CRITICAL
```

### 3. Utilisation directe du module d'analyse

```bash
# Analyser un fichier PCAP
python threat_analyzer.py -f captures/capture.pcap

# Avec règles personnalisées
python threat_analyzer.py -f captures/capture.pcap -r config/mes_regles.yaml

# Lister toutes les alertes de la base
python threat_analyzer.py --list-alerts

# Lister les alertes d'un fichier spécifique
python threat_analyzer.py --list-alerts --pcap-id 1
```

## Utilisation en Python

### Exemple de code

```python
from threat_analyzer import ThreatAnalyzer

# Initialiser l'analyseur
analyzer = ThreatAnalyzer(
    rules_path='config/threat_rules.yaml',
    db_path='pcap_database.db',
    log_dir='logs'
)

# Analyser un fichier PCAP
alerts = analyzer.analyze_pcap('captures/capture.pcap', verbose=True)

# Traiter les alertes
for alert in alerts:
    print(f"Alerte: {alert['rule_name']} - Sévérité: {alert['severity']}")
    print(f"  Description: {alert['description']}")
    print(f"  Paquet #{alert['packet_number']}")
    print(f"  {alert['src_ip']}:{alert['src_port']} -> {alert['dst_ip']}:{alert['dst_port']}")
    print(f"  Données détectées: {alert['matched_data']}\n")

# Récupérer les alertes critiques
critical_alerts = analyzer.get_alerts_by_severity(pcap_file_id=1, severity='CRITICAL')

# Récupérer toutes les alertes
all_alerts = analyzer.get_all_alerts()
```

### Intégration avec ingestion_pcap

```python
from ingestion_pcap import PcapIngestion

# Avec analyse de menaces activée (par défaut)
ingestion = PcapIngestion(
    db_path='pcap_database.db',
    enable_yara=True,
    yara_rules_path='config/threat_rules.yaml'
)

# Ingérer et analyser
pcap_id = ingestion.ingest_pcap('captures/capture.pcap', analyze=True)

# Récupérer les alertes via l'analyseur intégré
if ingestion.yara_analyzer:
    alerts = ingestion.yara_analyzer.get_all_alerts(pcap_id)
```

## Personnalisation des règles

### Ajouter une nouvelle règle

Éditez `config/threat_rules.yaml` :

```yaml
rules:
  # ... règles existantes ...
  
  - name: Detection_Cryptomining
    description: Détecte des indicateurs de cryptomining
    severity: MEDIUM
    patterns:
      - 'stratum\\+tcp://'
      - 'xmr-node'
      - 'cryptonight'
      - 'monero'
    case_sensitive: false
    
  - name: Detection_Ransomware
    description: Détecte des indicateurs de ransomware
    severity: CRITICAL
    patterns:
      - '\\.encrypted'
      - 'DECRYPT_INSTRUCTIONS'
      - 'pay.*bitcoin'
      - 'files.*encrypted'
    case_sensitive: false
```

### Exemples de patterns regex utiles

```yaml
# Détection d'adresses email
- '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}'

# Détection d'URLs suspectes
- 'http://[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}'

# Détection de clés privées
- '-----BEGIN (RSA |)PRIVATE KEY-----'

# Détection de tokens JWT
- 'eyJ[a-zA-Z0-9_-]*\\.[a-zA-Z0-9_-]*\\.[a-zA-Z0-9_-]*'

# Détection de numéros de carte bancaire
- '[0-9]{4}[\\s-]?[0-9]{4}[\\s-]?[0-9]{4}[\\s-]?[0-9]{4}'
```

## Base de données

### Structure de la table threat_alerts

```sql
CREATE TABLE threat_alerts (
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
    detection_time TEXT
);
```

### Requêtes SQL utiles

```sql
-- Compter les alertes par sévérité
SELECT severity, COUNT(*) as count 
FROM threat_alerts 
GROUP BY severity 
ORDER BY 
    CASE severity
        WHEN 'CRITICAL' THEN 1
        WHEN 'HIGH' THEN 2
        WHEN 'MEDIUM' THEN 3
        WHEN 'LOW' THEN 4
        WHEN 'INFO' THEN 5
    END;

-- Top 10 des règles déclenchées
SELECT rule_name, COUNT(*) as count 
FROM threat_alerts 
GROUP BY rule_name 
ORDER BY count DESC 
LIMIT 10;

-- Alertes critiques récentes
SELECT * FROM threat_alerts 
WHERE severity = 'CRITICAL' 
ORDER BY detection_time DESC 
LIMIT 20;

-- Alertes par IP source
SELECT src_ip, COUNT(*) as alert_count 
FROM threat_alerts 
WHERE src_ip IS NOT NULL 
GROUP BY src_ip 
ORDER BY alert_count DESC;

-- Alertes sur une période spécifique
SELECT * FROM threat_alerts 
WHERE timestamp BETWEEN '2025-12-01' AND '2025-12-31'
ORDER BY timestamp;
```

## Niveaux de sévérité

| Niveau | Description | Exemples |
|--------|-------------|----------|
| **INFO** | Information, pas nécessairement malveillant | Scan de ports basique |
| **LOW** | Menace faible, nécessite surveillance | Pattern suspect mais pas confirmé |
| **MEDIUM** | Menace moyenne, investigation recommandée | XSS, Path Traversal |
| **HIGH** | Menace élevée, action requise | Injection SQL, Command Injection, Fuites d'identifiants |
| **CRITICAL** | Menace critique, action immédiate | Reverse Shell, Transfert d'exécutables |

## Workflow recommandé

### 1. Capture réseau

```bash
# Démarrer une capture
python capture_reseau.py -i eth0 -d 300

# Ou utiliser le service
python capture_service.py --start
```

### 2. Analyse automatique

```bash
# Ingestion avec analyse de menaces
python ingestion_pcap.py -f captures/capture_20251203_122118.pcap
```

### 3. Revue des alertes

```bash
# Vérifier les alertes critiques
python ingestion_pcap.py --yara-alerts 1 --yara-severity CRITICAL

# Vérifier toutes les alertes
python ingestion_pcap.py --yara-alerts 1
```

### 4. Investigation

```bash
# Examiner les paquets suspects
python ingestion_pcap.py --query --pcap-id 1 --protocol TCP

# Analyser les flux
python ingestion_pcap.py --flows -f captures/capture_20251203_122118.pcap
```

## Logs

Les logs d'analyse sont stockés dans :
- `logs/threat_analysis_YYYYMMDD.log` : Logs de l'analyseur de menaces
- `logs/ingestion_YYYYMMDD.log` : Logs de l'ingestion PCAP

## Limitations et considérations

### Performance
- L'analyse peut être lente sur de gros fichiers PCAP (>1 Go)
- Utilisez des règles ciblées pour améliorer les performances
- Considérez l'analyse par lots pour les très gros fichiers

### Faux positifs
- Les règles basées sur patterns peuvent générer des faux positifs
- Ajustez les règles selon votre environnement réseau
- Utilisez la case_sensitivity de manière appropriée

### Confidentialité
- Les alertes stockent des extraits de données réseau
- Assurez-vous de respecter les réglementations de confidentialité
- Limitez l'accès à la base de données

## Dépannage

### L'analyseur ne détecte rien
1. Vérifiez que les règles sont chargées : `python threat_analyzer.py --list-alerts`
2. Vérifiez le fichier de règles : `cat config/threat_rules.yaml`
3. Activez le mode verbose : modifiez `verbose=True` dans le code

### Erreurs de règles
1. Vérifiez la syntaxe YAML
2. Testez les regex : `python -c "import re; re.compile('votre_pattern')"`
3. Consultez les logs : `tail -f logs/threat_analysis_*.log`

### Base de données corrompue
```bash
# Sauvegarde
cp pcap_database.db pcap_database.db.backup

# Réinitialisation
rm pcap_database.db
python ingestion_pcap.py -f captures/test.pcap
```

## Exemples avancés

### Script de surveillance continue

```python
#!/usr/bin/env python3
import time
from pathlib import Path
from ingestion_pcap import PcapIngestion
from threat_analyzer import ThreatAnalyzer

def monitor_directory(watch_dir='captures', interval=60):
    """Surveille un répertoire et analyse les nouveaux fichiers"""
    ingestion = PcapIngestion(enable_yara=True)
    processed = set()
    
    while True:
        for pcap_file in Path(watch_dir).glob('*.pcap'):
            if pcap_file not in processed:
                print(f"Nouveau fichier détecté: {pcap_file}")
                pcap_id = ingestion.ingest_pcap(str(pcap_file))
                
                if pcap_id and ingestion.yara_analyzer:
                    alerts = ingestion.yara_analyzer.get_all_alerts(pcap_id)
                    critical = [a for a in alerts if a['severity'] == 'CRITICAL']
                    
                    if critical:
                        print(f"⚠️  ALERTES CRITIQUES: {len(critical)}")
                        # Envoyer notification, email, etc.
                
                processed.add(pcap_file)
        
        time.sleep(interval)

if __name__ == '__main__':
    monitor_directory()
```

### Export des alertes en JSON

```python
import json
from threat_analyzer import ThreatAnalyzer

analyzer = ThreatAnalyzer()
alerts = analyzer.get_all_alerts()

# Export
with open('alertes_export.json', 'w') as f:
    json.dump(alerts, f, indent=2)

print(f"{len(alerts)} alertes exportées")
```

## Support et contribution

Pour signaler des bugs ou proposer des améliorations :
- Consultez la documentation principale : `docs/GuideUtilisationCapturePCAP.md`
- Ajoutez vos propres règles de détection
- Partagez vos patterns utiles

---

**Celestis_IA - Module Zeus**  
*Analyse intelligente de menaces réseau*

