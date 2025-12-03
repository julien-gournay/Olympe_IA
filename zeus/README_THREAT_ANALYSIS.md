# Système d'analyse de menaces réseau - Celestis_IA

## 📋 Vue d'ensemble

Le système d'analyse de menaces a été intégré avec succès au projet Celestis_IA. Il permet de détecter automatiquement des comportements suspects et des menaces potentielles dans les captures réseau (fichiers PCAP).

## ✨ Nouveautés ajoutées

### 1. Module d'analyse de menaces (`threat_analyzer.py`)

Un module complet d'analyse basé sur des patterns regex qui détecte :
- ✅ Injections SQL
- ✅ Cross-Site Scripting (XSS)
- ✅ Injections de commandes
- ✅ Path Traversal
- ✅ Malwares (User-Agent suspects)
- ✅ Transferts de fichiers exécutables
- ✅ Payloads encodés
- ✅ Reverse shells
- ✅ Fuites d'identifiants
- ✅ Scans de ports

### 2. Intégration avec `ingestion_pcap.py`

L'analyse de menaces est maintenant automatiquement exécutée lors de l'ingestion de fichiers PCAP.

### 3. Base de données

Nouvelle table `threat_alerts` pour stocker toutes les alertes détectées avec :
- Niveau de sévérité (INFO, LOW, MEDIUM, HIGH, CRITICAL)
- Détails du paquet (IP, ports, protocole)
- Pattern détecté et données correspondantes
- Timestamp de détection

### 4. Configuration flexible

Fichier de configuration YAML (`config/threat_rules.yaml`) pour :
- Personnaliser les règles de détection
- Ajouter de nouvelles menaces
- Ajuster la sensibilité

### 5. Documentation complète

- Guide complet d'utilisation : `docs/GuideAnalyseMenaces.md`
- Script de démonstration : `demo_threat_analysis.py`
- Exemples d'utilisation en Python et en ligne de commande

## 🚀 Utilisation rapide

### Installation

Les dépendances nécessaires sont déjà dans `requirements.txt` :
```bash
pip install -r requirements.txt
```

### Analyse d'un fichier PCAP

```bash
# Analyse simple
python threat_analyzer.py -f captures/capture.pcap

# Avec règles personnalisées
python threat_analyzer.py -f captures/capture.pcap -r mes_regles.yaml
```

### Ingestion avec analyse automatique

```bash
# Analyse activée par défaut
python ingestion_pcap.py -f captures/capture.pcap

# Désactiver l'analyse
python ingestion_pcap.py -f captures/capture.pcap --disable-yara
```

### Afficher les alertes

```bash
# Toutes les alertes pour un fichier PCAP (ID 1)
python ingestion_pcap.py --yara-alerts 1

# Alertes critiques uniquement
python ingestion_pcap.py --yara-alerts 1 --yara-severity CRITICAL
```

### Démonstration

```bash
# Voir toutes les règles disponibles
python demo_threat_analysis.py

# Analyser un fichier avec la démo
python demo_threat_analysis.py --with-pcap captures/capture.pcap

# Exemples de règles personnalisées
python demo_threat_analysis.py --custom-rules

# Exemples d'intégration
python demo_threat_analysis.py --integration
```

## 📊 Utilisation en Python

```python
from threat_analyzer import ThreatAnalyzer

# Initialiser
analyzer = ThreatAnalyzer()

# Analyser un fichier PCAP
alerts = analyzer.analyze_pcap('captures/capture.pcap')

# Traiter les alertes
for alert in alerts:
    if alert['severity'] in ['CRITICAL', 'HIGH']:
        print(f"⚠️  {alert['rule_name']}")
        print(f"   {alert['description']}")
        print(f"   {alert['src_ip']} -> {alert['dst_ip']}")
```

## 📁 Fichiers ajoutés/modifiés

### Nouveaux fichiers
- `zeus/threat_analyzer.py` - Module principal d'analyse de menaces
- `zeus/demo_threat_analysis.py` - Script de démonstration
- `zeus/config/threat_rules.yaml` - Règles de détection (créé auto)
- `docs/GuideAnalyseMenaces.md` - Documentation complète

### Fichiers modifiés
- `zeus/ingestion_pcap.py` - Intégration de l'analyse de menaces
- `zeus/config.yaml` - Ajout des paramètres YARA/threat analysis
- `zeus/pcap_database.db` - Nouvelle table `threat_alerts`

## 🎯 Niveaux de sévérité

| Niveau | Description | Action |
|--------|-------------|--------|
| **CRITICAL** | Menace critique | Action immédiate requise |
| **HIGH** | Menace élevée | Investigation urgente |
| **MEDIUM** | Menace moyenne | Surveillance recommandée |
| **LOW** | Menace faible | Information |
| **INFO** | Information | Aucune action |

## 🔧 Personnalisation

### Ajouter une règle personnalisée

Éditez `config/threat_rules.yaml` :

```yaml
rules:
  - name: Ma_Regle
    description: Description de la menace
    severity: HIGH
    patterns:
      - 'pattern1'
      - 'pattern2'
    case_sensitive: false
```

### Exemples de patterns utiles

```yaml
# Détection de Bitcoin
- 'bitcoin:[a-zA-Z0-9]{26,35}'

# Détection de tokens JWT
- 'eyJ[a-zA-Z0-9_-]*\\.[a-zA-Z0-9_-]*\\.[a-zA-Z0-9_-]*'

# Détection de clés AWS
- 'AKIA[0-9A-Z]{16}'
```

## 📈 Requêtes SQL utiles

```sql
-- Alertes critiques
SELECT * FROM threat_alerts 
WHERE severity = 'CRITICAL' 
ORDER BY detection_time DESC;

-- Top menaces détectées
SELECT rule_name, COUNT(*) as count 
FROM threat_alerts 
GROUP BY rule_name 
ORDER BY count DESC;

-- Alertes par IP source
SELECT src_ip, COUNT(*) as alert_count 
FROM threat_alerts 
WHERE src_ip IS NOT NULL 
GROUP BY src_ip 
ORDER BY alert_count DESC;
```

## 🔍 Workflow recommandé

1. **Capture réseau**
   ```bash
   python capture_reseau.py -i eth0 -d 300
   ```

2. **Analyse automatique**
   ```bash
   python ingestion_pcap.py -f captures/capture_*.pcap
   ```

3. **Revue des alertes**
   ```bash
   python ingestion_pcap.py --yara-alerts 1 --yara-severity CRITICAL
   ```

4. **Action sur les menaces**
   - Bloquer les IPs suspectes
   - Mettre à jour les règles firewall
   - Notifier l'équipe sécurité

## 🛡️ Sécurité et confidentialité

- Les alertes stockent des extraits de paquets réseau
- Respectez les réglementations de confidentialité (RGPD, etc.)
- Limitez l'accès à la base de données
- Chiffrez les données sensibles

## 📚 Documentation

Pour plus de détails, consultez :
- [Guide complet d'analyse de menaces](docs/GuideAnalyseMenaces.md)
- [Guide d'utilisation PCAP](docs/GuideUtilisationCapturePCAP.md)

## ✅ Tests effectués

- ✅ Import du module threat_analyzer
- ✅ Création automatique des règles par défaut
- ✅ Chargement de 10 règles de détection
- ✅ Analyse d'un fichier PCAP de 304 paquets
- ✅ Intégration avec ingestion_pcap.py
- ✅ Stockage des alertes en base de données
- ✅ Script de démonstration fonctionnel

## 🎉 Résultat

Le système d'analyse de menaces est maintenant **opérationnel** et prêt à détecter les comportements suspects dans votre trafic réseau !

## 💡 Conseils

1. **Commencez simple** : Utilisez les règles par défaut
2. **Testez régulièrement** : Analysez vos captures périodiquement
3. **Affinez les règles** : Adaptez selon votre environnement
4. **Automatisez** : Intégrez dans votre pipeline de sécurité
5. **Documentez** : Notez les faux positifs et ajustez

## 🚀 Prochaines étapes possibles

- [ ] Ajouter des notifications par email/Slack
- [ ] Créer un dashboard de visualisation
- [ ] Intégrer avec un SIEM
- [ ] Ajouter l'analyse comportementale
- [ ] Machine Learning pour la détection d'anomalies

---

**Celestis_IA - Module Zeus**  
*Protection intelligente de votre réseau*

