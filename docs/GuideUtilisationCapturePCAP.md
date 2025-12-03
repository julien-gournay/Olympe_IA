# Guide d'utilisation - Capture et Analyse PCAP
**Celestis_IA - Module Zeus**

---

## 📖 Table des matières

1. [Introduction](#introduction)
2. [Installation rapide](#installation-rapide)
3. [Capture de trafic réseau](#capture-de-trafic-réseau)
4. [Ingestion et analyse](#ingestion-et-analyse)
5. [Service continu](#service-continu)
6. [Cas d'usage pratiques](#cas-dusage-pratiques)
7. [FAQ](#faq)

---

## 🎯 Introduction

Le module Zeus de Celestis_IA permet de capturer, stocker et analyser le trafic réseau en local. Il est composé de 3 outils principaux :

| Outil | Usage |
|-------|-------|
| **capture_reseau.py** | Capture interactive de paquets réseau |
| **ingestion_pcap.py** | Stockage et analyse des fichiers PCAP |
| **capture_service.py** | Service automatisé de capture continue |

---

## ⚡ Installation rapide

### 1. Installer les dépendances

```powershell
cd C:\Users\tomcu\Documents\GitHub\Celestis_IA\zeus
pip install -r requirements.txt
```

### 2. Déployer la solution

```powershell
python deploy_capture.py --deploy
```

Cela va :
- ✅ Vérifier les dépendances (Scapy, PyYAML)
- ✅ Créer les répertoires (`captures/`, `logs/`, `exports/`)
- ✅ Initialiser la base de données SQLite
- ✅ Effectuer un test de capture

### 3. Vérifier l'installation

```powershell
python deploy_capture.py --status
```

### 4. Configuration avancée du déploiement

Le script de déploiement offre plusieurs options utiles :

- **Générer une configuration exemple** :
  ```powershell
  python deploy_capture.py --generate-config
  ```

- **Vérifier uniquement les dépendances** :
  ```powershell
  python deploy_capture.py --check-deps
  ```

---

## 📡 Capture de trafic réseau

### Lister les interfaces réseau

```powershell
python capture_reseau.py --list-interfaces
```

**Exemple de sortie :**
```
Interfaces réseau disponibles:
  1. \Device\NPF_{12345678-...}
  2. Ethernet
  3. Wi-Fi
  4. Loopback
```

### Capture basique

#### Capturer 100 paquets

```powershell
python capture_reseau.py -c 100
```

Le script vous demandera de choisir une interface. Les paquets seront sauvegardés dans `captures/capture_YYYYMMDD_HHMMSS.pcap`.

#### Capturer pendant 30 secondes

```powershell
python capture_reseau.py -t 30
```

#### Capturer sur une interface spécifique

```powershell
python capture_reseau.py -i Wi-Fi -c 500
```

### Capture avec filtres BPF

Les filtres BPF (Berkeley Packet Filter) permettent de cibler précisément le trafic à capturer.

#### Trafic HTTP uniquement

```powershell
python capture_reseau.py -f "tcp port 80" -c 1000
```

#### Trafic HTTPS uniquement

```powershell
python capture_reseau.py -f "tcp port 443" -t 60
```

#### Trafic DNS

```powershell
python capture_reseau.py -f "udp port 53" -c 200
```

#### Trafic d'un hôte spécifique

```powershell
python capture_reseau.py -f "host 192.168.1.100" -c 500
```

#### Trafic d'un sous-réseau

```powershell
python capture_reseau.py -f "net 192.168.1.0/24" -t 120
```

#### Combinaison de filtres

```powershell
# HTTP ou HTTPS
python capture_reseau.py -f "tcp port 80 or tcp port 443" -c 2000

# Trafic TCP vers un hôte spécifique
python capture_reseau.py -f "tcp and host 8.8.8.8" -c 300

# Exclure le trafic SSH
python capture_reseau.py -f "not tcp port 22" -c 1000
```

### Options avancées

#### Spécifier le nom du fichier

```powershell
python capture_reseau.py -c 500 -n ma_capture.pcap
```

#### Changer le répertoire de sortie

```powershell
python capture_reseau.py -o C:\Captures -c 1000
```

#### Désactiver les statistiques

```powershell
python capture_reseau.py -c 500 --no-stats
```

### Résumé des options

```
Options principales :
  -i, --interface      Interface réseau (ex: Wi-Fi, Ethernet)
  -c, --count          Nombre de paquets à capturer
  -t, --timeout        Durée en secondes
  -f, --filter         Filtre BPF
  -o, --output-dir     Répertoire de sortie
  -n, --filename       Nom du fichier PCAP
  --list-interfaces    Lister les interfaces
  --no-stats          Pas de statistiques
```

---

## 💾 Ingestion et analyse

### Ingestion d'un fichier PCAP

#### Ingérer un fichier spécifique

```powershell
python ingestion_pcap.py -f captures\capture_20251112_143000.pcap
```

**Sortie :**
```
Début de l'ingestion: captures\capture_20251112_143000.pcap
Paquets chargés: 8523
Analyse des paquets en cours...
  Paquets analysés: 1000
  Paquets analysés: 2000
  ...
Ingestion terminée. ID: 1, Paquets: 8523
```

#### Ingérer tous les fichiers d'un répertoire

```powershell
python ingestion_pcap.py -d captures
```

#### Ingérer avec pattern personnalisé

```powershell
python ingestion_pcap.py -d captures --pattern "capture_2025*.pcap"
```

### Lister les fichiers ingérés

```powershell
python ingestion_pcap.py --list
```

**Exemple de sortie :**
```
=== Fichiers PCAP ingérés ===

ID: 1
  Fichier: capture_20251112_143000.pcap
  Date: 2025-11-12T14:30:00
  Paquets: 8523
  Taille: 4.25 MB
  Durée: 120.50s

ID: 2
  Fichier: capture_20251112_150000.pcap
  Date: 2025-11-12T15:00:00
  Paquets: 12456
  Taille: 6.18 MB
  Durée: 180.20s
```

### Requêtes sur les paquets

#### Tous les paquets TCP

```powershell
python ingestion_pcap.py --query --protocol TCP
```

#### Filtrer par IP source

```powershell
python ingestion_pcap.py --query --src-ip 192.168.1.100
```

#### Filtrer par IP destination

```powershell
python ingestion_pcap.py --query --dst-ip 8.8.8.8
```

#### Requête sur un fichier PCAP spécifique

```powershell
python ingestion_pcap.py --query --pcap-id 1 --protocol UDP
```

#### Combiner les filtres

```powershell
python ingestion_pcap.py --query --pcap-id 1 --protocol TCP --src-ip 192.168.1.50
```

**Exemple de sortie :**
```
=== Résultats de la requête (45 paquets) ===

Paquet #1
  Temps: 2025-11-12T14:30:01.123456
  192.168.1.50:52341 -> 8.8.8.8:443
  Protocole: TCP
  Taille: 1460 bytes

Paquet #2
  Temps: 2025-11-12T14:30:01.234567
  192.168.1.50:52341 -> 8.8.8.8:443
  Protocole: TCP
  Taille: 1460 bytes
...
```

### Analyse de flux (Flows)

L'option `--flows` permet d'extraire et d'afficher les flux de communication (regroupement de paquets par connexion) d'un fichier PCAP.

```powershell
python ingestion_pcap.py -f captures\capture_20251112_143000.pcap --flows
```

**Exemple de sortie :**
```
=== Flux extraits (15) ===

Flux #1
  192.168.1.50:52341 -> 8.8.8.8:443 (TCP)
  Paquets: 150, Octets: 12540
  Durée: 15.2000s

Flux #2
  192.168.1.50:53 -> 8.8.8.8:53 (UDP)
  Paquets: 2, Octets: 180
  Durée: 0.0500s
...
```

### Export des données

#### Export en JSON

```powershell
python ingestion_pcap.py --export 1 -o exports\capture_1.json
```

Le fichier JSON contient :
- **pcap_info** : Métadonnées du fichier (nom, taille, durée, etc.)
- **statistics** : Statistiques complètes (protocoles, IPs uniques, etc.)
- **sample_packets** : Échantillon de 100 paquets

#### Exemple de structure JSON

```json
{
  "pcap_info": {
    "id": 1,
    "filename": "capture_20251112_143000.pcap",
    "packet_count": 8523,
    "duration": 120.5
  },
  "statistics": {
    "total_packets": "8523",
    "unique_src_ips": "12",
    "unique_dst_ips": "45",
    "protocol_tcp": "7821",
    "protocol_udp": "680",
    "protocol_icmp": "22"
  },
  "sample_packets": [...]
}
```

### Options de la base de données

#### Utiliser une base de données différente

```powershell
python ingestion_pcap.py -f capture.pcap --db ma_base.db
```

#### Spécifier le répertoire des logs

```powershell
python ingestion_pcap.py -d captures --log-dir mes_logs
```

---

## 🔄 Service continu

Le service permet d'automatiser la capture et l'ingestion.

### Mode continu (capture en boucle)

```powershell
python capture_service.py --continuous
```

Ce mode :
1. ✅ Capture des paquets selon la config (`max_packets`, `max_duration`)
2. ✅ Sauvegarde automatique dans `captures/`
3. ✅ Ingestion automatique dans la base de données
4. ✅ Attente de l'intervalle configuré
5. ✅ Répète le cycle

**Pour arrêter :** `Ctrl+C`

**Sortie exemple :**
```
Démarrage d'une session de capture (max 10000 paquets, 300s)
Capture terminée. Total de paquets: 8234
Capture sauvegardée: captures\capture_20251112_143000.pcap
Ingestion de capture_20251112_143000.pcap
Ingestion réussie (ID: 5)

--- Statistiques ---
Temps d'exécution: 305s
Captures complétées: 1
Total paquets: 8234
Fichiers ingérés: 1
-------------------

Attente de 60s avant la prochaine capture...
```

### Mode cycle unique

```powershell
python capture_service.py --single
```

Effectue une seule capture puis s'arrête. Utile pour les tâches planifiées.

### Mode surveillance

```powershell
python capture_service.py --watch
```

Surveille le répertoire `captures/` et ingère automatiquement les nouveaux fichiers PCAP.

**Cas d'usage :** Vous capturez manuellement avec `capture_reseau.py` et le service ingère automatiquement.

### Configuration du service

Éditez `config.yaml` pour personnaliser le comportement :

```yaml
capture:
  rotation:
    max_packets: 10000      # Rotation après 10k paquets
    max_duration: 300       # OU après 5 minutes

service:
  interval: 60              # Attente entre captures (secondes)

ingestion:
  auto_ingest: true         # Ingestion automatique
  watch_directory: captures # Répertoire surveillé

analysis:
  enable_statistics: true   # Activer les stats
  enable_export: false      # Export automatique JSON
```

---

## 💡 Cas d'usage pratiques

### Cas 1 : Débug d'une application web

**Objectif :** Capturer le trafic HTTP/HTTPS d'une application.

```powershell
# 1. Capturer le trafic web pendant 2 minutes
python capture_reseau.py -f "tcp port 80 or tcp port 443" -t 120 -n debug_web.pcap

# 2. Ingérer
python ingestion_pcap.py -f captures\debug_web.pcap

# 3. Analyser les connexions TCP
python ingestion_pcap.py --query --protocol TCP --pcap-id 1

# 4. Exporter pour analyse détaillée
python ingestion_pcap.py --export 1 -o debug_web.json
```

### Cas 2 : Monitoring de sécurité

**Objectif :** Surveiller le trafic d'un serveur suspect.

```powershell
# 1. Capturer tout le trafic d'une IP
python capture_reseau.py -f "host 192.168.1.50" -c 5000 -n surveillance.pcap

# 2. Ingérer et analyser
python ingestion_pcap.py -f captures\surveillance.pcap

# 3. Requêtes de sécurité
# Trafic sortant
python ingestion_pcap.py --query --src-ip 192.168.1.50

# Trafic entrant
python ingestion_pcap.py --query --dst-ip 192.168.1.50

# Connexions DNS suspectes
python ingestion_pcap.py --query --protocol UDP --src-ip 192.168.1.50
```

### Cas 3 : Analyse de performance réseau

**Objectif :** Diagnostiquer des lenteurs réseau.

```powershell
# 1. Capturer le trafic sur l'interface principale pendant 5 minutes
python capture_reseau.py -i Wi-Fi -t 300 -n performance.pcap

# 2. Ingérer
python ingestion_pcap.py -f captures\performance.pcap

# 3. Analyser les statistiques
python ingestion_pcap.py --list

# 4. Identifier les protocoles dominants
python ingestion_pcap.py --export 1 -o performance_stats.json
```

Analysez ensuite le JSON pour voir :
- Répartition des protocoles
- IPs les plus actives
- Volume de données

### Cas 4 : Monitoring 24/7

**Objectif :** Capture continue pour analyse ultérieure.

```powershell
# 1. Configurer la rotation dans config.yaml
# rotation:
#   max_packets: 50000
#   max_duration: 600  # 10 minutes

# 2. Lancer le service en continu
python capture_service.py --continuous
```

Le service créera automatiquement de nouveaux fichiers PCAP toutes les 10 minutes ou 50k paquets.

### Cas 5 : Analyse d'incident

**Objectif :** Capturer et analyser un incident réseau.

```powershell
# Pendant l'incident : capture urgente
python capture_reseau.py -c 10000 -n incident_urgent.pcap

# Après incident : analyse
python ingestion_pcap.py -f captures\incident_urgent.pcap

# Extraction des IPs impliquées
python ingestion_pcap.py --query --pcap-id 1 --protocol TCP

# Export pour rapport
python ingestion_pcap.py --export 1 -o rapport_incident.json
```

---

## ❓ FAQ

### Q1 : Pourquoi "Aucun paquet capturé" ?

**R :** Plusieurs causes possibles :

1. **Pas d'activité réseau** : Ouvrez un navigateur pour générer du trafic
2. **Interface incorrecte** : Listez les interfaces avec `--list-interfaces`
3. **Filtre BPF trop strict** : Testez sans filtre d'abord
4. **Permissions insuffisantes** : 
   - Windows : Exécutez en tant qu'administrateur
   - Linux/macOS : Utilisez `sudo`

### Q2 : Comment filtrer seulement le trafic sortant ?

**R :** Utilisez un filtre BPF avec votre IP locale :

```powershell
python capture_reseau.py -f "src host 192.168.1.10" -c 1000
```

### Q3 : La base de données devient trop volumineuse

**R :** Plusieurs solutions :

1. **Nettoyer les anciennes captures**
```powershell
# Supprimer la base et réingérer seulement les fichiers récents
Remove-Item pcap_database.db
python ingestion_pcap.py -d captures --pattern "capture_202511*.pcap"
```

2. **Utiliser plusieurs bases de données**
```powershell
python ingestion_pcap.py -f capture.pcap --db base_novembre.db
```

### Q4 : Comment capturer sur plusieurs interfaces simultanément ?

**R :** Lancez plusieurs instances :

```powershell
# Terminal 1
python capture_reseau.py -i Wi-Fi -c 5000 -n wifi.pcap

# Terminal 2
python capture_reseau.py -i Ethernet -c 5000 -n ethernet.pcap
```

### Q5 : Puis-je analyser des fichiers PCAP existants ?

**R :** Oui ! Copiez vos fichiers `.pcap` dans `captures/` puis :

```powershell
python ingestion_pcap.py -d captures
```

### Q6 : Comment automatiser les captures avec le Planificateur de tâches Windows ?

**R :** Créez une tâche planifiée :

1. Ouvrez "Planificateur de tâches"
2. Créez une tâche de base
3. **Déclencheur** : Quotidien à 00h00
4. **Action** : 
   - Programme : `python.exe`
   - Arguments : `C:\...\zeus\capture_service.py --single`
   - Répertoire : `C:\...\zeus`

### Q7 : Les captures fonctionnent mais pas l'ingestion

**R :** Vérifiez :

1. **Base de données** : 
```powershell
python deploy_capture.py --status
```

2. **Permissions sur le fichier de base**
```powershell
# Windows
Get-Acl pcap_database.db | Format-List
```

3. **Réinitialisez la base**
```powershell
Remove-Item pcap_database.db
python deploy_capture.py --deploy --skip-test
```

### Q8 : Comment capturer uniquement les requêtes HTTP GET ?

**R :** BPF ne peut pas filtrer par contenu HTTP, mais vous pouvez :

1. Capturer tout le trafic HTTP
2. Ingérer dans la base
3. Utiliser Wireshark ou analyser le JSON pour filtrer

```powershell
python capture_reseau.py -f "tcp port 80" -c 2000
python ingestion_pcap.py -f captures\capture_*.pcap
python ingestion_pcap.py --export 1 -o http_traffic.json
```

Puis analysez le JSON avec un script Python ou jq.

### Q9 : Puis-je exporter en CSV ?

**R :** Actuellement, seul JSON est supporté. Pour convertir en CSV :

```powershell
# Exportez en JSON
python ingestion_pcap.py --export 1 -o data.json

# Utilisez PowerShell pour convertir
$data = Get-Content data.json | ConvertFrom-Json
$data.sample_packets | Export-Csv -Path data.csv -NoTypeInformation
```

### Q10 : Comment voir les statistiques en temps réel pendant la capture ?

**R :** Le module affiche automatiquement les statistiques toutes les 100 paquets :

```
Paquets capturés: 100
Paquets capturés: 200
Paquets capturés: 300
...
```

À la fin, un résumé complet est affiché sauf si vous utilisez `--no-stats`.

---

## 📞 Support et ressources

### Vérifier l'état du système

```powershell
python deploy_capture.py --status
```

### Consulter les logs

```powershell
# Logs de capture
Get-Content captures\capture.log -Tail 50

# Logs d'ingestion
Get-Content logs\ingestion_*.log -Tail 50

# Logs du service
Get-Content logs\service_*.log -Tail 50
```

### Réinitialisation complète

```powershell
# Supprimer la base et les logs
Remove-Item pcap_database.db -ErrorAction SilentlyContinue
Remove-Item -Recurse logs\* -ErrorAction SilentlyContinue

# Re-déployer
python deploy_capture.py --deploy
```

### Ressources utiles

- **Syntaxe BPF** : [https://biot.com/capstats/bpf.html](https://biot.com/capstats/bpf.html)
- **Documentation Scapy** : [https://scapy.readthedocs.io/](https://scapy.readthedocs.io/)
- **Npcap (Windows)** : [https://nmap.org/npcap/](https://nmap.org/npcap/)

---

## 📝 Résumé des commandes essentielles

```powershell
# Installation
pip install -r requirements.txt
python deploy_capture.py --deploy

# Capture basique
python capture_reseau.py -c 1000

# Capture avec filtre
python capture_reseau.py -f "tcp port 80" -c 500

# Ingestion
python ingestion_pcap.py -d captures

# Lister les captures ingérées
python ingestion_pcap.py --list

# Requête
python ingestion_pcap.py --query --protocol TCP

# Service continu
python capture_service.py --continuous

# Statut du système
python deploy_capture.py --status
```

---

**Version** : 1.0.0  
**Date** : 12 novembre 2025  
**Projet** : Celestis_IA - Module Zeus  
**Auteur** : Équipe Celestis_IA
