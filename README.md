# Zeus - Détection de menaces par Intelligence Artificielle

Ce module implémente un système d'apprentissage automatique adaptatif pour la détection de menaces réseau.

## 🎯 Objectif

Créer une IA qui **apprend d'elle-même** à force de rencontrer les mêmes attaques et s'améliore continuellement avec le feedback utilisateur.

## 📁 Architecture

```
ml/
├── feature_extractor.py    # Extraction de caractéristiques des paquets
├── threat_models.py         # Modèles ML (Random Forest, Isolation Forest, Neural Networks)
├── trainer.py              # Entraînement et apprentissage continu
├── ml_detector.py          # Détecteur intégré avec Zeus
├── requirements.txt        # Dépendances Python
└── models/                 # Répertoire des modèles entraînés
```

## 🚀 Installation

```bash
cd ml
pip install -r requirements.txt
```

**Note**: TensorFlow est optionnel. Si vous ne voulez pas utiliser les réseaux de neurones, vous pouvez retirer cette ligne du `requirements.txt`.

## 📊 Fonctionnalités

### 1. **Extraction de Features (85 caractéristiques)**
- Features de base : taille, protocole, ports
- Features TCP : flags, window size, séquences
- Features payload : entropie, patterns suspects
- Features statistiques : timing, distributions
- Features comportementales : scans, bursts

### 2. **Modèles Disponibles**

#### **Random Forest** (Supervisé)
- Entraînement sur données labellisées
- Feature importance
- Haute précision
- Interprétable

#### **Isolation Forest** (Non supervisé)
- Détection d'anomalies
- Pas besoin de labels
- Détecte les patterns inhabituels

#### **Neural Network** (Supervisé - Optionnel)
- Deep learning
- Meilleure performance sur gros datasets
- Nécessite TensorFlow

### 3. **Apprentissage Continu**
Le système s'améliore automatiquement :
- Collecte du feedback utilisateur (vrai/faux positif)
- Ré-entraînement automatique après N feedbacks
- Historique des sessions d'entraînement
- Métriques de performance

## 🎓 Utilisation

### Étape 1 : Construire un Dataset

```bash
# À partir des alertes existantes dans la base de données
python trainer.py --build-dataset --db ../zeus/pcap_database.db
```

### Étape 2 : Entraîner un Modèle

```bash
# Random Forest (recommandé pour commencer, avec CV + tuning)
python trainer.py --train --model-type random_forest --model-name threat_detector --db ../zeus/pcap_database.db --cv-folds 5 --tune-hyperparams --dataset-mode packet

# Isolation Forest (détection d'anomalies)
python trainer.py --train --model-type anomaly --model-name anomaly_detector --db ../zeus/pcap_database.db
```

### Étape 3 : Évaluer et comparer un modèle

```bash
# Évaluer le modèle courant sur le dataset
python trainer.py --evaluate --model-type random_forest --model-name threat_detector --db ../zeus/pcap_database.db --dataset-mode packet

# Comparer baseline vs candidat
python trainer.py --compare --model-type random_forest --model-name threat_detector --candidate-model-name Zeus2 --db ../zeus/pcap_database.db --dataset-mode packet
```

### Étape 4 : Utiliser le Détecteur ML

```bash
# Analyser un fichier PCAP
python ml_detector.py -f ../zeus/captures/capture_20251203_120357.pcap --model models/threat_detector

# Avec seuil de confiance personnalisé
python ml_detector.py -f capture.pcap --threshold 0.8

# Afficher l'importance des features
python ml_detector.py -f capture.pcap --feature-importance
```

### Étape 5 : Apprentissage Continu

```python
from ml.trainer import ContinuousLearningSystem

# Initialiser le système
system = ContinuousLearningSystem(db_path="pcap_database.db")

# Ajouter du feedback (exemple : faux positif)
system.add_feedback(
    pcap_file_id=1,
    packet_number=42,
    predicted_label=1,  # Le modèle a prédit "malicious"
    actual_label=0,     # Mais c'était en fait "normal"
    confidence=1.0
)

# Ré-entraîner après accumulation de feedbacks
model, metrics = system.retrain_with_feedback(
    model_name="adaptive_threat_detector",
    model_type="random_forest"
)
```

## 🔄 Intégration avec Zeus

### Méthode 1 : Utiliser directement dans Python

```python
from ml.ml_detector import MLThreatDetector

# Créer le détecteur
detector = MLThreatDetector(
    model_path="ml/models/threat_detector",
    model_type="random_forest",
    confidence_threshold=0.7
)

# Analyser un PCAP
alerts = detector.analyze_pcap("captures/suspect.pcap")

# Les alertes ont le même format que threat_analyzer.py
for alert in alerts:
    print(f"{alert['severity']}: {alert['description']}")
    print(f"Confiance ML: {alert['ml_confidence']:.2%}")
```

### Méthode 2 : Combiner avec les règles regex

Modifiez `zeus/threat_analyzer.py` pour ajouter le ML :

```python
from ml.ml_detector import MLThreatDetector

class HybridThreatAnalyzer(ThreatAnalyzer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Ajouter le détecteur ML
        try:
            self.ml_detector = MLThreatDetector()
        except:
            self.ml_detector = None
    
    def analyze_packet(self, packet, packet_number):
        # Analyse avec règles regex
        regex_alerts = super().analyze_packet(packet, packet_number)
        
        # Analyse avec ML
        ml_alerts = []
        if self.ml_detector and self.ml_detector.is_available():
            ml_alert = self.ml_detector.analyze_packet(packet, packet_number)
            if ml_alert:
                ml_alerts.append(ml_alert)
        
        # Combiner les alertes
        return regex_alerts + ml_alerts
```

## 📈 Workflow Complet d'Apprentissage

```
1. Collecte initiale
   └─> Utiliser threat_analyzer.py pour détecter avec règles regex
   └─> Les alertes sont stockées dans la DB

2. Premier entraînement
   └─> trainer.py --build-dataset (utilise les alertes comme labels)
   └─> trainer.py --train (crée le modèle initial)

3. Utilisation en production
   └─> ml_detector.py analyse les nouveaux PCAP
   └─> Combine avec les règles regex pour double vérification

4. Feedback et amélioration
   └─> Utilisateur confirme/infirme les alertes
   └─> system.add_feedback() enregistre les corrections
   └─> Après N feedbacks, ré-entraînement automatique

5. Validation/évaluation continue
   └─> trainer.py --evaluate pour mesurer le modèle courant
   └─> trainer.py --compare pour décider la promotion
   └─> Option --promote-if-better pour mise à jour semi-automatique

6. Évolution continue
   └─> Le modèle s'améliore au fil du temps
   └─> Détecte de nouveaux patterns non couverts par les règles
   └─> S'adapte aux spécificités de votre réseau
```

## 🎯 Avantages de cette Approche

✅ **Apprentissage automatique** : Le modèle apprend des patterns sans règles explicites

✅ **Adaptation continue** : S'améliore avec le feedback utilisateur

✅ **Détection de nouvelles menaces** : Peut détecter des attaques inconnues (zero-day)

✅ **Complémentaire** : Fonctionne avec les règles regex existantes

✅ **Métriques de confiance** : Chaque alerte a un score de probabilité

✅ **Traçabilité** : Historique complet des entraînements

## 🔍 Exemple de Résultats

```
=== Entraînement du modèle ===
Dataset: 50000 échantillons
  Normal: 45000 (90.0%)
  Malicious: 5000 (10.0%)

Entraînement Random Forest...
Accuracy: Train=0.9842, Val=0.9521
ROC AUC: 0.9834

Top 5 Features importantes:
  1. Feature #42: 0.0834 (Entropie payload)
  2. Feature #29: 0.0621 (Nombre de ports uniques)
  3. Feature #24: 0.0519 (Moyenne entropie)
  4. Feature #1:  0.0487 (Taille du paquet)
  5. Feature #40: 0.0412 (Burst detection)
```

## 📚 Pour Aller Plus Loin

### Dataset Externe
Pour améliorer les performances, vous pouvez ajouter des datasets publics :
- **CICIDS2017** : Dataset d'intrusions
- **NSL-KDD** : Dataset classique de détection d'intrusions
- **CTU-13** : Dataset de botnet

### Amélirations Possibles
1. **Feature engineering** : Ajouter plus de features spécifiques
2. **Ensemble models** : Combiner plusieurs modèles
3. **Deep Learning** : LSTM pour analyser les séquences de paquets
4. **Active Learning** : Demander feedback sur les cas incertains
5. **Transfert Learning** : Pré-entraîner sur datasets publics

## ⚠️ Notes Importantes

- **Performance** : L'extraction de features peut être intensive en calcul
- **Mémoire** : Les gros PCAP peuvent nécessiter beaucoup de RAM
- **Balance** : Veillez à avoir un dataset équilibré (pas 99% normal)
- **Validation** : Toujours tester sur des données inconnues du modèle

## 🤝 Contribution

Ce module est conçu pour être extensible. N'hésitez pas à :
- Ajouter de nouvelles features dans `feature_extractor.py`
- Créer de nouveaux types de modèles dans `threat_models.py`
- Améliorer le système de feedback dans `trainer.py`
