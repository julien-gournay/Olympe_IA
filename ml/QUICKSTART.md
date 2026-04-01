# 🚀 Guide de Démarrage Rapide - IA Adaptive

Ce guide vous permet de mettre en place rapidement l'IA qui apprend d'elle-même.

## ⚡ Installation Express

```bash
# 1. Installer les dépendances ML
cd ml
pip install -r requirements.txt

# 2. Revenir à la racine
cd ..
```

## 📚 Workflow Complet en 7 Étapes

### Étape 1 : Capturer du Trafic Réseau

```bash
cd zeus
python capture_reseau.py -i Wi-Fi -c 5000 -o captures/training_data.pcap
```

### Étape 2 : Ingérer et Analyser avec Règles

```bash
# Ingérer le PCAP
python ingestion_pcap.py -f captures/training_data.pcap --enable-yara

# Les alertes sont automatiquement détectées et stockées
```

### Étape 3 : Construire le Dataset ML

```bash
cd ../ml

# Construire le dataset depuis les alertes existantes
python trainer.py --build-dataset --db ../zeus/pcap_database.db
```

**Résultat attendu :**
```
Dataset construit: 15000 échantillons
  Normal: 13500 (90.0%)
  Malicious: 1500 (10.0%)
Shape: (15000, 50)
```

### Étape 4 : Entraîner le Modèle

```bash
# Entraîner un Random Forest (split anti-fuite + CV + tuning)
python trainer.py --train --model-type random_forest --model-name threat_detector --db ../zeus/pcap_database.db --dataset-mode packet --cv-folds 5 --tune-hyperparams
```

**Résultat attendu :**
```
Entraînement Random Forest...
Accuracy: Train=0.9842, Val=0.9521
ROC AUC: 0.9834

F1 (seuil optimisé): 0.94xx
Seuil optimisé: 0.63xx
Modèle sauvegardé: threat_detector
```

### Étape 5 : Utiliser l'IA pour Détecter

```bash
# Analyser de nouveaux fichiers PCAP
python ml_detector.py -f ../zeus/captures/new_traffic.pcap --model models/threat_detector

# Avec l'approche hybride (recommandé)
python hybrid_analyzer.py -f ../zeus/captures/new_traffic.pcap
```

### Étape 6 : Évaluer le modèle entraîné

```bash
python trainer.py --evaluate --model-type random_forest --model-name threat_detector --db ../zeus/pcap_database.db --dataset-mode packet
```

### Étape 7 : Comparer au modèle actif (et promotion optionnelle)

```bash
# Comparer un candidat à votre modèle actif
python trainer.py --compare --model-type random_forest --model-name threat_detector --candidate-model-name Zeus2 --db ../zeus/pcap_database.db --dataset-mode packet

# Promouvoir automatiquement si meilleur
python trainer.py --compare --model-type random_forest --model-name threat_detector --candidate-model-name Zeus2 --db ../zeus/pcap_database.db --dataset-mode packet --promote-if-better --active-model-name threat_detector
```

> `trainer.py` supporte aussi `--dataset-mode flow` pour entraîner/évaluer sur des flux plutôt que des paquets.

## 🎯 Cas d'Usage Pratiques

### Cas 1 : Première Utilisation (Pas de Données)

Si vous n'avez pas encore de données :

```bash
# 1. Générer des alertes de test avec les règles par défaut
cd zeus
python demo_threat_analysis.py --with-pcap captures/capture_20251203_120357.pcap

# 2. Construire et entraîner
cd ../ml
python trainer.py --build-dataset --db ../zeus/pcap_database.db
python trainer.py --train --model-type random_forest --model-name initial_model --db ../zeus/pcap_database.db
```

### Cas 2 : Amélioration Continue

Après quelques semaines d'utilisation :

```python
from ml.trainer import ContinuousLearningSystem

# Initialiser le système
system = ContinuousLearningSystem(db_path="../zeus/pcap_database.db")

# Ajouter du feedback
# (À intégrer dans votre workflow de validation des alertes)
system.add_feedback(
    pcap_file_id=5,
    packet_number=1234,
    predicted_label=1,    # IA a dit "malicious"
    actual_label=0,       # En fait c'était "normal" (faux positif)
    confidence=1.0
)

# Après accumulation de 10+ feedbacks
model, metrics = system.retrain_with_feedback(
    model_name="improved_model",
    model_type="random_forest"
)
```

### Cas 2 bis : Validation manuelle via interface locale

Pour valider/corriger les alertes manuellement et alimenter `ml_feedback` sans coder:

```bash
cd ml
python manual_validation_ui.py --db ../zeus/pcap_database.db
```

Fonctionnalités principales:
- Liste des alertes avec filtre des elements non valides
- Validation rapide: "Confirmer menace" (label=1) ou "Marquer normal" (label=0)
- Choix de la confiance du feedback (0 a 1)
- Ré-entraînement déclenchable directement depuis l'interface

Options utiles:

```bash
# Ajuster le seuil de feedback avant recommandation de ré-entraînement
python manual_validation_ui.py --db ../zeus/pcap_database.db --feedback-threshold 20
```

Intégration au workflow principal:

```bash
# Lance le workflow complet et ouvre l'UI à la fin
python train_ai_workflow.py --db zeus/pcap_database.db --open-validation-ui

# Lance le workflow sans poser la question d'ouverture d'UI
python train_ai_workflow.py --db zeus/pcap_database.db --no-validation-ui-prompt
```

### Cas 3 : Analyse en Temps Réel

Intégrer dans le service de capture :

```python
# Dans zeus/capture_service.py (à modifier)
from ml.ml_detector import MLThreatDetector

class CaptureServiceWithML(CaptureService):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.ml_detector = MLThreatDetector(
            model_path="ml/models/threat_detector"
        )
    
    def on_packet_captured(self, packet):
        # Analyse ML en temps réel
        if self.ml_detector.is_available():
            alert = self.ml_detector.analyze_packet(packet, self.packet_count)
            if alert and alert['ml_confidence'] > 0.9:
                self.logger.critical(f"🚨 ALERTE ML HAUTE CONFIANCE: {alert}")
```

## 🔄 Cycle d'Amélioration Continue

```
┌─────────────────────────────────────────────────────────┐
│                   SEMAINE 1-2                           │
│  Collecte de données + Entraînement initial            │
│  ✓ Capturer trafic                                     │
│  ✓ Analyser avec règles                                │
│  ✓ Entraîner premier modèle                            │
└──────────────────┬──────────────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────────────┐
│                   SEMAINE 3-4                           │
│  Utilisation + Feedback                                 │
│  ✓ Détecter avec ML                                    │
│  ✓ Valider les alertes                                 │
│  ✓ Collecter feedbacks                                 │
└──────────────────┬──────────────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────────────┐
│                   SEMAINE 5-6                           │
│  Ré-entraînement                                        │
│  ✓ Intégrer les feedbacks                              │
│  ✓ Nouveau modèle amélioré                             │
│  ✓ Comparer métriques                                  │
└──────────────────┬──────────────────────────────────────┘
                   │
                   └──────────────┐
                                  ▼
                          (Répéter le cycle)
```

## 📊 Métriques à Surveiller

Vérifiez régulièrement :

```bash
# Historique d'entraînement
sqlite3 ../zeus/pcap_database.db "SELECT * FROM ml_training_runs ORDER BY id DESC LIMIT 5;"

# Feedbacks en attente
sqlite3 ../zeus/pcap_database.db "SELECT COUNT(*) FROM ml_feedback WHERE used_for_training = 0;"

# Performance du modèle actuel
python -c "
from ml.threat_models import RandomForestThreatModel
model = RandomForestThreatModel()
model.load('threat_detector')
print('Historique:', model.training_history[-1])
"
```

## 🛠️ Personnalisation

### Ajuster la Sensibilité

```python
# Haute sensibilité (plus d'alertes, possibles faux positifs)
detector = MLThreatDetector(confidence_threshold=0.5)

# Basse sensibilité (moins d'alertes, plus précis)
detector = MLThreatDetector(confidence_threshold=0.9)

# Recommandé pour production
detector = MLThreatDetector(confidence_threshold=0.75)
```

### Choisir le Bon Modèle

| Modèle | Avantages | Quand l'utiliser |
|--------|-----------|------------------|
| **Random Forest** | Rapide, interprétable, précis | Début, production stable |
| **Isolation Forest** | Détecte anomalies, pas besoin labels | Trafic principalement normal |
| **Neural Network** | Très précis, adaptatif | Gros volumes (>100k samples) |

## ❓ Troubleshooting

### Erreur : "Model not found"
```bash
# Vérifier que le modèle existe
ls -la ml/models/

# Si vide, entraîner un modèle
python ml/trainer.py --train --model-name threat_detector
```

### Dataset trop petit
```bash
# Vérifier la taille
python ml/trainer.py --build-dataset

# Si < 1000 échantillons :
# - Capturer plus de trafic
# - Analyser plus de PCAP
# - Utiliser des datasets publics
```

### Faible précision
```bash
# Vérifier la balance des classes
# Si trop déséquilibré (>99% normal) :
# - Augmenter contamination pour Isolation Forest
# - Utiliser class_weight='balanced' (déjà fait)
# - Collecter plus d'exemples malveillants
```

## 🎓 Prochaines Étapes

1. **Lire le README complet** : `ml/README.md`
2. **Tester avec démo** : `python ml/demo_ml.py --all`
3. **Intégrer dans production** : `ml/hybrid_analyzer.py`
4. **Automatiser** : Créer un cron job pour ré-entraînement hebdomadaire

## 💡 Astuces Pro

- **Commencez simple** : Random Forest avec règles regex
- **Loguez tout** : Chaque prédiction, chaque feedback
- **Validez régulièrement** : Comparez avec règles connues
- **Gardez l'humain dans la boucle** : Ne faites pas confiance à 100%
- **Évoluez progressivement** : 70% confiance → 80% → 90%

Bon apprentissage ! 🚀
