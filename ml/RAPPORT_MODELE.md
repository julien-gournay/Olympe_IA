# Documentation des Rapports de Modèle

## Vue d'ensemble

Lors de la génération d'un modèle d'IA, le système crée automatiquement un **rapport texte détaillé** qui documente toutes les informations importantes sur le modèle et les données utilisées pour l'entraînement.

## Fichiers générés

Pour chaque modèle (par exemple `Zeus1`), les fichiers suivants sont créés :

| Fichier | Description |
|---------|-------------|
| `Zeus1.pkl` | Le modèle entraîné (fichier binaire) |
| `Zeus1_scaler.pkl` | Le scaler pour la normalisation des données |
| `Zeus1_metadata.json` | Métadonnées au format JSON |
| **`Zeus1_report.txt`** | **📄 Rapport texte détaillé (NOUVEAU)** |

## Contenu du Rapport Texte

Le rapport `*_report.txt` contient les sections suivantes :

### 1. Informations sur le Modèle
- Type de modèle (Random Forest, Isolation Forest, etc.)
- Paramètres du modèle (nombre d'arbres, profondeur, etc.)
- Date de génération

### 2. Métriques d'Entraînement
- Nombre d'échantillons (entraînement et validation)
- Précision sur l'entraînement et la validation
- ROC AUC Score (si disponible)
- Rapport de classification détaillé pour chaque classe :
  - Classe 0 (Normal) : Précision, Rappel, F1-Score, Support
  - Classe 1 (Malveillant) : Précision, Rappel, F1-Score, Support
- Matrice de confusion :
  - Vrais Négatifs (TN)
  - Faux Positifs (FP)
  - Faux Négatifs (FN)
  - Vrais Positifs (TP)

### 3. Importance des Caractéristiques
- Top 15 des features les plus importantes pour la détection
- Pourcentage d'importance de chaque feature

### 4. Menaces Détectées dans les Données d'Entraînement
Cette section contient les informations extraites de la base de données :

- **Total d'alertes** générées pendant l'analyse
- **Alertes par sévérité** :
  - CRITICAL : nombre et pourcentage
  - HIGH : nombre et pourcentage
  - MEDIUM : nombre et pourcentage
  - LOW : nombre et pourcentage
- **Top 10 des règles YARA/Threat déclenchées** :
  - Nom de la règle
  - Sévérité
  - Nombre de fois déclenchée
- **Nombre de fichiers PCAP analysés**
- **Détails des fichiers PCAP** (nom et nombre d'alertes)

### 5. Historique d'Entraînement
Si le modèle a été ré-entraîné plusieurs fois, cette section montre l'historique complet avec :
- Date et heure de chaque entraînement
- Nombre d'échantillons utilisés
- Précision obtenue

## Exemple de Rapport

```
======================================================================
  RAPPORT DU MODÈLE: Zeus1
======================================================================

Date de génération: 2026-01-28 15:30:45

----------------------------------------------------------------------
1. INFORMATIONS SUR LE MODÈLE
----------------------------------------------------------------------
Type de modèle: RandomForestClassifier
Nombre d'arbres: 100
Profondeur maximale: 20

----------------------------------------------------------------------
2. MÉTRIQUES D'ENTRAÎNEMENT
----------------------------------------------------------------------
Échantillons d'entraînement: 4000
Échantillons de validation: 1000
Précision (entraînement): 0.9850 (98.50%)
Précision (validation): 0.9640 (96.40%)
ROC AUC Score: 0.9823

Rapport de classification détaillé:

  Classe 0 (Normal):
    Précision: 0.9700
    Rappel: 0.9800
    F1-Score: 0.9750
    Support: 850

  Classe 1 (Malveillant):
    Précision: 0.9450
    Rappel: 0.9200
    F1-Score: 0.9323
    Support: 150

Matrice de confusion:
  Vrais Négatifs (TN): 833
  Faux Positifs (FP): 17
  Faux Négatifs (FN): 12
  Vrais Positifs (TP): 138

----------------------------------------------------------------------
3. IMPORTANCE DES CARACTÉRISTIQUES (Top 15)
----------------------------------------------------------------------
   1. Feature # 8: 0.085432 (8.543%)
   2. Feature #12: 0.074821 (7.482%)
   3. Feature #23: 0.068234 (6.823%)
   ...

----------------------------------------------------------------------
4. MENACES DÉTECTÉES DANS LES DONNÉES D'ENTRAÎNEMENT
----------------------------------------------------------------------
Total d'alertes: 1245

Alertes par sévérité:
  CRITICAL  :    125 (10.04%)
  HIGH      :    456 (36.63%)
  MEDIUM    :    523 (42.01%)
  LOW       :    141 (11.32%)

Top 10 des règles YARA/Threat déclenchées:
   1. Suspicious_SQL_Injection        [HIGH    ] -   234 fois
   2. Suspicious_XSS_Attempt          [MEDIUM  ] -   189 fois
   3. Suspicious_Command_Injection    [HIGH    ] -   156 fois
   4. Malware_UserAgent               [HIGH    ] -   134 fois
   5. Suspicious_Executable_Transfer  [CRITICAL] -   125 fois
   ...

Nombre de fichiers PCAP analysés: 2

Détails des fichiers PCAP:
  - training_ai.pcap: 1245 alertes

======================================================================
FIN DU RAPPORT
======================================================================
```

## Utilisation

### Consultation du Rapport

Après l'entraînement d'un modèle, vous pouvez consulter le rapport directement :

```bash
# Ouvrir avec un éditeur de texte
notepad ml/models/Zeus1_report.txt

# Ou afficher dans le terminal
cat ml/models/Zeus1_report.txt
```

### Comparaison de Modèles

Vous pouvez comparer plusieurs versions de modèles en consultant leurs rapports respectifs :

```bash
# Comparer Zeus1 et Zeus2
diff ml/models/Zeus1_report.txt ml/models/Zeus2_report.txt
```

### Intégration dans le Workflow

Le rapport est automatiquement généré à la fin du workflow d'entraînement. Vous verrez la confirmation dans la sortie :

```
[OK] Modèle entraîné: Zeus1
[OK] Emplacement modèle: c:\...\ml\models\Zeus1.pkl (125.43 KB)
[OK] Rapport détaillé: c:\...\ml\models\Zeus1_report.txt (8.52 KB)
```

## Avantages

1. **Traçabilité** : Toutes les informations importantes sont documentées automatiquement
2. **Reproductibilité** : Permet de comprendre comment le modèle a été créé
3. **Analyse** : Facilite l'analyse des performances et l'identification des problèmes
4. **Audit** : Fournit un historique complet pour l'audit de sécurité
5. **Documentation** : Sert de documentation automatique pour chaque modèle

## Cas d'Usage

### 1. Analyse de Performance
Consultez le rapport pour comprendre pourquoi un modèle performe mieux qu'un autre.

### 2. Identification des Menaces
Vérifiez quelles menaces ont été détectées le plus fréquemment dans vos données.

### 3. Optimisation
Utilisez les informations sur l'importance des features pour optimiser l'extraction de caractéristiques.

### 4. Reporting
Utilisez le rapport pour présenter les résultats à votre équipe ou management.

## Notes Techniques

- Le rapport est encodé en UTF-8 pour supporter tous les caractères
- Le format est lisible par des humains et parsable par des scripts
- Les statistiques sont mises à jour à chaque ré-entraînement
- Le rapport inclut uniquement les données disponibles au moment de la génération

## Personnalisation Future

Le format du rapport peut être étendu pour inclure :
- Graphiques et visualisations (si exporté en HTML/PDF)
- Recommandations automatiques d'amélioration
- Comparaisons avec des modèles précédents
- Alertes sur des anomalies dans les données d'entraînement
