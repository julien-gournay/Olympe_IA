#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script de démonstration du système ML
Montre comment entraîner et utiliser les modèles
Celestis_IA - Module ML
"""

import sys
import logging
from pathlib import Path

# Configurer l'encodage UTF-8 pour Windows
if sys.platform == 'win32':
    try:
        if hasattr(sys.stdout, 'reconfigure') and hasattr(sys.stderr, 'reconfigure'):
            sys.stdout.reconfigure(encoding='utf-8')  # type: ignore[attr-defined]
            sys.stderr.reconfigure(encoding='utf-8')  # type: ignore[attr-defined]
    except Exception:
        pass

# Ajouter le chemin parent
sys.path.append(str(Path(__file__).parent.parent))

def demo_feature_extraction():
    """Démo d'extraction de features"""
    print("\n" + "="*70)
    print("DÉMONSTRATION - Extraction de Features ML")
    print("="*70)
    
    from scapy.all import rdpcap
    from ml.feature_extractor import NetworkFeatureExtractor
    
    # Vérifier si on a un fichier PCAP
    pcap_dir = Path("../zeus/captures")
    pcap_files = list(pcap_dir.glob("*.pcap"))
    
    if not pcap_files:
        print("\n[X] Aucun fichier PCAP trouvé dans zeus/captures/")
        print("   Capturez d'abord du trafic avec capture_reseau.py")
        return
    
    pcap_file = pcap_files[0]
    print(f"\n[*] Fichier: {pcap_file}")
    
    # Charger quelques paquets
    packets = rdpcap(str(pcap_file))[:5]
    print(f"[*] Paquets chargés: {len(packets)}")
    
    # Extraire les features
    extractor = NetworkFeatureExtractor()
    
    print("\n[*] Extraction des features du premier paquet...")
    features = extractor.extract_packet_features(packets[0])
    
    print(f"\n[OK] Features extraites: {len(features)} caractéristiques")
    print(f"  Shape: {features.shape}")
    print(f"\n  Exemples de valeurs:")
    print(f"    [0] Taille paquet: {features[0]:.0f}")
    print(f"    [1-5] Protocole (one-hot): {features[1:6]}")
    print(f"    [6-7] Ports: src={features[6]:.0f}, dst={features[7]:.0f}")
    print(f"    [42] Entropie: {features[42]:.2f}")
    
    print(f"\n[*] Extraction de features de flux (5 paquets)...")
    flow_features = extractor.extract_flow_features(packets)
    print(f"[OK] Features de flux: {len(flow_features)} caractéristiques")
    print(f"  Nombre de paquets: {flow_features[0]:.0f}")
    print(f"  Taille moyenne: {flow_features[1]:.1f} bytes")
    print(f"  Durée: {flow_features[5]:.3f}s")


def demo_training():
    """Démo d'entraînement de modèle"""
    print("\n" + "="*70)
    print("DÉMONSTRATION - Entraînement de Modèle ML")
    print("="*70)
    
    from ml.trainer import ThreatDatasetBuilder
    from ml.threat_models import RandomForestThreatModel
    
    print("\n[*] Construction du dataset depuis les alertes...")
    
    try:
        builder = ThreatDatasetBuilder("../zeus/pcap_database.db")
        X, y = builder.build_from_alerts()
        
        if len(X) == 0:
            print("\n[X] Aucune donnée disponible pour l'entraînement")
            print("   1. Capturez du trafic avec capture_reseau.py")
            print("   2. Ingérez avec ingestion_pcap.py")
            print("   3. Analysez avec threat_analyzer.py")
            return
        
        print(f"\n[OK] Dataset construit:")
        print(f"  Échantillons: {len(X)}")
        print(f"  Features: {X.shape[1]}")
        print(f"  Normal: {sum(y == 0)} ({sum(y == 0)/len(y)*100:.1f}%)")
        print(f"  Malicious: {sum(y == 1)} ({sum(y == 1)/len(y)*100:.1f}%)")
        
        # Entraîner
        print("\n[*] Entraînement du Random Forest...")
        model = RandomForestThreatModel()
        metrics = model.train(X, y, validation_split=0.2)
        
        print(f"\n[OK] Entraînement terminé!")
        print(f"  Accuracy (train): {metrics['train_accuracy']:.4f}")
        print(f"  Accuracy (val): {metrics['val_accuracy']:.4f}")
        
        if 'roc_auc' in metrics:
            print(f"  ROC AUC: {metrics['roc_auc']:.4f}")
        
        # Sauvegarder
        print("\n[*] Sauvegarde du modèle...")
        model.save("demo_model")
        print("  [OK] Modèle sauvegardé: models/demo_model.pkl")
        
        # Top features
        print("\n[*] Top 10 Features importantes:")
        for i, (feat_idx, importance) in enumerate(metrics['top_features'], 1):
            print(f"  {i:2d}. Feature #{feat_idx:2d}: {importance:.4f}")
        
    except Exception as e:
        print(f"\n[X] Erreur: {e}")


def demo_detection():
    """Démo de détection avec ML"""
    print("\n" + "="*70)
    print("DÉMONSTRATION - Détection de Menaces avec ML")
    print("="*70)
    
    from ml.ml_detector import MLThreatDetector
    
    # Vérifier si on a un modèle
    model_path = Path("models/demo_model.pkl")
    if not model_path.exists():
        print("\n[X] Modèle non trouvé: models/demo_model.pkl")
        print("   Lancez d'abord: python demo_ml.py --train")
        return
    
    # Vérifier si on a un PCAP
    pcap_dir = Path("../zeus/captures")
    pcap_files = list(pcap_dir.glob("*.pcap"))
    
    if not pcap_files:
        print("\n[X] Aucun fichier PCAP trouvé")
        return
    
    pcap_file = pcap_files[0]
    print(f"\n[*] Fichier: {pcap_file}")
    
    # Créer le détecteur
    print("\n[*] Initialisation du détecteur ML...")
    detector = MLThreatDetector(
        model_path="models/demo_model",
        model_type="random_forest",
        confidence_threshold=0.7
    )
    
    if not detector.is_available():
        print("[X] Détecteur non disponible")
        return
    
    print("[OK] Détecteur initialisé")
    
    # Analyser
    print(f"\n[*] Analyse ML du fichier PCAP...")
    alerts = detector.analyze_pcap(str(pcap_file), verbose=False)
    
    print(f"\n[OK] Analyse terminée: {len(alerts)} alerte(s) détectée(s)")
    
    if alerts:
        print("\n[*] Détails des alertes:")
        for i, alert in enumerate(alerts[:5], 1):  # Top 5
            print(f"\n  Alerte #{i}:")
            print(f"    Paquet: #{alert['packet_number']}")
            print(f"    Sévérité: {alert['severity']}")
            print(f"    Confiance ML: {alert['ml_confidence']:.2%}")
            print(f"    Protocole: {alert['protocol']}")
            if alert['src_ip']:
                print(f"    Flux: {alert['src_ip']}:{alert['src_port']} -> {alert['dst_ip']}:{alert['dst_port']}")


def demo_continuous_learning():
    """Démo d'apprentissage continu"""
    print("\n" + "="*70)
    print("DÉMONSTRATION - Apprentissage Continu")
    print("="*70)
    
    from ml.trainer import ContinuousLearningSystem
    
    print("\n[*] Système d'apprentissage adaptatif")
    print("\nCe système permet au modèle de s'améliorer avec le feedback:")
    
    print("\n1. Feedback Utilisateur")
    print("   |-> Confirmer/infirmer les alertes")
    print("   |-> Corriger les faux positifs/négatifs")
    
    print("\n2. Accumulation")
    print("   |-> Stockage dans ml_feedback")
    print("   |-> Seuil: N feedbacks (configurable)")
    
    print("\n3. Ré-entraînement Automatique")
    print("   |-> Intégration des nouveaux exemples")
    print("   |-> Amélioration du modèle")
    
    print("\n4. Déploiement")
    print("   |-> Nouveau modèle utilisé")
    print("   |-> Métriques trackées")
    
    print("\n[*] Exemple de code:")
    print("""
    system = ContinuousLearningSystem(db_path="pcap_database.db")
    
    # Ajouter feedback (faux positif)
    system.add_feedback(
        pcap_file_id=1,
        packet_number=42,
        predicted_label=1,  # Prédit: malicious
        actual_label=0,     # Réel: normal
        confidence=1.0
    )
    
    # Ré-entraîner après accumulation
    model, metrics = system.retrain_with_feedback(
        model_name="adaptive_model",
        model_type="random_forest"
    )
    """)


def demo_hybrid_approach():
    """Démo d'approche hybride règles + ML"""
    print("\n" + "="*70)
    print("DÉMONSTRATION - Approche Hybride (Règles + ML)")
    print("="*70)
    
    print("\n[*] Stratégie recommandée:")
    print("\n1. Règles Regex (threat_analyzer.py)")
    print("   [+] Détection rapide de patterns connus")
    print("   [+] Explications claires (quel pattern a matché)")
    print("   [+] Faible taux de faux positifs")
    print("   [-] Limité aux patterns définis")
    
    print("\n2. Machine Learning (ml_detector.py)")
    print("   [+] Détecte des patterns complexes invisibles")
    print("   [+] S'adapte aux nouvelles menaces")
    print("   [+] Apprend des exemples")
    print("   [-] Peut générer des faux positifs")
    
    print("\n3. Combinaison Optimale")
    print("   |-> Règles : Haute confiance, faible couverture")
    print("   |-> ML : Confiance variable, haute couverture")
    print("   |-> Ensemble : Meilleur des deux mondes")
    
    print("\n[*] Architecture suggérée:")
    print("""
    ┌─────────────────────┐
    │   Paquet réseau     │
    └──────────┬──────────┘
               │
       ┌───────┴───────┐
       │               │
       ▼               ▼
    ┌─────┐        ┌─────┐
    │Regex│        │ ML  │
    │Rules│        │Model│
    └──┬──┘        └──┬──┘
       │              │
       └──────┬───────┘
              ▼
       ┌─────────────┐
       │   Fusion    │
       │  d'alertes  │
       └──────┬──────┘
              │
              ▼
       ┌─────────────┐
       │  Priorité   │
       │  Confiance  │
       └──────┬──────┘
              │
              ▼
         [Alerte finale]
    """)


def main():
    """Menu principal"""
    import argparse
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(message)s'
    )
    
    parser = argparse.ArgumentParser(
        description="Démonstration du système ML - Celestis_IA",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('--features', action='store_true',
                       help='Démo extraction de features')
    parser.add_argument('--train', action='store_true',
                       help='Démo entraînement de modèle')
    parser.add_argument('--detect', action='store_true',
                       help='Démo détection avec ML')
    parser.add_argument('--continuous', action='store_true',
                       help='Démo apprentissage continu')
    parser.add_argument('--hybrid', action='store_true',
                       help='Démo approche hybride')
    parser.add_argument('--all', action='store_true',
                       help='Toutes les démos')
    
    args = parser.parse_args()
    
    if args.all or (not any([args.features, args.train, args.detect, args.continuous, args.hybrid])):
        # Afficher toutes les démos
        demo_feature_extraction()
        input("\n[Appuyez sur Entrée pour continuer...]")
        
        demo_training()
        input("\n[Appuyez sur Entrée pour continuer...]")
        
        demo_detection()
        input("\n[Appuyez sur Entrée pour continuer...]")
        
        demo_continuous_learning()
        input("\n[Appuyez sur Entrée pour continuer...]")
        
        demo_hybrid_approach()
    else:
        if args.features:
            demo_feature_extraction()
        if args.train:
            demo_training()
        if args.detect:
            demo_detection()
        if args.continuous:
            demo_continuous_learning()
        if args.hybrid:
            demo_hybrid_approach()


if __name__ == "__main__":
    main()
