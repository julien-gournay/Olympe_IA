#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Exemple d'intégration ML avec le système Zeus existant
Montre comment combiner les règles regex et le ML
"""

import sys
from pathlib import Path
import logging

# Configurer l'encodage UTF-8 pour Windows
if sys.platform == 'win32':
    try:
        if hasattr(sys.stdout, 'reconfigure') and hasattr(sys.stderr, 'reconfigure'):
            sys.stdout.reconfigure(encoding='utf-8')  # type: ignore[attr-defined]
            sys.stderr.reconfigure(encoding='utf-8')  # type: ignore[attr-defined]
    except Exception:
        pass

# Ajouter les chemins
sys.path.append(str(Path(__file__).parent.parent))

from zeus.threat_analyzer import ThreatAnalyzer
from ml.ml_detector import MLThreatDetector
import sqlite3
from datetime import datetime


class HybridThreatAnalyzer(ThreatAnalyzer):
    """
    Analyseur hybride qui combine :
    - Règles regex (rapide, précis, connu)
    - Machine Learning (adaptatif, détecte l'inconnu)
    """
    
    def __init__(self, rules_path: str = "config/threat_rules.yaml",
                 db_path: str = "pcap_database.db",
                 log_dir: str = "logs",
                 ml_model_path: str = "ml/models/threat_detector",
                 ml_model_type: str = "random_forest",
                 ml_threshold: float = 0.7,
                 enable_ml: bool = True):
        """
        Initialise l'analyseur hybride
        
        Args:
            rules_path: Chemin vers les règles regex
            db_path: Base de données
            log_dir: Répertoire des logs
            ml_model_path: Chemin vers le modèle ML
            ml_model_type: Type de modèle ML
            ml_threshold: Seuil de confiance ML
            enable_ml: Activer le ML (False = règles uniquement)
        """
        # Initialiser l'analyseur de base
        super().__init__(rules_path, db_path, log_dir)
        
        # Ajouter le détecteur ML
        self.enable_ml = enable_ml
        self.ml_detector = None
        
        if self.enable_ml:
            try:
                self.ml_detector = MLThreatDetector(
                    model_path=ml_model_path,
                    model_type=ml_model_type,
                    confidence_threshold=ml_threshold
                )
                
                if self.ml_detector.is_available():
                    self.logger.info("🤖 Détecteur ML activé")
                else:
                    self.logger.warning("ML désactivé: modèle non disponible")
                    self.ml_detector = None
            except Exception as e:
                self.logger.warning(f"Impossible d'activer le ML: {e}")
                self.ml_detector = None
    
    def analyze_packet(self, packet, packet_number: int):
        """
        Analyse un paquet avec règles + ML
        
        Returns:
            Liste combinée des alertes (regex + ML)
        """
        # 1. Analyse avec règles regex (méthode parent)
        regex_alerts = super().analyze_packet(packet, packet_number)
        
        # 2. Analyse avec ML
        ml_alerts = []
        if self.ml_detector and self.ml_detector.is_available():
            ml_alert = self.ml_detector.analyze_packet(packet, packet_number)
            if ml_alert:
                ml_alerts.append(ml_alert)
        
        # 3. Combiner et dédupliquer
        all_alerts = self._merge_alerts(regex_alerts, ml_alerts, packet_number)
        
        return all_alerts
    
    def _merge_alerts(self, regex_alerts, ml_alerts, packet_number):
        """
        Fusionne intelligemment les alertes regex et ML
        
        Stratégie:
        - Si regex détecte: haute confiance, on garde
        - Si ML détecte sans regex: on garde avec le score ML
        - Si les deux détectent: on combine les infos
        """
        all_alerts = []
        
        # Ajouter toutes les alertes regex (haute confiance)
        for alert in regex_alerts:
            alert['detection_method'] = 'regex'
            alert['combined_confidence'] = 0.95  # Règles = haute confiance
            all_alerts.append(alert)
        
        # Ajouter les alertes ML
        for ml_alert in ml_alerts:
            ml_alert['detection_method'] = 'ml'
            ml_alert['combined_confidence'] = ml_alert['ml_confidence']
            
            # Vérifier si une règle regex a déjà détecté ce paquet
            regex_detected = len(regex_alerts) > 0
            
            if regex_detected:
                # Les deux ont détecté : augmenter la confiance
                ml_alert['severity'] = 'CRITICAL'  # Upgrade severity
                ml_alert['description'] += ' [CONFIRMÉ PAR RÈGLES REGEX]'
                ml_alert['combined_confidence'] = 0.99
            
            all_alerts.append(ml_alert)
        
        return all_alerts
    
    def analyze_pcap(self, pcap_file: str, pcap_file_id=None, verbose: bool = True):
        """
        Analyse un PCAP complet avec approche hybride
        """
        self.logger.info(f"🔍 Analyse hybride (Règles + ML): {pcap_file}")
        
        # Utiliser la méthode parent qui appelle analyze_packet
        all_alerts = super().analyze_pcap(pcap_file, pcap_file_id, verbose)
        
        # Statistiques hybrides
        if all_alerts:
            self._print_hybrid_summary(all_alerts)
        
        return all_alerts
    
    def _print_hybrid_summary(self, alerts):
        """Affiche un résumé de la détection hybride"""
        regex_count = sum(1 for a in alerts if a.get('detection_method') == 'regex')
        ml_count = sum(1 for a in alerts if a.get('detection_method') == 'ml')
        
        print(f"\n{'='*70}")
        print(f"=== RÉSUMÉ DÉTECTION HYBRIDE ===")
        print(f"{'='*70}")
        print(f"\n🔧 Alertes par Règles Regex: {regex_count}")
        print(f"🤖 Alertes par ML uniquement: {ml_count}")
        print(f"📍 Total: {len(alerts)}")
        
        # Confiance moyenne
        avg_confidence = sum(a.get('combined_confidence', 0) for a in alerts) / len(alerts)
        print(f"\n📈 Confiance moyenne: {avg_confidence:.2%}")
        print(f"{'='*70}\n")


def demo_hybrid_analysis():
    """Démontre l'analyse hybride"""
    import argparse
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    parser = argparse.ArgumentParser(description="Analyse hybride (Règles + ML)")
    parser.add_argument('-f', '--file', required=True,
                       help='Fichier PCAP à analyser')
    parser.add_argument('--ml-model', default='ml/models/threat_detector',
                       help='Chemin vers le modèle ML')
    parser.add_argument('--disable-ml', action='store_true',
                       help='Désactiver le ML (règles uniquement)')
    parser.add_argument('--ml-threshold', type=float, default=0.7,
                       help='Seuil de confiance ML')
    
    args = parser.parse_args()
    
    print("\n" + "="*70)
    print("🚀 ANALYSE HYBRIDE - Règles Regex + Machine Learning")
    print("="*70)
    
    # Créer l'analyseur hybride
    analyzer = HybridThreatAnalyzer(
        rules_path='zeus/config/threat_rules.yaml',
        db_path='zeus/pcap_database.db',
        ml_model_path=args.ml_model,
        enable_ml=not args.disable_ml,
        ml_threshold=args.ml_threshold
    )
    
    # Analyser
    alerts = analyzer.analyze_pcap(args.file, verbose=True)
    
    print(f"\n[OK] Analyse terminée: {len(alerts)} alerte(s) détectée(s)")
    
    # Sauvegarder dans un rapport
    if alerts:
        output_file = Path("hybrid_analysis_report.txt")
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("RAPPORT D'ANALYSE HYBRIDE\n")
            f.write("="*70 + "\n\n")
            f.write(f"Fichier analysé: {args.file}\n")
            f.write(f"Date: {datetime.now().isoformat()}\n")
            f.write(f"Total alertes: {len(alerts)}\n\n")
            
            for i, alert in enumerate(alerts, 1):
                f.write(f"\nAlerte #{i}\n")
                f.write(f"  Méthode: {alert.get('detection_method', 'unknown')}\n")
                f.write(f"  Sévérité: {alert['severity']}\n")
                f.write(f"  Confiance: {alert.get('combined_confidence', 0):.2%}\n")
                f.write(f"  Paquet: #{alert['packet_number']}\n")
                f.write(f"  Description: {alert['description']}\n")
        
        print(f"\n📄 Rapport sauvegardé: {output_file}")


if __name__ == "__main__":
    demo_hybrid_analysis()
