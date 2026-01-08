#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Détecteur de menaces utilisant le Machine Learning
Intégration avec le système existant de Celestis_IA
"""

import sys
import os
import numpy as np
import logging
from pathlib import Path
from typing import List, Dict, Optional, Any, Tuple
from datetime import datetime

# Configurer l'encodage UTF-8 pour Windows
if sys.platform == 'win32':
    try:
        # Essayer de configurer UTF-8 (Python 3.7+)
        if hasattr(sys.stdout, 'reconfigure') and hasattr(sys.stderr, 'reconfigure'):
            sys.stdout.reconfigure(encoding='utf-8')  # type: ignore[attr-defined]
            sys.stderr.reconfigure(encoding='utf-8')  # type: ignore[attr-defined]
        else:
            # Python < 3.7
            import codecs
            sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')  # type: ignore[assignment]
            sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')  # type: ignore[assignment]
    except Exception:
        # Si la configuration échoue, on utilisera des caractères ASCII
        pass

# Ajouter le chemin parent
sys.path.append(str(Path(__file__).parent.parent))

from scapy.utils import rdpcap
from ml.feature_extractor import NetworkFeatureExtractor
from ml.threat_models import RandomForestThreatModel, AnomalyDetectionModel


class MLThreatDetector:
    """Détecteur de menaces basé sur ML - Intégration avec Zeus"""
    
    def __init__(self, model_path: str = "ml/models/threat_detector",
                 model_type: str = "random_forest",
                 confidence_threshold: float = 0.7):
        """
        Args:
            model_path: Chemin vers le modèle pré-entraîné
            model_type: Type de modèle ('random_forest' ou 'anomaly')
            confidence_threshold: Seuil de confiance pour alerter
        """
        self.model_path = Path(model_path)
        self.model_type = model_type
        self.confidence_threshold = confidence_threshold
        
        self.extractor = NetworkFeatureExtractor()
        self.model = None
        
        self.logger = logging.getLogger(__name__)
        
        # Charger le modèle si disponible
        self._load_model()
    
    def _load_model(self):
        """Charge le modèle ML"""
        try:
            if self.model_type == "random_forest":
                self.model = RandomForestThreatModel()
            elif self.model_type == "anomaly":
                self.model = AnomalyDetectionModel()
            else:
                raise ValueError(f"Type de modèle inconnu: {self.model_type}")
            
            # Charger les poids
            model_name = self.model_path.stem
            self.model.load(model_name)
            
            self.logger.info(f"Modèle ML chargé: {self.model_path}")
            
        except FileNotFoundError:
            self.logger.warning(f"Modèle non trouvé: {self.model_path}")
            self.logger.warning("Le détecteur ML ne sera pas disponible")
            self.model = None
        except Exception as e:
            self.logger.error(f"Erreur lors du chargement du modèle: {e}")
            self.model = None
    
    def is_available(self) -> bool:
        """Vérifie si le détecteur ML est disponible"""
        return self.model is not None
    
    def analyze_packet(self, packet: Any, packet_number: int) -> Optional[Dict]:
        """
        Analyse un paquet avec le ML
        
        Args:
            packet: Paquet Scapy
            packet_number: Numéro du paquet
            
        Returns:
            Dictionnaire d'alerte si menace détectée, None sinon
        """
        if not self.is_available():
            return None
        
        try:
            # Extraire les features
            features = self.extractor.extract_packet_features(packet)
            features = features.reshape(1, -1)
            
            # Prédire (model est garanti non-None ici)
            assert self.model is not None
            prediction = self.model.predict(features)[0]
            probabilities = self.model.predict_proba(features)[0]
            
            # Probabilité de menace (classe 1)
            threat_probability = probabilities[1]
            
            # Vérifier le seuil
            if prediction == 1 and threat_probability >= self.confidence_threshold:
                # Extraire informations du paquet
                from scapy.layers.inet import IP, TCP, UDP
                
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
                
                # Déterminer la sévérité selon la confiance
                if threat_probability >= 0.95:
                    severity = "CRITICAL"
                elif threat_probability >= 0.85:
                    severity = "HIGH"
                elif threat_probability >= 0.75:
                    severity = "MEDIUM"
                else:
                    severity = "LOW"
                
                alert = {
                    'packet_number': packet_number,
                    'timestamp': datetime.fromtimestamp(float(packet.time)).isoformat(),
                    'rule_name': f'ML_{self.model_type.upper()}_Detection',
                    'severity': severity,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'protocol': protocol,
                    'matched_pattern': 'ML_Pattern',
                    'matched_data': f'ML Confidence: {threat_probability:.2%}',
                    'description': f'Machine Learning detected suspicious activity (confidence: {threat_probability:.2%})',
                    'detection_time': datetime.now().isoformat(),
                    'ml_confidence': threat_probability,
                    'ml_model': self.model_type
                }
                
                return alert
            
            return None
            
        except Exception as e:
            self.logger.error(f"Erreur lors de l'analyse ML du paquet {packet_number}: {e}")
            return None
    
    def analyze_pcap(self, pcap_file: str, verbose: bool = True) -> List[Dict]:
        """
        Analyse un fichier PCAP complet avec ML
        
        Args:
            pcap_file: Chemin vers le fichier PCAP
            verbose: Afficher les détails
            
        Returns:
            Liste des alertes détectées
        """
        if not self.is_available():
            self.logger.error("Modèle ML non disponible")
            return []
        
        pcap_path = Path(pcap_file)
        
        if not pcap_path.exists():
            self.logger.error(f"Fichier PCAP introuvable: {pcap_file}")
            return []
        
        self.logger.info(f"Analyse ML: {pcap_file}")
        
        all_alerts = []
        
        try:
            packets = rdpcap(str(pcap_path))
            total_packets = len(packets)
            
            self.logger.info(f"Analyse de {total_packets} paquets avec ML ({self.model_type})...")
            
            for i, packet in enumerate(packets, 1):
                alert = self.analyze_packet(packet, i)
                
                if alert:
                    all_alerts.append(alert)
                    
                    if verbose:
                        self._print_alert(alert)
                
                # Progression
                if i % 1000 == 0:
                    self.logger.info(f"  Paquets analysés: {i}/{total_packets} - Alertes ML: {len(all_alerts)}")
            
            self.logger.info(f"Analyse terminée: {len(all_alerts)} alerte(s) ML détectée(s)")
            
            if all_alerts:
                self._print_summary(all_alerts)
            
            return all_alerts
            
        except Exception as e:
            self.logger.error(f"Erreur lors de l'analyse: {e}")
            return []
    
    def _print_alert(self, alert: Dict):
        """Affiche une alerte de manière formatée"""
        severity_icons = {
            "INFO": "[i]",
            "LOW": "[*]",
            "MEDIUM": "[!]",
            "HIGH": "[!!]",
            "CRITICAL": "[!!!]"
        }
        
        icon = severity_icons.get(alert['severity'], "⚠️")
        
        print(f"\n{'='*70}")
        print(f"{icon} ALERTE ML - Sévérité: {alert['severity']}")
        print(f"{'='*70}")
        print(f"Modèle: {alert['ml_model']}")
        print(f"Confiance: {alert['ml_confidence']:.2%}")
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
        
        print(f"Description: {alert['description']}")
        print(f"{'='*70}\n")
    
    def _print_summary(self, alerts: List[Dict]):
        """Affiche un résumé des alertes"""
        print(f"\n{'='*70}")
        print(f"=== RÉSUMÉ DE L'ANALYSE ML ===")
        print(f"{'='*70}")
        
        # Comptage par sévérité
        severity_count = {}
        for alert in alerts:
            severity = alert['severity']
            severity_count[severity] = severity_count.get(severity, 0) + 1
        
        print(f"\nAlertes ML par sévérité:")
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            count = severity_count.get(severity, 0)
            if count > 0:
                print(f"  {severity}: {count}")
        
        # Confiance moyenne
        avg_confidence = np.mean([a['ml_confidence'] for a in alerts])
        print(f"\nConfiance moyenne: {avg_confidence:.2%}")
        
        print(f"{'='*70}\n")
    
    def get_feature_importance(self, top_n: int = 10) -> Optional[List[Tuple[int, float]]]:
        """
        Retourne l'importance des features (Random Forest uniquement)
        
        Args:
            top_n: Nombre de features à retourner
            
        Returns:
            Liste de (feature_index, importance)
        """
        if not self.is_available():
            return None
        
        if isinstance(self.model, RandomForestThreatModel):
            return self.model._get_top_features(top_n)
        
        return None


def main():
    """Fonction principale pour tester le détecteur ML"""
    import argparse
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    parser = argparse.ArgumentParser(description="Détection de menaces avec ML")
    parser.add_argument('-f', '--file', required=True,
                       help='Fichier PCAP à analyser')
    parser.add_argument('--model', default='ml/models/threat_detector',
                       help='Chemin vers le modèle')
    parser.add_argument('--model-type', default='random_forest',
                       choices=['random_forest', 'anomaly'],
                       help='Type de modèle')
    parser.add_argument('--threshold', type=float, default=0.7,
                       help='Seuil de confiance (0-1)')
    parser.add_argument('--feature-importance', action='store_true',
                       help='Afficher l\'importance des features')
    
    args = parser.parse_args()
    
    # Créer le détecteur
    detector = MLThreatDetector(
        model_path=args.model,
        model_type=args.model_type,
        confidence_threshold=args.threshold
    )
    
    if not detector.is_available():
        print("\n[X] Erreur: Modèle ML non disponible")
        print("Entraînez d'abord un modèle avec: python ml/trainer.py --train")
        return
    
    # Analyser le fichier PCAP
    alerts = detector.analyze_pcap(args.file)
    
    # Afficher l'importance des features
    if args.feature_importance:
        importance = detector.get_feature_importance(15)
        if importance:
            print("\n=== Top 15 Features les plus importantes ===")
            for i, (feature_idx, score) in enumerate(importance, 1):
                print(f"{i:2d}. Feature #{feature_idx:2d}: {score:.4f}")
    
    # Résumé final
    if alerts:
        print(f"\n[OK] Analyse terminée: {len(alerts)} alerte(s) ML détectée(s)")
    else:
        print("\n[OK] Analyse terminée: Aucune menace détectée par ML")


if __name__ == "__main__":
    main()
