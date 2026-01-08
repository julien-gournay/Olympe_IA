#!/usr/bin/env python3
"""
Module d'entraînement et d'apprentissage continu
Gère la préparation des données, l'entraînement, et le ré-entraînement
Celestis_IA - Module ML
"""

import sys
import numpy as np
import sqlite3
import logging
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Tuple, Optional
from collections import Counter

# Ajouter le chemin parent pour les imports
sys.path.append(str(Path(__file__).parent.parent))

from scapy.all import rdpcap
from ml.feature_extractor import NetworkFeatureExtractor
from ml.threat_models import RandomForestThreatModel, AnomalyDetectionModel


class ThreatDatasetBuilder:
    """Construit des datasets d'entraînement à partir de données labellisées"""
    
    def __init__(self, db_path: str = "pcap_database.db"):
        self.db_path = Path(db_path)
        self.extractor = NetworkFeatureExtractor()
        self.logger = logging.getLogger(__name__)
        
    def build_from_alerts(self, pcap_file_id: Optional[int] = None,
                         min_confidence: float = 0.7) -> Tuple[np.ndarray, np.ndarray]:
        """
        Construit un dataset à partir des alertes de menaces
        
        Args:
            pcap_file_id: ID du fichier PCAP (None = tous)
            min_confidence: Seuil de confiance minimum pour les labels
            
        Returns:
            (X, y) - Features et labels
        """
        self.logger.info("Construction du dataset à partir des alertes...")
        
        if not self.db_path.exists():
            self.logger.warning(f"Database not found: {self.db_path}")
            self.logger.warning("Retour d'un dataset vide. Veuillez d'abord exécuter l'ingestion PCAP.")
            return np.array([]), np.array([])
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Récupérer les fichiers PCAP
            if pcap_file_id:
                cursor.execute("SELECT id, file_path FROM pcap_files WHERE id = ?", (pcap_file_id,))
            else:
                cursor.execute("SELECT id, file_path FROM pcap_files")
            
            pcap_files = cursor.fetchall()
            
            X_list = []
            y_list = []
            
            for file_id, file_path in pcap_files:
                self.logger.info(f"Traitement du fichier: {file_path}")
                
                # Récupérer les alertes pour ce fichier
                cursor.execute("""
                    SELECT packet_number, severity, rule_name 
                    FROM threat_alerts 
                    WHERE pcap_file_id = ?
                """, (file_id,))
                
                alerts = cursor.fetchall()
                alert_dict = {}
                
                for packet_num, severity, rule_name in alerts:
                    # Convertir la sévérité en score
                    severity_score = {
                        'INFO': 0.2,
                        'LOW': 0.4,
                        'MEDIUM': 0.6,
                        'HIGH': 0.8,
                        'CRITICAL': 1.0
                    }.get(severity, 0.5)
                    
                    if packet_num not in alert_dict:
                        alert_dict[packet_num] = []
                    alert_dict[packet_num].append(severity_score)
                
                # Charger les paquets
                try:
                    # Vérifier que le fichier existe
                    if not Path(file_path).exists():
                        self.logger.warning(f"Fichier PCAP non trouvé, ignoré: {file_path}")
                        continue
                    
                    packets = rdpcap(file_path)
                    
                    # Extraire les features pour chaque paquet
                    for i, packet in enumerate(packets, 1):
                        # Extraire features
                        features = self.extractor.extract_packet_features(packet)
                        
                        # Déterminer le label
                        if i in alert_dict:
                            # Moyenne des scores de sévérité
                            avg_score = np.mean(alert_dict[i])
                            label = 1 if avg_score >= min_confidence else 0
                        else:
                            label = 0  # Normal
                        
                        X_list.append(features)
                        y_list.append(label)
                    
                    self.logger.info(f"  {len(packets)} paquets traités")
                    
                except Exception as e:
                    self.logger.error(f"Erreur lors du traitement de {file_path}: {e}")
            
            X = np.array(X_list)
            y = np.array(y_list)
            
            # Vérifier si le dataset est vide
            if len(X) == 0:
                self.logger.warning("Dataset vide!")
                self.logger.warning("Aucune donnée n'a pu être extraite. Vérifiez que:")
                self.logger.warning("  1. Les fichiers PCAP existent et sont accessibles")
                self.logger.warning("  2. L'ingestion PCAP a été exécutée avec succès")
                self.logger.warning("  3. Des alertes ont été générées pendant l'ingestion")
                return X, y
            
            # Statistiques
            malicious_count = np.sum(y == 1)
            normal_count = np.sum(y == 0)
            
            self.logger.info(f"Dataset construit: {len(X)} échantillons")
            self.logger.info(f"  Normal: {normal_count} ({normal_count/len(y)*100:.1f}%)")
            self.logger.info(f"  Malicious: {malicious_count} ({malicious_count/len(y)*100:.1f}%)")
            
            return X, y
    
    def build_from_labeled_pcaps(self, labeled_pcaps: List[Dict]) -> Tuple[np.ndarray, np.ndarray]:
        """
        Construit un dataset à partir de fichiers PCAP pré-labellisés
        
        Args:
            labeled_pcaps: Liste de {'path': str, 'label': 0 ou 1}
            
        Returns:
            (X, y) - Features et labels
        """
        self.logger.info(f"Construction du dataset à partir de {len(labeled_pcaps)} fichiers labellisés...")
        
        X_list = []
        y_list = []
        
        for item in labeled_pcaps:
            pcap_path = item['path']
            label = item['label']
            
            self.logger.info(f"Traitement: {pcap_path} (label={label})")
            
            try:
                packets = rdpcap(pcap_path)
                
                for packet in packets:
                    features = self.extractor.extract_packet_features(packet)
                    X_list.append(features)
                    y_list.append(label)
                
                self.logger.info(f"  {len(packets)} paquets ajoutés")
                
            except Exception as e:
                self.logger.error(f"Erreur: {e}")
        
        X = np.array(X_list)
        y = np.array(y_list)
        
        self.logger.info(f"Dataset total: {len(X)} échantillons")
        
        return X, y
    
    def build_from_flows(self, pcap_file_id: Optional[int] = None) -> Tuple[np.ndarray, np.ndarray]:
        """
        Construit un dataset basé sur les flux (plus efficace que par paquet)
        
        Returns:
            (X, y) - Features de flux et labels
        """
        self.logger.info("Construction du dataset par flux...")
        
        # À implémenter : agrégation par flux
        # Cette méthode nécessiterait d'extraire les flux depuis ingestion_pcap
        raise NotImplementedError("Feature extraction par flux à implémenter")


class ContinuousLearningSystem:
    """Système d'apprentissage continu qui s'améliore avec le temps"""
    
    def __init__(self, model_dir: str = "ml/models", 
                 db_path: str = "pcap_database.db",
                 feedback_threshold: int = 10):
        """
        Args:
            model_dir: Répertoire des modèles
            db_path: Base de données
            feedback_threshold: Nombre de feedbacks avant ré-entraînement
        """
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)
        
        self.db_path = Path(db_path)
        self.feedback_threshold = feedback_threshold
        
        self.dataset_builder = ThreatDatasetBuilder(str(db_path))
        self.logger = logging.getLogger(__name__)
        
        # Initialiser la table de feedback
        self._init_feedback_table()
    
    def _init_feedback_table(self):
        """Crée la table pour stocker le feedback utilisateur"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ml_feedback (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pcap_file_id INTEGER,
                    packet_number INTEGER,
                    predicted_label INTEGER,
                    actual_label INTEGER,
                    confidence REAL,
                    feedback_time TEXT,
                    used_for_training INTEGER DEFAULT 0,
                    FOREIGN KEY (pcap_file_id) REFERENCES pcap_files(id)
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ml_training_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    model_name TEXT,
                    model_type TEXT,
                    training_time TEXT,
                    samples_count INTEGER,
                    accuracy REAL,
                    metrics TEXT
                )
            """)
            
            conn.commit()
            self.logger.info("Tables de feedback initialisées")
    
    def add_feedback(self, pcap_file_id: int, packet_number: int,
                    predicted_label: int, actual_label: int, 
                    confidence: float = 1.0):
        """
        Ajoute du feedback utilisateur sur une prédiction
        
        Args:
            pcap_file_id: ID du fichier PCAP
            packet_number: Numéro du paquet
            predicted_label: Label prédit par le modèle
            actual_label: Vrai label confirmé par l'utilisateur
            confidence: Confiance dans le vrai label (0-1)
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO ml_feedback 
                (pcap_file_id, packet_number, predicted_label, actual_label, 
                 confidence, feedback_time)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                pcap_file_id, packet_number, predicted_label, actual_label,
                confidence, datetime.now().isoformat()
            ))
            
            conn.commit()
            
        self.logger.info(f"Feedback ajouté: paquet #{packet_number}, "
                        f"prédit={predicted_label}, réel={actual_label}")
        
        # Vérifier si on doit ré-entraîner
        self._check_retrain_needed()
    
    def _check_retrain_needed(self):
        """Vérifie si un ré-entraînement est nécessaire"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT COUNT(*) FROM ml_feedback 
                WHERE used_for_training = 0
            """)
            
            unused_feedback_count = cursor.fetchone()[0]
            
            if unused_feedback_count >= self.feedback_threshold:
                self.logger.info(f"Seuil atteint ({unused_feedback_count} feedbacks non utilisés)")
                self.logger.info("Ré-entraînement recommandé!")
                return True
            
            return False
    
    def retrain_with_feedback(self, model_name: str = "adaptive_model",
                             model_type: str = "random_forest"):
        """
        Ré-entraîne le modèle en incorporant les nouveaux feedbacks
        
        Args:
            model_name: Nom du modèle à ré-entraîner/créer
            model_type: Type de modèle ('random_forest' ou 'anomaly')
        """
        self.logger.info("Démarrage du ré-entraînement avec feedback...")
        
        # 1. Construire le dataset de base depuis les alertes
        X_base, y_base = self.dataset_builder.build_from_alerts()
        
        # 2. Ajouter les données de feedback
        X_feedback, y_feedback = self._get_feedback_data()
        
        if len(X_feedback) > 0:
            X = np.vstack([X_base, X_feedback])
            y = np.concatenate([y_base, y_feedback])
            self.logger.info(f"Dataset augmenté avec {len(X_feedback)} feedbacks")
        else:
            X, y = X_base, y_base
            self.logger.warning("Aucun feedback disponible, entraînement sur données de base")
        
        # 3. Créer et entraîner le modèle
        if model_type == "random_forest":
            model = RandomForestThreatModel(str(self.model_dir))
        elif model_type == "anomaly":
            model = AnomalyDetectionModel(str(self.model_dir))
        else:
            raise ValueError(f"Type de modèle inconnu: {model_type}")
        
        # Entraîner
        metrics = model.train(X, y, validation_split=0.2)
        
        # Sauvegarder
        model.save(model_name)
        
        # 4. Enregistrer la session d'entraînement
        self._log_training_run(model_name, model_type, len(X), metrics)
        
        # 5. Marquer les feedbacks comme utilisés
        self._mark_feedback_used()
        
        self.logger.info(f"Modèle {model_name} entraîné avec succès!")
        
        return model, metrics
    
    def _get_feedback_data(self) -> Tuple[np.ndarray, np.ndarray]:
        """Récupère et transforme les données de feedback en features"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT f.pcap_file_id, f.packet_number, f.actual_label, p.file_path
                FROM ml_feedback f
                JOIN pcap_files p ON f.pcap_file_id = p.id
                WHERE f.used_for_training = 0 AND f.confidence >= 0.7
            """)
            
            feedbacks = cursor.fetchall()
            
            if not feedbacks:
                return np.array([]), np.array([])
            
            X_list = []
            y_list = []
            
            # Grouper par fichier PCAP pour efficacité
            file_groups = {}
            for pcap_id, packet_num, label, file_path in feedbacks:
                if file_path not in file_groups:
                    file_groups[file_path] = []
                file_groups[file_path].append((packet_num, label))
            
            # Traiter chaque fichier
            for file_path, items in file_groups.items():
                try:
                    packets = rdpcap(file_path)
                    
                    for packet_num, label in items:
                        if 0 < packet_num <= len(packets):
                            packet = packets[packet_num - 1]
                            features = self.dataset_builder.extractor.extract_packet_features(packet)
                            X_list.append(features)
                            y_list.append(label)
                
                except Exception as e:
                    self.logger.error(f"Erreur lors du traitement de {file_path}: {e}")
            
            return np.array(X_list), np.array(y_list)
    
    def _mark_feedback_used(self):
        """Marque tous les feedbacks comme utilisés pour l'entraînement"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE ml_feedback SET used_for_training = 1 WHERE used_for_training = 0")
            conn.commit()
    
    def _log_training_run(self, model_name: str, model_type: str, 
                         samples_count: int, metrics: Dict):
        """Enregistre une session d'entraînement"""
        import json
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            accuracy = metrics.get('val_accuracy', 0)
            
            cursor.execute("""
                INSERT INTO ml_training_runs 
                (model_name, model_type, training_time, samples_count, accuracy, metrics)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                model_name,
                model_type,
                datetime.now().isoformat(),
                samples_count,
                accuracy,
                json.dumps(metrics)
            ))
            
            conn.commit()


def main():
    """Fonction principale pour tester l'entraînement"""
    import argparse
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    parser = argparse.ArgumentParser(description="Entraînement de modèles ML")
    parser.add_argument('--build-dataset', action='store_true',
                       help='Construire le dataset depuis les alertes')
    parser.add_argument('--train', action='store_true',
                       help='Entraîner un nouveau modèle')
    parser.add_argument('--retrain', action='store_true',
                       help='Ré-entraîner avec feedback')
    parser.add_argument('--model-type', default='random_forest',
                       choices=['random_forest', 'anomaly'],
                       help='Type de modèle')
    parser.add_argument('--model-name', default='threat_detector',
                       help='Nom du modèle')
    parser.add_argument('--db', default='pcap_database.db',
                       help='Chemin vers la base de données')
    
    args = parser.parse_args()
    
    if args.build_dataset:
        builder = ThreatDatasetBuilder(args.db)
        X, y = builder.build_from_alerts()
        print(f"\nDataset construit: {len(X)} échantillons")
        print(f"Shape: {X.shape}")
        print(f"Labels: {Counter(y)}")
    
    elif args.train:
        builder = ThreatDatasetBuilder(args.db)
        X, y = builder.build_from_alerts()
        
        # Vérifier que le dataset n'est pas vide
        if len(X) == 0:
            print("\n❌ ERREUR: Dataset vide!")
            print("\nImpossible d'entraîner un modèle sans données.")
            print("\nÉtapes pour résoudre ce problème:")
            print("  1. Assurez-vous d'avoir capturé du trafic réseau (étape 1)")
            print("  2. Exécutez l'ingestion PCAP avec analyse YARA (étape 2)")
            print("  3. Vérifiez que des alertes ont été générées")
            print("\nCommandes suggérées:")
            print(f"  cd zeus")
            print(f"  python ingestion_pcap.py -f training_ai.pcap --enable-yara")
            sys.exit(1)
        
        if args.model_type == 'random_forest':
            model = RandomForestThreatModel()
        else:
            model = AnomalyDetectionModel()
        
        print(f"\nEntraînement du modèle {args.model_type}...")
        metrics = model.train(X, y)
        model.save(args.model_name)
        
        print("\n=== Résultats ===")
        print(f"Accuracy: {metrics['val_accuracy']:.4f}")
        if 'roc_auc' in metrics:
            print(f"ROC AUC: {metrics['roc_auc']:.4f}")
    
    elif args.retrain:
        system = ContinuousLearningSystem(db_path=args.db)
        model, metrics = system.retrain_with_feedback(
            model_name=args.model_name,
            model_type=args.model_type
        )
        
        print("\n=== Ré-entraînement terminé ===")
        print(f"Accuracy: {metrics.get('val_accuracy', 0):.4f}")
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
