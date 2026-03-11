#!/usr/bin/env python3
"""
Modèles de Machine Learning pour la détection de menaces
Supporte Random Forest, Isolation Forest, et Neural Networks
Celestis_IA - Module ML
"""

import numpy as np
import pickle
import json
import sqlite3
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import (
    train_test_split,
    GroupShuffleSplit,
    GroupKFold,
    StratifiedKFold,
    GridSearchCV,
)
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score,
    precision_recall_curve,
    f1_score,
)
import logging

# Neural Network (optionnel)
try:
    import tensorflow as tf
    TENSORFLOW_AVAILABLE = True
except ImportError:
    TENSORFLOW_AVAILABLE = False
    tf = None  # type: ignore


class ThreatDetectionModel:
    """Modèle de base pour la détection de menaces"""
    
    def __init__(self, model_dir: str = "models", db_path: Optional[str] = None):
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)
        
        self.model = None
        self.scaler = StandardScaler()
        self.feature_importance = None
        self.training_history = []
        self.db_path = db_path
        self.optimal_threshold = 0.5
        
        self.logger = logging.getLogger(__name__)
        
    def train(self, X: np.ndarray, y: np.ndarray,
             validation_split: float = 0.2,
             groups: Optional[np.ndarray] = None,
             cv_folds: int = 5,
             use_hyperparameter_search: bool = False) -> Dict:
        """
        Entraîne le modèle
        
        Args:
            X: Features (n_samples, n_features)
            y: Labels (n_samples,) - 0 = normal, 1 = malicious
            validation_split: Ratio de données pour validation
            
        Returns:
            Dictionnaire avec les métriques
        """
        raise NotImplementedError
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """Prédit les labels"""
        raise NotImplementedError
    
    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Prédit les probabilités"""
        raise NotImplementedError
    
    def save(self, name: str):
        """Sauvegarde le modèle"""
        raise NotImplementedError
    
    def load(self, name: str):
        """Charge le modèle"""
        raise NotImplementedError
    
    def _generate_text_report(self, name: str) -> str:
        """Génère un rapport texte détaillé sur le modèle"""
        report_lines = []
        report_lines.append("="*70)
        report_lines.append(f"  RAPPORT DU MODÈLE: {name}")
        report_lines.append("="*70)
        report_lines.append("")
        report_lines.append(f"Date de génération: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append("")
        
        # Informations sur le modèle
        report_lines.append("-" * 70)
        report_lines.append("1. INFORMATIONS SUR LE MODÈLE")
        report_lines.append("-" * 70)
        
        if hasattr(self, 'model') and self.model is not None:
            model_type = type(self.model).__name__
            report_lines.append(f"Type de modèle: {model_type}")
            
            if isinstance(self.model, RandomForestClassifier):
                report_lines.append(f"Nombre d'arbres: {self.model.n_estimators}")
                report_lines.append(f"Profondeur maximale: {self.model.max_depth}")
            elif isinstance(self.model, IsolationForest):
                report_lines.append(f"Contamination: {self.model._contamination}")
        
        report_lines.append("")
        
        # Métriques d'entraînement
        if self.training_history:
            latest = self.training_history[-1]
            report_lines.append("-" * 70)
            report_lines.append("2. MÉTRIQUES D'ENTRAÎNEMENT")
            report_lines.append("-" * 70)
            report_lines.append(f"Échantillons d'entraînement: {latest.get('train_samples', 'N/A')}")
            report_lines.append(f"Échantillons de validation: {latest.get('val_samples', 'N/A')}")
            
            train_acc = latest.get('train_accuracy', latest.get('final_train_accuracy'))
            val_acc = latest.get('val_accuracy', latest.get('final_val_accuracy'))
            
            if train_acc is not None:
                report_lines.append(f"Précision (entraînement): {train_acc:.4f} ({train_acc*100:.2f}%)")
            if val_acc is not None:
                report_lines.append(f"Précision (validation): {val_acc:.4f} ({val_acc*100:.2f}%)")
            
            if 'roc_auc' in latest:
                report_lines.append(f"ROC AUC Score: {latest['roc_auc']:.4f}")
            
            report_lines.append("")
            
            # Rapport de classification
            if 'classification_report' in latest:
                report_lines.append("Rapport de classification détaillé:")
                report_lines.append("")
                clf_report = latest['classification_report']
                
                if '0' in clf_report:
                    normal = clf_report['0']
                    report_lines.append(f"  Classe 0 (Normal):")
                    report_lines.append(f"    Précision: {normal.get('precision', 0):.4f}")
                    report_lines.append(f"    Rappel: {normal.get('recall', 0):.4f}")
                    report_lines.append(f"    F1-Score: {normal.get('f1-score', 0):.4f}")
                    report_lines.append(f"    Support: {normal.get('support', 0)}")
                    report_lines.append("")
                
                if '1' in clf_report:
                    malicious = clf_report['1']
                    report_lines.append(f"  Classe 1 (Malveillant):")
                    report_lines.append(f"    Précision: {malicious.get('precision', 0):.4f}")
                    report_lines.append(f"    Rappel: {malicious.get('recall', 0):.4f}")
                    report_lines.append(f"    F1-Score: {malicious.get('f1-score', 0):.4f}")
                    report_lines.append(f"    Support: {malicious.get('support', 0)}")
                    report_lines.append("")
            
            # Matrice de confusion
            if 'confusion_matrix' in latest:
                report_lines.append("Matrice de confusion:")
                cm = latest['confusion_matrix']
                if len(cm) == 2 and len(cm[0]) == 2:
                    report_lines.append(f"  Vrais Négatifs (TN): {cm[0][0]}")
                    report_lines.append(f"  Faux Positifs (FP): {cm[0][1]}")
                    report_lines.append(f"  Faux Négatifs (FN): {cm[1][0]}")
                    report_lines.append(f"  Vrais Positifs (TP): {cm[1][1]}")
                report_lines.append("")
        
        # Features importantes
        if self.feature_importance is not None:
            report_lines.append("-" * 70)
            report_lines.append("3. IMPORTANCE DES CARACTÉRISTIQUES (Top 15)")
            report_lines.append("-" * 70)
            top_features = self._get_top_features(15)
            for idx, (feat_idx, importance) in enumerate(top_features, 1):
                report_lines.append(f"  {idx:2d}. Feature #{feat_idx:2d}: {importance:.6f} ({importance*100:.3f}%)")
            report_lines.append("")
        
        # Informations sur les menaces depuis la base de données
        if self.db_path and Path(self.db_path).exists():
            report_lines.append("-" * 70)
            report_lines.append("4. MENACES DÉTECTÉES DANS LES DONNÉES D'ENTRAÎNEMENT")
            report_lines.append("-" * 70)
            
            try:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    
                    # Statistiques globales
                    cursor.execute("SELECT COUNT(*) FROM threat_alerts")
                    total_alerts = cursor.fetchone()[0]
                    report_lines.append(f"Total d'alertes: {total_alerts}")
                    report_lines.append("")
                    
                    # Alertes par sévérité
                    cursor.execute("""
                        SELECT severity, COUNT(*) as count 
                        FROM threat_alerts 
                        GROUP BY severity 
                        ORDER BY 
                            CASE severity
                                WHEN 'CRITICAL' THEN 1
                                WHEN 'HIGH' THEN 2
                                WHEN 'MEDIUM' THEN 3
                                WHEN 'LOW' THEN 4
                                ELSE 5
                            END
                    """)
                    severity_stats = cursor.fetchall()
                    
                    if severity_stats:
                        report_lines.append("Alertes par sévérité:")
                        for severity, count in severity_stats:
                            percentage = (count / total_alerts * 100) if total_alerts > 0 else 0
                            report_lines.append(f"  {severity:10s}: {count:6d} ({percentage:5.2f}%)")
                        report_lines.append("")
                    
                    # Top 10 des règles déclenchées
                    cursor.execute("""
                        SELECT rule_name, severity, COUNT(*) as count 
                        FROM threat_alerts 
                        GROUP BY rule_name, severity 
                        ORDER BY count DESC 
                        LIMIT 10
                    """)
                    top_rules = cursor.fetchall()
                    
                    if top_rules:
                        report_lines.append("Top 10 des règles YARA/Threat déclenchées:")
                        for idx, (rule_name, severity, count) in enumerate(top_rules, 1):
                            report_lines.append(f"  {idx:2d}. {rule_name:30s} [{severity:8s}] - {count:5d} fois")
                        report_lines.append("")
                    
                    # Informations sur les fichiers PCAP
                    cursor.execute("""
                        SELECT COUNT(DISTINCT pcap_file_id) 
                        FROM threat_alerts
                    """)
                    num_pcap_files = cursor.fetchone()[0]
                    report_lines.append(f"Nombre de fichiers PCAP analysés: {num_pcap_files}")
                    
                    # Détails des fichiers PCAP (uniquement ceux avec des alertes)
                    cursor.execute("""
                        SELECT p.file_path, COUNT(t.id) as alert_count
                        FROM pcap_files p
                        INNER JOIN threat_alerts t ON p.id = t.pcap_file_id
                        GROUP BY p.id, p.file_path
                        ORDER BY alert_count DESC
                    """)
                    pcap_details = cursor.fetchall()
                    
                    if pcap_details:
                        report_lines.append("")
                        report_lines.append("Détails des fichiers PCAP:")
                        for pcap_path, alert_count in pcap_details:
                            pcap_name = Path(pcap_path).name
                            report_lines.append(f"  - {pcap_name}: {alert_count} alertes")
                    
            except Exception as e:
                report_lines.append(f"Erreur lors de la récupération des menaces: {e}")
            
            report_lines.append("")
        
        # Historique d'entraînement
        if len(self.training_history) > 1:
            report_lines.append("-" * 70)
            report_lines.append("5. HISTORIQUE D'ENTRAÎNEMENT")
            report_lines.append("-" * 70)
            for idx, history in enumerate(self.training_history, 1):
                timestamp = history.get('timestamp', 'N/A')
                train_samples = history.get('train_samples', 'N/A')
                val_acc = history.get('val_accuracy', history.get('final_val_accuracy', 'N/A'))
                report_lines.append(f"  Run #{idx} - {timestamp}")
                report_lines.append(f"    Échantillons: {train_samples}")
                if isinstance(val_acc, float):
                    report_lines.append(f"    Précision validation: {val_acc:.4f}")
                report_lines.append("")
        
        report_lines.append("="*70)
        report_lines.append("FIN DU RAPPORT")
        report_lines.append("="*70)
        
        return "\n".join(report_lines)


class RandomForestThreatModel(ThreatDetectionModel):
    """Modèle Random Forest pour la détection de menaces"""
    
    def __init__(self, model_dir: str = "models", 
                 n_estimators: int = 100, max_depth: int = 20,
                 db_path: Optional[str] = None):
        super().__init__(model_dir, db_path)
        self.model = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            random_state=42,
            n_jobs=-1,
            class_weight='balanced'  # Pour gérer les classes déséquilibrées
        )
    
    def train(self, X: np.ndarray, y: np.ndarray,
             validation_split: float = 0.2,
             groups: Optional[np.ndarray] = None,
             cv_folds: int = 5,
             use_hyperparameter_search: bool = False) -> Dict:
        """Entraîne le Random Forest"""

        X_train, X_val, y_train, y_val, groups_train = self._split_train_validation(
            X, y, validation_split, groups
        )
        
        self.logger.info(f"Entraînement sur {len(X_train)} échantillons, "
                        f"validation sur {len(X_val)} échantillons")
        
        # Normalisation
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_val_scaled = self.scaler.transform(X_val)
        
        # Validation croisée avant entraînement final
        cv_metrics = self._compute_cross_validation_metrics(
            X_train_scaled, y_train, groups_train, cv_folds
        )

        # Entraînement (optionnellement avec recherche d'hyperparamètres)
        self.logger.info("Entraînement du Random Forest...")
        if use_hyperparameter_search:
            self.model = self._run_hyperparameter_search(
                X_train_scaled, y_train, groups_train, cv_folds
            )
        self.model.fit(X_train_scaled, y_train)
        
        # Évaluation
        y_pred = self.model.predict(X_val_scaled)
        y_pred_proba_all = self.model.predict_proba(X_val_scaled)
        
        # Gérer le cas où il n'y a qu'une seule classe
        if y_pred_proba_all.shape[1] == 1:
            # Une seule classe détectée - utiliser cette probabilité
            y_pred_proba = y_pred_proba_all[:, 0]
        else:
            # Deux classes - utiliser la probabilité de la classe positive (1)
            y_pred_proba = y_pred_proba_all[:, 1]

        # Seuil optimisé sur le jeu de validation
        self.optimal_threshold = self._optimize_threshold(y_val, y_pred_proba)
        y_pred_threshold = (y_pred_proba >= self.optimal_threshold).astype(int)
        
        # Métriques
        metrics = {
            'timestamp': datetime.now().isoformat(),
            'train_samples': len(X_train),
            'val_samples': len(X_val),
            'train_accuracy': self.model.score(X_train_scaled, y_train),
            'val_accuracy': self.model.score(X_val_scaled, y_val),
            'classification_report': classification_report(y_val, y_pred_threshold, output_dict=True),
            'confusion_matrix': confusion_matrix(y_val, y_pred_threshold).tolist(),
            'optimal_threshold': float(self.optimal_threshold),
            'val_f1_thresholded': float(f1_score(y_val, y_pred_threshold, zero_division=0)),
        }

        if cv_metrics:
            metrics['cv'] = cv_metrics
        
        # ROC AUC si on a les deux classes
        if len(np.unique(y_val)) > 1 and y_pred_proba_all.shape[1] > 1:
            metrics['roc_auc'] = roc_auc_score(y_val, y_pred_proba)
        
        # Feature importance
        self.feature_importance = self.model.feature_importances_
        metrics['top_features'] = self._get_top_features(10)
        
        self.training_history.append(metrics)
        
        self.logger.info(f"Accuracy: Train={metrics['train_accuracy']:.4f}, "
                        f"Val={metrics['val_accuracy']:.4f}")
        if 'roc_auc' in metrics:
            self.logger.info(f"ROC AUC: {metrics['roc_auc']:.4f}")
        self.logger.info(f"Seuil optimisé: {self.optimal_threshold:.4f}")
        
        return metrics

    def _split_train_validation(
        self,
        X: np.ndarray,
        y: np.ndarray,
        validation_split: float,
        groups: Optional[np.ndarray],
    ) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, Optional[np.ndarray]]:
        """Réalise un split train/validation en évitant la fuite par groupe si possible."""
        if groups is not None:
            unique_groups = np.unique(groups)
            if len(unique_groups) > 1:
                splitter = GroupShuffleSplit(
                    n_splits=1,
                    test_size=validation_split,
                    random_state=42,
                )
                train_idx, val_idx = next(splitter.split(X, y, groups=groups))
                return (
                    X[train_idx],
                    X[val_idx],
                    y[train_idx],
                    y[val_idx],
                    groups[train_idx],
                )

        unique_classes, counts = np.unique(y, return_counts=True)
        use_stratify = all(count >= 2 for count in counts) and len(unique_classes) > 1

        if use_stratify:
            X_train, X_val, y_train, y_val = train_test_split(
                X, y, test_size=validation_split, random_state=42, stratify=y
            )
        else:
            self.logger.warning("Stratification désactivée - classes insuffisantes ou déséquilibrées")
            X_train, X_val, y_train, y_val = train_test_split(
                X, y, test_size=validation_split, random_state=42
            )

        return X_train, X_val, y_train, y_val, None

    def _compute_cross_validation_metrics(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        groups_train: Optional[np.ndarray],
        cv_folds: int,
    ) -> Dict[str, float]:
        """Calcule des métriques CV robustes sur l'ensemble d'entraînement."""
        try:
            n_folds = max(2, min(cv_folds, len(X_train)))
            if groups_train is not None and len(np.unique(groups_train)) >= n_folds:
                cv = GroupKFold(n_splits=n_folds)
                cv_scores = []
                for tr_idx, te_idx in cv.split(X_train, y_train, groups=groups_train):
                    fold_model = RandomForestClassifier(
                        n_estimators=self.model.n_estimators,
                        max_depth=self.model.max_depth,
                        random_state=42,
                        n_jobs=-1,
                        class_weight='balanced'
                    )
                    fold_model.fit(X_train[tr_idx], y_train[tr_idx])
                    fold_pred = fold_model.predict(X_train[te_idx])
                    cv_scores.append(f1_score(y_train[te_idx], fold_pred, zero_division=0))
            else:
                cv = StratifiedKFold(
                    n_splits=min(n_folds, max(2, np.min(np.bincount(y_train.astype(int))))),
                    shuffle=True,
                    random_state=42,
                )
                cv_scores = []
                for tr_idx, te_idx in cv.split(X_train, y_train):
                    fold_model = RandomForestClassifier(
                        n_estimators=self.model.n_estimators,
                        max_depth=self.model.max_depth,
                        random_state=42,
                        n_jobs=-1,
                        class_weight='balanced'
                    )
                    fold_model.fit(X_train[tr_idx], y_train[tr_idx])
                    fold_pred = fold_model.predict(X_train[te_idx])
                    cv_scores.append(f1_score(y_train[te_idx], fold_pred, zero_division=0))

            return {
                'f1_mean': float(np.mean(cv_scores)),
                'f1_std': float(np.std(cv_scores)),
                'folds': float(len(cv_scores)),
            }
        except Exception as exc:
            self.logger.warning(f"CV ignorée: {exc}")
            return {}

    def _run_hyperparameter_search(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        groups_train: Optional[np.ndarray],
        cv_folds: int,
    ) -> RandomForestClassifier:
        """Recherche simple d'hyperparamètres avec GridSearchCV."""
        param_grid = {
            'n_estimators': [100, 200],
            'max_depth': [10, 20, None],
            'min_samples_leaf': [1, 2, 4],
        }

        if groups_train is not None and len(np.unique(groups_train)) >= max(2, cv_folds):
            cv = GroupKFold(n_splits=cv_folds)
        else:
            cv = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=42)

        search = GridSearchCV(
            estimator=RandomForestClassifier(
                random_state=42,
                n_jobs=-1,
                class_weight='balanced',
            ),
            param_grid=param_grid,
            scoring='f1',
            cv=cv,
            n_jobs=-1,
            refit=True,
        )

        if isinstance(cv, GroupKFold) and groups_train is not None:
            search.fit(X_train, y_train, groups=groups_train)
        else:
            search.fit(X_train, y_train)

        self.logger.info(f"Meilleurs hyperparamètres: {search.best_params_}")
        self.logger.info(f"Meilleur score CV (F1): {search.best_score_:.4f}")
        return search.best_estimator_

    def _optimize_threshold(self, y_true: np.ndarray, y_proba: np.ndarray) -> float:
        """Optimise le seuil de décision en maximisant le F1 sur validation."""
        if len(np.unique(y_true)) < 2:
            return 0.5

        precision, recall, thresholds = precision_recall_curve(y_true, y_proba)
        if len(thresholds) == 0:
            return 0.5

        f1_scores = (2 * precision[:-1] * recall[:-1]) / (
            precision[:-1] + recall[:-1] + 1e-10
        )
        best_idx = int(np.argmax(f1_scores))
        return float(thresholds[best_idx])
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """Prédit les labels (0 = normal, 1 = malicious)"""
        if self.model is None:
            raise ValueError("Model not trained or loaded")
        
        X_scaled = self.scaler.transform(X)
        if hasattr(self.model, "predict_proba"):
            y_proba_all = self.model.predict_proba(X_scaled)
            if y_proba_all.shape[1] == 1:
                y_proba = y_proba_all[:, 0]
            else:
                y_proba = y_proba_all[:, 1]
            threshold = float(getattr(self, 'optimal_threshold', 0.5))
            return (y_proba >= threshold).astype(int)
        return self.model.predict(X_scaled)
    
    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Prédit les probabilités [P(normal), P(malicious)]"""
        if self.model is None:
            raise ValueError("Model not trained or loaded")
        
        X_scaled = self.scaler.transform(X)
        return self.model.predict_proba(X_scaled)
    
    def save(self, name: str = "random_forest_model"):
        """Sauvegarde le modèle"""
        model_path = self.model_dir / f"{name}.pkl"
        scaler_path = self.model_dir / f"{name}_scaler.pkl"
        metadata_path = self.model_dir / f"{name}_metadata.json"
        report_path = self.model_dir / f"{name}_report.txt"
        
        # Sauvegarder le modèle
        with open(model_path, 'wb') as f:
            pickle.dump(self.model, f)
        
        # Sauvegarder le scaler
        with open(scaler_path, 'wb') as f:
            pickle.dump(self.scaler, f)
        
        # Sauvegarder les métadonnées
        metadata = {
            'model_type': 'RandomForest',
            'training_history': self.training_history,
            'feature_importance': self.feature_importance.tolist() if self.feature_importance is not None else None,
            'optimal_threshold': float(getattr(self, 'optimal_threshold', 0.5)),
            'saved_at': datetime.now().isoformat()
        }
        
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        # Générer et sauvegarder le rapport texte
        report_text = self._generate_text_report(name)
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(report_text)
        
        self.logger.info(f"Modèle sauvegardé: {model_path}")
        self.logger.info(f"Rapport généré: {report_path}")
    
    def load(self, name: str = "random_forest_model"):
        """Charge le modèle"""
        model_path = self.model_dir / f"{name}.pkl"
        scaler_path = self.model_dir / f"{name}_scaler.pkl"
        metadata_path = self.model_dir / f"{name}_metadata.json"
        
        if not model_path.exists():
            raise FileNotFoundError(f"Model not found: {model_path}")
        
        # Charger le modèle
        with open(model_path, 'rb') as f:
            self.model = pickle.load(f)
        
        # Charger le scaler
        with open(scaler_path, 'rb') as f:
            self.scaler = pickle.load(f)
        
        # Charger les métadonnées
        if metadata_path.exists():
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
                self.training_history = metadata.get('training_history', [])
                fi = metadata.get('feature_importance')
                if fi:
                    self.feature_importance = np.array(fi)
                self.optimal_threshold = float(metadata.get('optimal_threshold', 0.5))
        
        self.logger.info(f"Modèle chargé: {model_path}")
    
    def _get_top_features(self, n: int = 10) -> List[Tuple[int, float]]:
        """Retourne les N features les plus importantes"""
        if self.feature_importance is None:
            return []
        
        indices = np.argsort(self.feature_importance)[::-1][:n]
        return [(int(i), float(self.feature_importance[i])) for i in indices]


class AnomalyDetectionModel(ThreatDetectionModel):
    """Modèle d'apprentissage non supervisé (Isolation Forest)"""
    
    def __init__(self, model_dir: str = "models", 
                 contamination: float = 0.1,
                 db_path: Optional[str] = None):
        super().__init__(model_dir, db_path)
        self.model = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_jobs=-1
        )
    
    def train(self, X: np.ndarray, y: Optional[np.ndarray] = None, 
             validation_split: float = 0.2) -> Dict:
        """
        Entraîne l'Isolation Forest (non supervisé)
        
        Note: y est optionnel, utilisé uniquement pour l'évaluation
        """
        
        self.logger.info(f"Entraînement sur {len(X)} échantillons (non supervisé)")
        
        # Normalisation
        X_scaled = self.scaler.fit_transform(X)
        
        # Entraînement
        self.logger.info("Entraînement de l'Isolation Forest...")
        self.model.fit(X_scaled)
        
        # Prédictions (-1 = anomalie, 1 = normal)
        predictions = self.model.predict(X_scaled)
        anomaly_count = np.sum(predictions == -1)
        
        metrics = {
            'timestamp': datetime.now().isoformat(),
            'train_samples': len(X),
            'anomalies_detected': int(anomaly_count),
            'anomaly_ratio': float(anomaly_count / len(X)),
            'contamination': self.model._contamination  # type: ignore
        }
        
        # Si on a des labels, évaluer
        if y is not None:
            # Convertir -1/1 en 0/1
            y_pred = (predictions == -1).astype(int)
            metrics['classification_report'] = classification_report(
                y, y_pred, output_dict=True, zero_division=0
            )
            metrics['confusion_matrix'] = confusion_matrix(y, y_pred).tolist()
        
        self.training_history.append(metrics)
        
        self.logger.info(f"Anomalies détectées: {anomaly_count}/{len(X)} "
                        f"({metrics['anomaly_ratio']:.2%})")
        
        return metrics
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """Prédit les labels (0 = normal, 1 = anomalie)"""
        if self.model is None:
            raise ValueError("Model not trained or loaded")
        
        X_scaled = self.scaler.transform(X)
        predictions = self.model.predict(X_scaled)
        
        # Convertir -1/1 en 1/0 (1 = anomalie)
        return (predictions == -1).astype(int)
    
    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """
        Retourne les scores d'anomalie (plus négatif = plus anormal)
        Converti en probabilités [P(normal), P(anomalie)]
        """
        if self.model is None:
            raise ValueError("Model not trained or loaded")
        
        X_scaled = self.scaler.transform(X)
        scores = self.model.score_samples(X_scaled)
        
        # Normaliser les scores en probabilités (approximation)
        # Score typiquement entre -1 et 1
        proba_anomaly = 1 / (1 + np.exp(scores))  # Sigmoid
        proba_normal = 1 - proba_anomaly
        
        return np.column_stack([proba_normal, proba_anomaly])
    
    def save(self, name: str = "isolation_forest_model"):
        """Sauvegarde le modèle"""
        model_path = self.model_dir / f"{name}.pkl"
        scaler_path = self.model_dir / f"{name}_scaler.pkl"
        metadata_path = self.model_dir / f"{name}_metadata.json"
        report_path = self.model_dir / f"{name}_report.txt"
        
        with open(model_path, 'wb') as f:
            pickle.dump(self.model, f)
        
        with open(scaler_path, 'wb') as f:
            pickle.dump(self.scaler, f)
        
        metadata = {
            'model_type': 'IsolationForest',
            'training_history': self.training_history,
            'saved_at': datetime.now().isoformat()
        }
        
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        # Générer et sauvegarder le rapport texte
        report_text = self._generate_text_report(name)
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(report_text)
        
        self.logger.info(f"Modèle sauvegardé: {model_path}")
        self.logger.info(f"Rapport généré: {report_path}")
    
    def load(self, name: str = "isolation_forest_model"):
        """Charge le modèle"""
        model_path = self.model_dir / f"{name}.pkl"
        scaler_path = self.model_dir / f"{name}_scaler.pkl"
        
        if not model_path.exists():
            raise FileNotFoundError(f"Model not found: {model_path}")
        
        with open(model_path, 'rb') as f:
            self.model = pickle.load(f)
        
        with open(scaler_path, 'rb') as f:
            self.scaler = pickle.load(f)
        
        self.logger.info(f"Modèle chargé: {model_path}")


class NeuralNetworkThreatModel(ThreatDetectionModel):
    """Modèle de réseau de neurones profond"""
    
    def __init__(self, model_dir: str = "models", 
                 input_dim: int = 85, hidden_layers: List[int] = [128, 64, 32],
                 db_path: Optional[str] = None):
        super().__init__(model_dir, db_path)
        
        if not TENSORFLOW_AVAILABLE:
            raise ImportError("TensorFlow n'est pas installé. pip install tensorflow")
        
        self.input_dim = input_dim
        self.hidden_layers = hidden_layers
        self._build_model()
    
    def _build_model(self):
        """Construit l'architecture du réseau de neurones"""
        assert tf is not None
        self.model = tf.keras.Sequential()  # type: ignore
        
        # Couche d'entrée
        self.model.add(tf.keras.layers.Input(shape=(self.input_dim,)))  # type: ignore
        
        # Couches cachées
        for units in self.hidden_layers:
            self.model.add(tf.keras.layers.Dense(units, activation='relu'))  # type: ignore
            self.model.add(tf.keras.layers.Dropout(0.3))  # type: ignore
            self.model.add(tf.keras.layers.BatchNormalization())  # type: ignore
        
        # Couche de sortie (classification binaire)
        self.model.add(tf.keras.layers.Dense(1, activation='sigmoid'))  # type: ignore
        
        # Compilation
        self.model.compile(
            optimizer='adam',
            loss='binary_crossentropy',
            metrics=['accuracy', tf.keras.metrics.AUC(name='auc')]  # type: ignore
        )
        
        self.logger.info(f"Modèle construit: {len(self.hidden_layers)} couches cachées")
    
    def train(self, X: np.ndarray, y: np.ndarray, 
             validation_split: float = 0.2, epochs: int = 50, 
             batch_size: int = 32) -> Dict:
        """Entraîne le réseau de neurones"""
        assert tf is not None
        
        # Split train/validation
        # Vérifier si stratify est possible
        unique_classes, counts = np.unique(y, return_counts=True)
        use_stratify = all(count >= 2 for count in counts) and len(unique_classes) > 1
        
        if use_stratify:
            X_train, X_val, y_train, y_val = train_test_split(
                X, y, test_size=validation_split, random_state=42, stratify=y
            )
        else:
            self.logger.warning("Stratification désactivée - classes insuffisantes ou déséquilibrées")
            X_train, X_val, y_train, y_val = train_test_split(
                X, y, test_size=validation_split, random_state=42
            )
        
        self.logger.info(f"Entraînement sur {len(X_train)} échantillons, "
                        f"validation sur {len(X_val)} échantillons")
        
        # Normalisation
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_val_scaled = self.scaler.transform(X_val)
        
        # Callbacks
        early_stopping = tf.keras.callbacks.EarlyStopping(  # type: ignore
            monitor='val_loss',
            patience=10,
            restore_best_weights=True
        )
        
        # Entraînement
        self.logger.info(f"Entraînement du réseau de neurones ({epochs} epochs)...")
        history = self.model.fit(
            X_train_scaled, y_train,
            validation_data=(X_val_scaled, y_val),
            epochs=epochs,
            batch_size=batch_size,
            callbacks=[early_stopping],
            verbose=0
        )
        
        # Évaluation
        y_pred_proba = self.model.predict(X_val_scaled, verbose=0).flatten()
        y_pred = (y_pred_proba > 0.5).astype(int)
        
        # Métriques
        metrics = {
            'timestamp': datetime.now().isoformat(),
            'train_samples': len(X_train),
            'val_samples': len(X_val),
            'epochs_trained': len(history.history['loss']),
            'final_train_loss': float(history.history['loss'][-1]),
            'final_val_loss': float(history.history['val_loss'][-1]),
            'final_train_accuracy': float(history.history['accuracy'][-1]),
            'final_val_accuracy': float(history.history['val_accuracy'][-1]),
            'classification_report': classification_report(y_val, y_pred, output_dict=True),
            'confusion_matrix': confusion_matrix(y_val, y_pred).tolist(),
        }
        
        if len(np.unique(y_val)) > 1:
            metrics['roc_auc'] = roc_auc_score(y_val, y_pred_proba)
        
        self.training_history.append(metrics)
        
        self.logger.info(f"Accuracy: Train={metrics['final_train_accuracy']:.4f}, "
                        f"Val={metrics['final_val_accuracy']:.4f}")
        if 'roc_auc' in metrics:
            self.logger.info(f"ROC AUC: {metrics['roc_auc']:.4f}")
        
        return metrics
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """Prédit les labels"""
        if self.model is None:
            raise ValueError("Model not trained or loaded")
        
        X_scaled = self.scaler.transform(X)
        y_pred_proba = self.model.predict(X_scaled, verbose=0).flatten()
        return (y_pred_proba > 0.5).astype(int)
    
    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Prédit les probabilités"""
        if self.model is None:
            raise ValueError("Model not trained or loaded")
        
        X_scaled = self.scaler.transform(X)
        proba_malicious = self.model.predict(X_scaled, verbose=0).flatten()
        proba_normal = 1 - proba_malicious
        
        return np.column_stack([proba_normal, proba_malicious])
    
    def save(self, name: str = "neural_network_model"):
        """Sauvegarde le modèle"""
        assert tf is not None
        model_path = self.model_dir / f"{name}.h5"
        scaler_path = self.model_dir / f"{name}_scaler.pkl"
        metadata_path = self.model_dir / f"{name}_metadata.json"
        report_path = self.model_dir / f"{name}_report.txt"
        
        # Sauvegarder le modèle TensorFlow
        self.model.save(model_path)
        
        # Sauvegarder le scaler
        with open(scaler_path, 'wb') as f:
            pickle.dump(self.scaler, f)
        
        # Sauvegarder les métadonnées
        metadata = {
            'model_type': 'NeuralNetwork',
            'input_dim': self.input_dim,
            'hidden_layers': self.hidden_layers,
            'training_history': self.training_history,
            'saved_at': datetime.now().isoformat()
        }
        
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        # Générer et sauvegarder le rapport texte
        report_text = self._generate_text_report(name)
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(report_text)
        
        self.logger.info(f"Modèle sauvegardé: {model_path}")
        self.logger.info(f"Rapport généré: {report_path}")
    
    def load(self, name: str = "neural_network_model"):
        """Charge le modèle"""
        assert tf is not None
        model_path = self.model_dir / f"{name}.h5"
        scaler_path = self.model_dir / f"{name}_scaler.pkl"
        metadata_path = self.model_dir / f"{name}_metadata.json"
        
        if not model_path.exists():
            raise FileNotFoundError(f"Model not found: {model_path}")
        
        # Charger le modèle TensorFlow
        self.model = tf.keras.models.load_model(model_path)  # type: ignore
        
        # Charger le scaler
        with open(scaler_path, 'rb') as f:
            self.scaler = pickle.load(f)
        
        # Charger les métadonnées
        if metadata_path.exists():
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
                self.training_history = metadata.get('training_history', [])
                self.input_dim = metadata.get('input_dim', 85)
                self.hidden_layers = metadata.get('hidden_layers', [128, 64, 32])
        
        self.logger.info(f"Modèle chargé: {model_path}")
