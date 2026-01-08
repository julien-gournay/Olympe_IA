#!/usr/bin/env python3
"""
Modèles de Machine Learning pour la détection de menaces
Supporte Random Forest, Isolation Forest, et Neural Networks
Celestis_IA - Module ML
"""

import numpy as np
import pickle
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
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
    
    def __init__(self, model_dir: str = "ml/models"):
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)
        
        self.model = None
        self.scaler = StandardScaler()
        self.feature_importance = None
        self.training_history = []
        
        self.logger = logging.getLogger(__name__)
        
    def train(self, X: np.ndarray, y: np.ndarray, 
             validation_split: float = 0.2) -> Dict:
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


class RandomForestThreatModel(ThreatDetectionModel):
    """Modèle Random Forest pour la détection de menaces"""
    
    def __init__(self, model_dir: str = "ml/models", 
                 n_estimators: int = 100, max_depth: int = 20):
        super().__init__(model_dir)
        self.model = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            random_state=42,
            n_jobs=-1,
            class_weight='balanced'  # Pour gérer les classes déséquilibrées
        )
    
    def train(self, X: np.ndarray, y: np.ndarray, 
             validation_split: float = 0.2) -> Dict:
        """Entraîne le Random Forest"""
        
        # Split train/validation
        # Vérifier si stratify est possible (au moins 2 échantillons par classe)
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
        
        # Entraînement
        self.logger.info("Entraînement du Random Forest...")
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
        
        # Métriques
        metrics = {
            'timestamp': datetime.now().isoformat(),
            'train_samples': len(X_train),
            'val_samples': len(X_val),
            'train_accuracy': self.model.score(X_train_scaled, y_train),
            'val_accuracy': self.model.score(X_val_scaled, y_val),
            'classification_report': classification_report(y_val, y_pred, output_dict=True),
            'confusion_matrix': confusion_matrix(y_val, y_pred).tolist(),
        }
        
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
        
        return metrics
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """Prédit les labels (0 = normal, 1 = malicious)"""
        if self.model is None:
            raise ValueError("Model not trained or loaded")
        
        X_scaled = self.scaler.transform(X)
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
            'saved_at': datetime.now().isoformat()
        }
        
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        self.logger.info(f"Modèle sauvegardé: {model_path}")
    
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
        
        self.logger.info(f"Modèle chargé: {model_path}")
    
    def _get_top_features(self, n: int = 10) -> List[Tuple[int, float]]:
        """Retourne les N features les plus importantes"""
        if self.feature_importance is None:
            return []
        
        indices = np.argsort(self.feature_importance)[::-1][:n]
        return [(int(i), float(self.feature_importance[i])) for i in indices]


class AnomalyDetectionModel(ThreatDetectionModel):
    """Modèle d'apprentissage non supervisé (Isolation Forest)"""
    
    def __init__(self, model_dir: str = "ml/models", 
                 contamination: float = 0.1):
        super().__init__(model_dir)
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
        
        self.logger.info(f"Modèle sauvegardé: {model_path}")
    
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
    
    def __init__(self, model_dir: str = "ml/models", 
                 input_dim: int = 85, hidden_layers: List[int] = [128, 64, 32]):
        super().__init__(model_dir)
        
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
        
        self.logger.info(f"Modèle sauvegardé: {model_path}")
    
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
