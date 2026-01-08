"""
Module ML - Intelligence Artificielle pour la détection de menaces
Celestis_IA

Ce module fournit des capacités d'apprentissage automatique adaptatif
pour la détection de menaces réseau.
"""

__version__ = "1.0.0"
__author__ = "Celestis_IA Team"

# Imports principaux pour faciliter l'utilisation
from .feature_extractor import NetworkFeatureExtractor
from .threat_models import (
    RandomForestThreatModel,
    AnomalyDetectionModel,
    NeuralNetworkThreatModel
)
from .trainer import ThreatDatasetBuilder, ContinuousLearningSystem
from .ml_detector import MLThreatDetector

__all__ = [
    'NetworkFeatureExtractor',
    'RandomForestThreatModel',
    'AnomalyDetectionModel',
    'NeuralNetworkThreatModel',
    'ThreatDatasetBuilder',
    'ContinuousLearningSystem',
    'MLThreatDetector'
]
