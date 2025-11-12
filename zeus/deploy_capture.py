#!/usr/bin/env python3
"""
Script de déploiement pour la solution de capture PCAP locale
Celestis_IA - Module Zeus
"""

import argparse
import json
import logging
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

import yaml


class CaptureDeployment:
    """Classe pour déployer la solution de capture PCAP"""
    
    def __init__(self, config_file: str = "config.yaml"):
        """
        Initialise le déploiement
        
        Args:
            config_file: Chemin vers le fichier de configuration
        """
        self.config_file = Path(config_file)
        self.config = {}
        self.logger = self._setup_logging()
        
    def _setup_logging(self):
        """Configure le système de logging"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler()
            ]
        )
        return logging.getLogger(__name__)
    
    def load_config(self) -> bool:
        """
        Charge la configuration depuis le fichier YAML
        
        Returns:
            True si succès, False sinon
        """
        if not self.config_file.exists():
            self.logger.error(f"Fichier de configuration introuvable: {self.config_file}")
            return False
        
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                self.config = yaml.safe_load(f)
            self.logger.info(f"Configuration chargée: {self.config_file}")
            return True
        except Exception as e:
            self.logger.error(f"Erreur lors du chargement de la configuration: {e}")
            return False
    
    def check_dependencies(self) -> bool:
        """
        Vérifie que toutes les dépendances sont installées
        
        Returns:
            True si toutes les dépendances sont présentes
        """
        self.logger.info("Vérification des dépendances...")
        
        required_modules = ['scapy', 'yaml']
        missing = []
        
        for module in required_modules:
            try:
                __import__(module)
                self.logger.info(f"  ✓ {module}")
            except ImportError:
                self.logger.warning(f"  ✗ {module} (manquant)")
                missing.append(module)
        
        # Vérifier Python version
        python_version = sys.version_info
        if python_version.major < 3 or (python_version.major == 3 and python_version.minor < 7):
            self.logger.error(f"Python 3.7+ requis (version actuelle: {sys.version})")
            return False
        
        self.logger.info(f"  ✓ Python {python_version.major}.{python_version.minor}")
        
        if missing:
            self.logger.warning(f"\nDépendances manquantes: {', '.join(missing)}")
            self.logger.info("Installez-les avec: pip install -r requirements.txt")
            return False
        
        return True
    
    def check_permissions(self) -> bool:
        """
        Vérifie les permissions nécessaires pour la capture réseau
        
        Returns:
            True si les permissions sont suffisantes
        """
        self.logger.info("Vérification des permissions...")
        
        system = platform.system()
        
        if system == 'Windows':
            try:
                import ctypes
                is_admin = ctypes.windll.shell32.IsUserAnAdmin()
                if not is_admin:
                    self.logger.warning("  ⚠ Privilèges administrateur non détectés")
                    self.logger.warning("  La capture réseau peut ne pas fonctionner correctement")
                    self.logger.info("  Relancez ce script en tant qu'administrateur si nécessaire")
                else:
                    self.logger.info("  ✓ Privilèges administrateur")
                return True  # On continue même sans admin sur Windows
            except:
                self.logger.warning("  ⚠ Impossible de vérifier les privilèges")
                return True
        
        elif system == 'Linux':
            if os.geteuid() != 0:
                self.logger.warning("  ⚠ Non-root: certaines interfaces peuvent être inaccessibles")
                self.logger.info("  Utilisez sudo si nécessaire")
            else:
                self.logger.info("  ✓ Privilèges root")
            return True
        
        elif system == 'Darwin':  # macOS
            if os.geteuid() != 0:
                self.logger.warning("  ⚠ Non-root: certaines interfaces peuvent être inaccessibles")
                self.logger.info("  Utilisez sudo si nécessaire")
            else:
                self.logger.info("  ✓ Privilèges root")
            return True
        
        return True
    
    def create_directories(self) -> bool:
        """
        Crée les répertoires nécessaires
        
        Returns:
            True si succès
        """
        self.logger.info("Création des répertoires...")
        
        directories = [
            self.config.get('capture', {}).get('output_directory', 'captures'),
            self.config.get('ingestion', {}).get('log_directory', 'logs'),
            'exports',
            'config'
        ]
        
        try:
            for directory in directories:
                dir_path = Path(directory)
                dir_path.mkdir(parents=True, exist_ok=True)
                self.logger.info(f"  ✓ {directory}")
            return True
        except Exception as e:
            self.logger.error(f"Erreur lors de la création des répertoires: {e}")
            return False
    
    def test_capture(self, duration: int = 5, count: int = 10) -> bool:
        """
        Teste la capture réseau
        
        Args:
            duration: Durée du test en secondes
            count: Nombre de paquets à capturer
            
        Returns:
            True si le test réussit
        """
        self.logger.info(f"\nTest de capture réseau ({count} paquets)...")
        
        try:
            # Import local pour éviter les erreurs si scapy n'est pas installé
            from scapy.all import sniff
            
            interface = self.config.get('capture', {}).get('interface')
            
            self.logger.info(f"  Interface: {interface or 'toutes'}")
            self.logger.info(f"  Durée: {duration}s")
            
            packets = sniff(
                iface=interface,
                count=count,
                timeout=duration,
                store=True
            )
            
            if len(packets) > 0:
                self.logger.info(f"  ✓ {len(packets)} paquets capturés")
                return True
            else:
                self.logger.warning("  ⚠ Aucun paquet capturé")
                self.logger.info("  Vérifiez l'interface réseau et les permissions")
                return False
                
        except PermissionError:
            self.logger.error("  ✗ Permissions insuffisantes")
            self.logger.info("  Relancez avec des privilèges administrateur/root")
            return False
        except Exception as e:
            self.logger.error(f"  ✗ Erreur lors du test: {e}")
            return False
    
    def initialize_database(self) -> bool:
        """
        Initialise la base de données pour l'ingestion
        
        Returns:
            True si succès
        """
        self.logger.info("\nInitialisation de la base de données...")
        
        try:
            from ingestion_pcap import PcapIngestion
            
            db_path = self.config.get('ingestion', {}).get('database_path', 'pcap_database.db')
            log_dir = self.config.get('ingestion', {}).get('log_directory', 'logs')
            
            ingestion = PcapIngestion(db_path=db_path, log_dir=log_dir)
            self.logger.info(f"  ✓ Base de données créée: {db_path}")
            return True
        except Exception as e:
            self.logger.error(f"  ✗ Erreur lors de l'initialisation: {e}")
            return False
    
    def generate_sample_config(self, output_file: str = "config.yaml") -> bool:
        """
        Génère un fichier de configuration exemple
        
        Args:
            output_file: Chemin du fichier de sortie
            
        Returns:
            True si succès
        """
        sample_config = {
            'capture': {
                'interface': None,  # None = toutes les interfaces
                'output_directory': 'captures',
                'filter_bpf': None,  # Exemple: "tcp port 80"
                'rotation': {
                    'enabled': True,
                    'max_packets': 10000,
                    'max_duration': 300  # secondes
                }
            },
            'ingestion': {
                'database_path': 'pcap_database.db',
                'log_directory': 'logs',
                'auto_ingest': True,
                'watch_directory': 'captures'
            },
            'service': {
                'continuous_capture': False,
                'interval': 60,  # secondes entre chaque capture
                'auto_start': False
            },
            'analysis': {
                'enable_statistics': True,
                'enable_export': False,
                'export_format': 'json'
            }
        }
        
        try:
            output_path = Path(output_file)
            with open(output_path, 'w', encoding='utf-8') as f:
                yaml.dump(sample_config, f, default_flow_style=False, allow_unicode=True)
            
            self.logger.info(f"Configuration exemple créée: {output_path}")
            return True
        except Exception as e:
            self.logger.error(f"Erreur lors de la création du fichier de configuration: {e}")
            return False
    
    def deploy(self, skip_test: bool = False) -> bool:
        """
        Déploie la solution complète
        
        Args:
            skip_test: Si True, ignore le test de capture
            
        Returns:
            True si le déploiement réussit
        """
        self.logger.info("=== Déploiement de la solution de capture PCAP ===\n")
        
        # Étape 1: Vérifier les dépendances
        if not self.check_dependencies():
            self.logger.error("\n❌ Déploiement échoué: dépendances manquantes")
            return False
        
        # Étape 2: Charger la configuration
        if not self.load_config():
            self.logger.error("\n❌ Déploiement échoué: configuration invalide")
            return False
        
        # Étape 3: Vérifier les permissions
        self.check_permissions()  # Non bloquant
        
        # Étape 4: Créer les répertoires
        if not self.create_directories():
            self.logger.error("\n❌ Déploiement échoué: création des répertoires")
            return False
        
        # Étape 5: Initialiser la base de données
        if not self.initialize_database():
            self.logger.error("\n❌ Déploiement échoué: initialisation de la base de données")
            return False
        
        # Étape 6: Tester la capture (optionnel)
        if not skip_test:
            test_result = self.test_capture()
            if not test_result:
                self.logger.warning("\n⚠ Avertissement: test de capture échoué")
                self.logger.info("Le déploiement continue mais la capture peut ne pas fonctionner")
        
        self.logger.info("\n✅ Déploiement réussi!")
        self.logger.info("\nProchaines étapes:")
        self.logger.info("  1. Vérifiez et ajustez config.yaml selon vos besoins")
        self.logger.info("  2. Lancez une capture: python capture_reseau.py")
        self.logger.info("  3. Ingérez les fichiers: python ingestion_pcap.py -d captures")
        self.logger.info("  4. Pour un service continu: python capture_service.py")
        
        return True
    
    def show_status(self):
        """Affiche le statut du système"""
        self.logger.info("=== Statut du système ===\n")
        
        # Vérifier les fichiers
        files = {
            'capture_reseau.py': Path('capture_reseau.py'),
            'ingestion_pcap.py': Path('ingestion_pcap.py'),
            'capture_service.py': Path('capture_service.py'),
            'config.yaml': Path('config.yaml')
        }
        
        self.logger.info("Fichiers:")
        for name, path in files.items():
            status = "✓" if path.exists() else "✗"
            self.logger.info(f"  {status} {name}")
        
        # Vérifier les répertoires
        self.logger.info("\nRépertoires:")
        directories = ['captures', 'logs', 'exports', 'config']
        for directory in directories:
            path = Path(directory)
            status = "✓" if path.exists() else "✗"
            count = len(list(path.glob('*'))) if path.exists() else 0
            self.logger.info(f"  {status} {directory}/ ({count} fichiers)")
        
        # Vérifier la base de données
        db_path = Path('pcap_database.db')
        if db_path.exists():
            size_mb = db_path.stat().st_size / (1024 * 1024)
            self.logger.info(f"\nBase de données: ✓ ({size_mb:.2f} MB)")
        else:
            self.logger.info("\nBase de données: ✗")
        
        # Vérifier les dépendances
        self.logger.info("\nDépendances:")
        self.check_dependencies()


def main():
    """Fonction principale"""
    parser = argparse.ArgumentParser(
        description="Déploiement de la solution de capture PCAP - Celestis_IA",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation:
  # Générer une configuration exemple
  python deploy_capture.py --generate-config
  
  # Déployer la solution
  python deploy_capture.py --deploy
  
  # Vérifier le statut
  python deploy_capture.py --status
  
  # Déployer sans test de capture
  python deploy_capture.py --deploy --skip-test
        """
    )
    
    parser.add_argument('--config',
                        default='config.yaml',
                        help='Fichier de configuration (défaut: config.yaml)')
    parser.add_argument('--generate-config',
                        action='store_true',
                        help='Générer un fichier de configuration exemple')
    parser.add_argument('--deploy',
                        action='store_true',
                        help='Déployer la solution')
    parser.add_argument('--skip-test',
                        action='store_true',
                        help='Ignorer le test de capture')
    parser.add_argument('--status',
                        action='store_true',
                        help='Afficher le statut du système')
    parser.add_argument('--check-deps',
                        action='store_true',
                        help='Vérifier uniquement les dépendances')
    
    args = parser.parse_args()
    
    deployment = CaptureDeployment(config_file=args.config)
    
    # Générer la configuration
    if args.generate_config:
        deployment.generate_sample_config(args.config)
        return
    
    # Vérifier les dépendances
    if args.check_deps:
        deployment.check_dependencies()
        return
    
    # Afficher le statut
    if args.status:
        deployment.show_status()
        return
    
    # Déployer
    if args.deploy:
        success = deployment.deploy(skip_test=args.skip_test)
        sys.exit(0 if success else 1)
    
    # Si aucune action, afficher l'aide
    parser.print_help()


if __name__ == "__main__":
    main()
