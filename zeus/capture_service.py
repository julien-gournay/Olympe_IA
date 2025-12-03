#!/usr/bin/env python3
"""
Service de capture réseau continue
Celestis_IA - Module Zeus
"""

import argparse
import logging
import signal
import sys
from datetime import datetime
from pathlib import Path
from threading import Event
from typing import Optional

import yaml

try:
    from capture_reseau import NetworkCapture
    from ingestion_pcap import PcapIngestion
except ImportError as e:
    print(f"Erreur d'import: {e}")
    print("Assurez-vous que capture_reseau.py et ingestion_pcap.py sont dans le même répertoire")
    sys.exit(1)


class CaptureService:
    """Service de capture réseau continue avec ingestion automatique"""
    
    def __init__(self, config_file: str = "config.yaml"):
        """
        Initialise le service
        
        Args:
            config_file: Chemin vers le fichier de configuration
        """
        self.config_file = Path(config_file)
        self.config = self._load_config()
        self.running = Event()
        self.logger = self._setup_logging()
        
        # Composants
        self.capture: Optional[NetworkCapture] = None
        self.ingestion: Optional[PcapIngestion] = None
        
        # Statistiques
        self.stats = {
            'captures_completed': 0,
            'total_packets': 0,
            'files_ingested': 0,
            'start_time': None
        }
    
    def _load_config(self) -> dict:
        """Charge la configuration"""
        if not self.config_file.exists():
            print(f"Erreur: Fichier de configuration introuvable: {self.config_file}")
            sys.exit(1)
        
        with open(self.config_file, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)
    
    def _setup_logging(self):
        """Configure le logging"""
        log_dir = Path(self.config.get('ingestion', {}).get('log_directory', 'logs'))
        log_dir.mkdir(parents=True, exist_ok=True)
        
        log_file = log_dir / f"service_{datetime.now().strftime('%Y%m%d')}.log"
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        return logging.getLogger(__name__)
    
    def _signal_handler(self, signum, frame):
        """Gestionnaire de signal pour arrêt gracieux"""
        self.logger.info("\nArrêt du service demandé...")
        self.running.clear()
    
    def initialize(self) -> bool:
        """
        Initialise les composants du service
        
        Returns:
            True si succès
        """
        try:
            # Configuration de la capture
            capture_config = self.config.get('capture', {})
            self.capture = NetworkCapture(
                interface=capture_config.get('interface'),
                output_dir=capture_config.get('output_directory', 'captures'),
                filter_bpf=capture_config.get('filter_bpf')
            )
            
            # Configuration de l'ingestion
            ingestion_config = self.config.get('ingestion', {})
            self.ingestion = PcapIngestion(
                db_path=ingestion_config.get('database_path', 'pcap_database.db'),
                log_dir=ingestion_config.get('log_directory', 'logs')
            )
            
            self.logger.info("Service initialisé avec succès")
            return True
            
        except Exception as e:
            self.logger.error(f"Erreur lors de l'initialisation: {e}")
            return False
    
    def capture_session(self) -> Optional[Path]:
        """
        Effectue une session de capture
        
        Returns:
            Chemin du fichier PCAP créé (Path) ou None
        """
        try:
            if not self.capture:
                self.logger.error("Capture non initialisée")
                return None
                
            capture_config = self.config.get('capture', {})
            rotation_config = capture_config.get('rotation', {})
            
            max_packets = rotation_config.get('max_packets', 10000)
            max_duration = rotation_config.get('max_duration', 300)
            
            self.logger.info(f"Démarrage d'une session de capture (max {max_packets} paquets, {max_duration}s)")
            
            # Capturer
            self.capture.start_capture(count=max_packets, timeout=max_duration)
            
            # Sauvegarder
            if self.capture.packets:
                output_file = self.capture.save_capture()
                
                # Mettre à jour les statistiques
                self.stats['captures_completed'] += 1
                self.stats['total_packets'] += len(self.capture.packets)
                
                return output_file
            else:
                self.logger.warning("Aucun paquet capturé dans cette session")
                return None
                
        except Exception as e:
            self.logger.error(f"Erreur lors de la capture: {e}")
            return None
    
    def ingest_file(self, pcap_file: Path) -> bool:
        """
        Ingère un fichier PCAP
        
        Args:
            pcap_file: Chemin du fichier PCAP
            
        Returns:
            True si succès
        """
        try:
            if not self.ingestion:
                self.logger.error("Ingestion non initialisée")
                return False
                
            self.logger.info(f"Ingestion de {pcap_file.name}")
            pcap_id = self.ingestion.ingest_pcap(str(pcap_file))
            
            if pcap_id:
                self.stats['files_ingested'] += 1
                self.logger.info(f"Ingestion réussie (ID: {pcap_id})")
                return True
            else:
                self.logger.error("Échec de l'ingestion")
                return False
                
        except Exception as e:
            self.logger.error(f"Erreur lors de l'ingestion: {e}")
            return False
    
    def run_continuous(self):
        """Mode de capture continue"""
        self.logger.info("=== Démarrage du service de capture continue ===")
        self.stats['start_time'] = datetime.now()
        
        service_config = self.config.get('service', {})
        interval = service_config.get('interval', 60)
        auto_ingest = self.config.get('ingestion', {}).get('auto_ingest', True)
        
        self.running.set()
        
        # Enregistrer le gestionnaire de signal
        signal.signal(signal.SIGINT, self._signal_handler)
        if hasattr(signal, 'SIGTERM'):
            signal.signal(signal.SIGTERM, self._signal_handler)
        
        try:
            while self.running.is_set():
                # Capturer
                pcap_file = self.capture_session()
                
                # Ingérer automatiquement si configuré
                if pcap_file and auto_ingest:
                    self.ingest_file(pcap_file)
                
                # Afficher les statistiques
                self.print_stats()
                
                # Attendre avant la prochaine capture
                if self.running.is_set():
                    self.logger.info(f"Attente de {interval}s avant la prochaine capture...")
                    self.running.wait(timeout=interval)
                    
        except Exception as e:
            self.logger.error(f"Erreur dans la boucle principale: {e}")
        
        finally:
            self.logger.info("Service arrêté")
            self.print_final_stats()
    
    def run_single_cycle(self):
        """Mode de capture unique"""
        self.logger.info("=== Exécution d'un cycle de capture ===")
        self.stats['start_time'] = datetime.now()
        
        # Capturer
        pcap_file = self.capture_session()
        
        # Ingérer si configuré
        if pcap_file:
            auto_ingest = self.config.get('ingestion', {}).get('auto_ingest', True)
            if auto_ingest:
                self.ingest_file(pcap_file)
        
        self.print_final_stats()
    
    def run_watch_mode(self):
        """Mode surveillance d'un répertoire"""
        self.logger.info("=== Démarrage du mode surveillance ===")
        
        watch_dir = Path(self.config.get('ingestion', {}).get('watch_directory', 'captures'))
        
        if not watch_dir.exists():
            self.logger.error(f"Répertoire introuvable: {watch_dir}")
            return
        
        self.logger.info(f"Surveillance du répertoire: {watch_dir}")
        
        # Garder une trace des fichiers déjà traités
        processed_files = set()
        
        self.running.set()
        signal.signal(signal.SIGINT, self._signal_handler)
        
        try:
            while self.running.is_set():
                # Rechercher de nouveaux fichiers PCAP
                pcap_files = set(watch_dir.glob('*.pcap'))
                new_files = pcap_files - processed_files
                
                if new_files:
                    self.logger.info(f"Nouveaux fichiers détectés: {len(new_files)}")
                    
                    for pcap_file in new_files:
                        if self.ingest_file(pcap_file):
                            processed_files.add(pcap_file)
                
                # Attendre avant la prochaine vérification
                self.running.wait(timeout=10)
                
        except Exception as e:
            self.logger.error(f"Erreur dans le mode surveillance: {e}")
        
        finally:
            self.logger.info("Mode surveillance arrêté")
            self.print_final_stats()
    
    def print_stats(self):
        """Affiche les statistiques courantes"""
        uptime = (datetime.now() - self.stats['start_time']).total_seconds()
        
        self.logger.info("\n--- Statistiques ---")
        self.logger.info(f"Temps d'exécution: {uptime:.0f}s")
        self.logger.info(f"Captures complétées: {self.stats['captures_completed']}")
        self.logger.info(f"Total paquets: {self.stats['total_packets']}")
        self.logger.info(f"Fichiers ingérés: {self.stats['files_ingested']}")
        self.logger.info("-------------------\n")
    
    def print_final_stats(self):
        """Affiche les statistiques finales"""
        if self.stats['start_time']:
            uptime = (datetime.now() - self.stats['start_time']).total_seconds()
            
            self.logger.info("\n=== Statistiques finales ===")
            self.logger.info(f"Durée totale: {uptime:.0f}s")
            self.logger.info(f"Captures complétées: {self.stats['captures_completed']}")
            self.logger.info(f"Total paquets capturés: {self.stats['total_packets']}")
            self.logger.info(f"Fichiers ingérés: {self.stats['files_ingested']}")
            
            if self.stats['captures_completed'] > 0:
                avg_packets = self.stats['total_packets'] / self.stats['captures_completed']
                self.logger.info(f"Moyenne paquets/capture: {avg_packets:.0f}")
            
            self.logger.info("===========================\n")


def main():
    """Fonction principale"""
    parser = argparse.ArgumentParser(
        description="Service de capture réseau continue - Celestis_IA",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation:
  # Mode continu (capture en boucle)
  python capture_service.py --continuous
  
  # Mode cycle unique
  python capture_service.py --single
  
  # Mode surveillance (ingestion automatique)
  python capture_service.py --watch
  
  # Avec configuration personnalisée
  python capture_service.py --continuous --config my_config.yaml
        """
    )
    
    parser.add_argument('--config',
                        default='config.yaml',
                        help='Fichier de configuration (défaut: config.yaml)')
    parser.add_argument('--continuous',
                        action='store_true',
                        help='Mode capture continue')
    parser.add_argument('--single',
                        action='store_true',
                        help='Mode cycle unique')
    parser.add_argument('--watch',
                        action='store_true',
                        help='Mode surveillance de répertoire')
    
    args = parser.parse_args()
    
    # Créer le service
    service = CaptureService(config_file=args.config)
    
    # Initialiser
    if not service.initialize():
        sys.exit(1)
    
    # Démarrer selon le mode
    if args.continuous:
        service.run_continuous()
    elif args.single:
        service.run_single_cycle()
    elif args.watch:
        service.run_watch_mode()
    else:
        parser.print_help()
        print("\nVeuillez spécifier un mode: --continuous, --single, ou --watch")


if __name__ == "__main__":
    main()
