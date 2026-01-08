#!/usr/bin/env python3
"""
Script d'automatisation du workflow complet d'entraînement de l'IA
Basé sur le QUICKSTART.md

Usage:
    python train_ai_workflow.py [--interface INTERFACE] [--duration MINUTES]
"""

import subprocess
import sys
import time
import argparse
from pathlib import Path
from datetime import datetime
import os

class Colors:
    """Couleurs pour l'affichage terminal"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


class AITrainingWorkflow:
    """Gestionnaire du workflow complet d'entraînement"""
    
    def __init__(self, network_interface="Wi-Fi", duration_minutes=15):
        self.root_dir = Path(__file__).parent
        self.zeus_dir = self.root_dir / "zeus"
        self.ml_dir = self.root_dir / "ml"
        self.interface = network_interface
        self.duration_minutes = duration_minutes
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.pcap_file = f"training_data_{self.timestamp}.pcap"
        self.db_path = self.zeus_dir / "pcap_database.db"
        
    def print_step(self, step_num, total_steps, message):
        """Affiche un message de progression"""
        print(f"\n{Colors.HEADER}{'='*70}{Colors.ENDC}")
        print(f"{Colors.BOLD}Étape {step_num}/{total_steps}: {message}{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*70}{Colors.ENDC}\n")
    
    def print_success(self, message):
        """Affiche un message de succès"""
        print(f"{Colors.OKGREEN}✓ {message}{Colors.ENDC}")
    
    def print_error(self, message):
        """Affiche un message d'erreur"""
        print(f"{Colors.FAIL}✗ {message}{Colors.ENDC}")
    
    def print_info(self, message):
        """Affiche un message d'information"""
        print(f"{Colors.OKCYAN}ℹ {message}{Colors.ENDC}")
    
    def print_warning(self, message):
        """Affiche un message d'avertissement"""
        print(f"{Colors.WARNING}⚠ {message}{Colors.ENDC}")
    
    def run_command(self, cmd, cwd=None, timeout=None):
        """Exécute une commande et retourne le résultat"""
        try:
            self.print_info(f"Commande: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                cwd=cwd or self.root_dir,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=True
            )
            if result.stdout:
                print(result.stdout)
            return True, result.stdout
        except subprocess.CalledProcessError as e:
            self.print_error(f"Erreur lors de l'exécution: {e}")
            if e.stdout:
                print(f"STDOUT: {e.stdout}")
            if e.stderr:
                print(f"STDERR: {e.stderr}")
            return False, e.stderr
        except subprocess.TimeoutExpired:
            self.print_error(f"Timeout atteint")
            return False, "Timeout"
        except Exception as e:
            self.print_error(f"Erreur inattendue: {e}")
            return False, str(e)
    
    def step1_capture_traffic(self):
        """Étape 1: Capturer le trafic réseau pendant N minutes"""
        self.print_step(1, 5, f"Capture du trafic réseau pendant {self.duration_minutes} minutes")
        
        capture_path = self.zeus_dir / "captures" / self.pcap_file
        
        # Créer le dossier captures s'il n'existe pas
        capture_path.parent.mkdir(parents=True, exist_ok=True)
        
        self.print_info(f"Interface réseau: {self.interface}")
        self.print_info(f"Durée: {self.duration_minutes} minutes ({self.duration_minutes * 60} secondes)")
        self.print_info(f"Fichier de sortie: {capture_path}")
        
        # Calculer un nombre approximatif de paquets (100 paquets/sec * 60 * minutes)
        # On utilise plutôt une capture temporisée
        estimated_packets = self.duration_minutes * 60 * 100
        
        self.print_warning(f"La capture va démarrer. Générez du trafic réseau pour améliorer l'entraînement.")
        self.print_info(f"Estimation: ~{estimated_packets} paquets")
        
        cmd = [
            sys.executable,
            "capture_reseau.py",
            "-i", self.interface,
            "-c", str(estimated_packets),
            "-o", f"captures/{self.pcap_file}"
        ]
        
        # Timeout = durée + 2 minutes de marge
        timeout = (self.duration_minutes + 2) * 60
        
        success, output = self.run_command(cmd, cwd=self.zeus_dir, timeout=timeout)
        
        if success and capture_path.exists():
            size_mb = capture_path.stat().st_size / (1024 * 1024)
            self.print_success(f"Capture terminée! Fichier: {self.pcap_file} ({size_mb:.2f} MB)")
            return True
        else:
            self.print_error("La capture a échoué ou le fichier n'a pas été créé")
            return False
    
    def step2_ingest_pcap(self):
        """Étape 2: Ingérer et analyser le PCAP avec YARA"""
        self.print_step(2, 5, "Ingestion et analyse du PCAP avec règles YARA")
        
        cmd = [
            sys.executable,
            "ingestion_pcap.py",
            "-f", f"captures/{self.pcap_file}",
            "--enable-yara"
        ]
        
        success, output = self.run_command(cmd, cwd=self.zeus_dir, timeout=600)
        
        if success:
            self.print_success("Ingestion et analyse YARA terminées")
            return True
        else:
            self.print_error("L'ingestion a échoué")
            return False
    
    def step3_build_dataset(self):
        """Étape 3: Construire le dataset ML"""
        self.print_step(3, 5, "Construction du dataset ML")
        
        cmd = [
            sys.executable,
            "trainer.py",
            "--build-dataset",
            "--db", str(self.db_path)
        ]
        
        success, output = self.run_command(cmd, cwd=self.ml_dir, timeout=300)
        
        if success:
            self.print_success("Dataset ML construit avec succès")
            # Extraire les infos du dataset si disponibles dans l'output
            if "échantillons" in output or "samples" in output:
                print(f"\n{Colors.OKBLUE}{output}{Colors.ENDC}")
            return True
        else:
            self.print_warning("La construction du dataset a rencontré des problèmes")
            self.print_info("Cela peut être normal si vous n'avez pas encore assez de données")
            return True  # On continue quand même
    
    def step4_train_model(self):
        """Étape 4: Entraîner le modèle"""
        self.print_step(4, 5, "Entraînement du modèle Random Forest")
        
        model_name = f"threat_detector_{self.timestamp}"
        
        cmd = [
            sys.executable,
            "trainer.py",
            "--train",
            "--model-type", "random_forest",
            "--model-name", model_name,
            "--db", str(self.db_path)
        ]
        
        self.print_info(f"Nom du modèle: {model_name}")
        
        success, output = self.run_command(cmd, cwd=self.ml_dir, timeout=600)
        
        if success:
            self.print_success(f"Modèle entraîné avec succès: {model_name}")
            # Extraire les métriques si disponibles
            if "Accuracy" in output or "ROC AUC" in output:
                print(f"\n{Colors.OKGREEN}{output}{Colors.ENDC}")
            
            # Vérifier que le modèle a été sauvegardé
            model_path = self.ml_dir / "models" / f"{model_name}.pkl"
            if model_path.exists():
                self.print_success(f"Modèle sauvegardé: {model_path}")
            
            return True, model_name
        else:
            self.print_error("L'entraînement du modèle a échoué")
            return False, None
    
    def step5_test_model(self, model_name):
        """Étape 5 (optionnelle): Tester le modèle sur le PCAP capturé"""
        self.print_step(5, 5, "Test du modèle sur les données capturées")
        
        cmd = [
            sys.executable,
            "ml_detector.py",
            "-f", str(self.zeus_dir / "captures" / self.pcap_file),
            "--model", f"models/{model_name}"
        ]
        
        success, output = self.run_command(cmd, cwd=self.ml_dir, timeout=300)
        
        if success:
            self.print_success("Test du modèle terminé")
            return True
        else:
            self.print_warning("Le test du modèle a échoué (cela peut être normal)")
            return True  # On ne bloque pas le workflow
    
    def run_workflow(self):
        """Exécute le workflow complet"""
        print(f"\n{Colors.BOLD}{Colors.HEADER}")
        print("╔════════════════════════════════════════════════════════════════════╗")
        print("║    🚀 WORKFLOW D'ENTRAÎNEMENT DE L'IA - CELESTIS IA 🚀            ║")
        print("╚════════════════════════════════════════════════════════════════════╝")
        print(f"{Colors.ENDC}")
        
        self.print_info(f"Heure de début: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self.print_info(f"Interface réseau: {self.interface}")
        self.print_info(f"Durée de capture: {self.duration_minutes} minutes")
        self.print_info(f"Base de données: {self.db_path}")
        
        start_time = time.time()
        
        # Vérifier que les dossiers existent
        if not self.zeus_dir.exists():
            self.print_error(f"Le dossier zeus n'existe pas: {self.zeus_dir}")
            return False
        
        if not self.ml_dir.exists():
            self.print_error(f"Le dossier ml n'existe pas: {self.ml_dir}")
            return False
        
        # Étape 1: Capture
        if not self.step1_capture_traffic():
            self.print_error("Échec à l'étape 1: Capture réseau")
            return False
        
        # Étape 2: Ingestion
        if not self.step2_ingest_pcap():
            self.print_error("Échec à l'étape 2: Ingestion PCAP")
            return False
        
        # Étape 3: Construction du dataset
        if not self.step3_build_dataset():
            self.print_error("Échec à l'étape 3: Construction du dataset")
            return False
        
        # Étape 4: Entraînement
        success, model_name = self.step4_train_model()
        if not success:
            self.print_error("Échec à l'étape 4: Entraînement du modèle")
            return False
        
        # Étape 5: Test (optionnel)
        if model_name:
            self.step5_test_model(model_name)
        
        # Résumé final
        elapsed_time = time.time() - start_time
        minutes = int(elapsed_time // 60)
        seconds = int(elapsed_time % 60)
        
        print(f"\n{Colors.BOLD}{Colors.OKGREEN}")
        print("╔════════════════════════════════════════════════════════════════════╗")
        print("║                   ✓ WORKFLOW TERMINÉ AVEC SUCCÈS ✓                ║")
        print("╚════════════════════════════════════════════════════════════════════╝")
        print(f"{Colors.ENDC}")
        
        self.print_success(f"Temps total d'exécution: {minutes}m {seconds}s")
        self.print_success(f"Fichier PCAP: {self.pcap_file}")
        if model_name:
            self.print_success(f"Modèle entraîné: {model_name}")
        
        print(f"\n{Colors.OKCYAN}Prochaines étapes:{Colors.ENDC}")
        print(f"  1. Tester le modèle: cd ml && python ml_detector.py -f ../zeus/captures/[nouveau_pcap].pcap --model models/{model_name}")
        print(f"  2. Utiliser l'analyse hybride: cd ml && python hybrid_analyzer.py -f ../zeus/captures/[nouveau_pcap].pcap")
        print(f"  3. Améliorer avec feedback: Voir ml/QUICKSTART.md section 'Cas 2: Amélioration Continue'")
        
        return True


def main():
    """Point d'entrée principal"""
    parser = argparse.ArgumentParser(
        description="Workflow automatisé d'entraînement de l'IA pour Celestis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples:
  python train_ai_workflow.py
  python train_ai_workflow.py --interface Ethernet --duration 30
  python train_ai_workflow.py -i Wi-Fi -d 10
        """
    )
    
    parser.add_argument(
        "-i", "--interface",
        default="Wi-Fi",
        help="Interface réseau à capturer (défaut: Wi-Fi)"
    )
    
    parser.add_argument(
        "-d", "--duration",
        type=int,
        default=15,
        help="Durée de capture en minutes (défaut: 15)"
    )
    
    args = parser.parse_args()
    
    # Valider les arguments
    if args.duration < 1:
        print(f"{Colors.FAIL}Erreur: La durée doit être au moins 1 minute{Colors.ENDC}")
        return 1
    
    if args.duration > 120:
        print(f"{Colors.WARNING}Attention: Une capture de {args.duration} minutes est très longue{Colors.ENDC}")
        response = input("Continuer? [o/N]: ")
        if response.lower() not in ['o', 'oui', 'y', 'yes']:
            print("Annulé par l'utilisateur")
            return 0
    
    # Lancer le workflow
    workflow = AITrainingWorkflow(
        network_interface=args.interface,
        duration_minutes=args.duration
    )
    
    try:
        success = workflow.run_workflow()
        return 0 if success else 1
    except KeyboardInterrupt:
        print(f"\n\n{Colors.WARNING}Workflow interrompu par l'utilisateur{Colors.ENDC}")
        return 130
    except Exception as e:
        print(f"\n{Colors.FAIL}Erreur fatale: {e}{Colors.ENDC}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
