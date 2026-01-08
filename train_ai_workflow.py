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
import threading

try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False

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
    
    def progress_timer(self, stop_event, message="En cours"):
        """Affiche un timer et un spinner pendant l'exécution"""
        spinner = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
        idx = 0
        start_time = time.time()
        
        while not stop_event.is_set():
            elapsed = int(time.time() - start_time)
            mins, secs = divmod(elapsed, 60)
            timer_str = f"{mins:02d}:{secs:02d}"
            
            # Afficher le spinner et le timer
            print(f"\r{Colors.OKCYAN}{spinner[idx]} {message}... [{timer_str}]{Colors.ENDC}", end='', flush=True)
            idx = (idx + 1) % len(spinner)
            time.sleep(0.1)
        
        # Effacer la ligne du spinner
        print("\r" + " " * 80 + "\r", end='', flush=True)
    
    def run_command(self, cmd, cwd=None, timeout=None, progress_msg="Exécution"):
        """Exécute une commande et retourne le résultat avec timer"""
        try:
            self.print_info(f"Commande: {' '.join(cmd)}")
            
            # Démarrer le timer dans un thread séparé
            stop_event = threading.Event()
            timer_thread = threading.Thread(
                target=self.progress_timer,
                args=(stop_event, progress_msg)
            )
            timer_thread.daemon = True
            timer_thread.start()
            
            start_time = time.time()
            
            try:
                result = subprocess.run(
                    cmd,
                    cwd=cwd or self.root_dir,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    check=True
                )
            finally:
                # Arrêter le timer
                stop_event.set()
                timer_thread.join(timeout=1)
                
                # Afficher le temps écoulé
                elapsed = time.time() - start_time
                mins, secs = divmod(int(elapsed), 60)
                self.print_info(f"Temps d'exécution: {mins}m {secs}s")
            
            if result.stdout:
                print(result.stdout)
            return True, result.stdout
        except subprocess.CalledProcessError as e:
            stop_event.set()
            timer_thread.join(timeout=1)
            self.print_error(f"Erreur lors de l'exécution: {e}")
            if e.stdout:
                print(f"STDOUT: {e.stdout}")
            if e.stderr:
                print(f"STDERR: {e.stderr}")
            return False, e.stderr
        except subprocess.TimeoutExpired:
            stop_event.set()
            timer_thread.join(timeout=1)
            self.print_error(f"Timeout atteint")
            return False, "Timeout"
        except Exception as e:
            stop_event.set()
            timer_thread.join(timeout=1)
            self.print_error(f"Erreur inattendue: {e}")
            return False, str(e)
    
    def run_capture_command(self, cmd, cwd=None, timeout=None, packet_target=10000):
        """Exécute une commande de capture avec affichage en temps réel des paquets"""
        try:
            self.print_info(f"Commande: {' '.join(cmd)}")
            
            start_time = time.time()
            packets_captured = 0
            
            # Lancer le processus sans capturer la sortie
            process = subprocess.Popen(
                cmd,
                cwd=cwd or self.root_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            output_lines = []
            spinner = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
            idx = 0
            
            # Lire la sortie ligne par ligne
            import re
            while True:
                # Vérifier le timeout
                if timeout and (time.time() - start_time) > timeout:
                    process.kill()
                    raise subprocess.TimeoutExpired(cmd, timeout)
                
                if process.stdout is None:
                    break
                line = process.stdout.readline()
                if not line and process.poll() is not None:
                    break
                
                if line:
                    line = line.strip()
                    output_lines.append(line)
                    
                    # Essayer d'extraire le nombre de paquets de la ligne
                    # Rechercher des patterns comme "Captured 1234 packets" ou "1234 packets captured"
                    packet_match = re.search(r'(\d+)\s+(?:packets?|paquets?)', line.lower())
                    if packet_match:
                        packets_captured = int(packet_match.group(1))
                
                # Afficher la progression
                elapsed = int(time.time() - start_time)
                mins, secs = divmod(elapsed, 60)
                timer_str = f"{mins:02d}:{secs:02d}"
                
                # Calculer le pourcentage
                percentage = min(100, int((packets_captured / packet_target) * 100)) if packet_target > 0 else 0
                
                # Barre de progression
                bar_length = 30
                filled_length = int(bar_length * percentage / 100)
                bar = '█' * filled_length + '░' * (bar_length - filled_length)
                
                print(
                    f"\r{Colors.OKCYAN}{spinner[idx]} Capture en cours... "
                    f"[{timer_str}] {bar} {percentage}% "
                    f"({packets_captured:,}/{packet_target:,} paquets){Colors.ENDC}",
                    end='', flush=True
                )
                idx = (idx + 1) % len(spinner)
                time.sleep(0.1)
            
            # Effacer la ligne de progression
            print("\r" + " " * 120 + "\r", end='', flush=True)
            
            # Attendre la fin du processus
            return_code = process.wait()
            
            elapsed = time.time() - start_time
            mins, secs = divmod(int(elapsed), 60)
            self.print_info(f"Temps d'exécution: {mins}m {secs}s")
            
            # Afficher la sortie complète
            full_output = '\n'.join(output_lines)
            if full_output:
                print(full_output)
            
            if return_code == 0:
                return True, full_output
            else:
                raise subprocess.CalledProcessError(return_code, cmd, full_output)
                
        except subprocess.CalledProcessError as e:
            self.print_error(f"Erreur lors de l'exécution: {e}")
            return False, str(e)
        except subprocess.TimeoutExpired:
            self.print_error(f"Timeout atteint")
            return False, "Timeout"
        except Exception as e:
            self.print_error(f"Erreur inattendue: {e}")
            return False, str(e)
    
    def step1_capture_traffic(self):
        """Étape 1: Capturer le trafic réseau avec confirmation toutes les 10 000 paquets"""
        self.print_step(1, 5, f"Capture du trafic réseau (par lots de 10 000 paquets)")
        
        capture_path = self.zeus_dir / "captures" / self.pcap_file
        
        # Créer le dossier captures s'il n'existe pas
        capture_path.parent.mkdir(parents=True, exist_ok=True)
        
        self.print_info(f"Interface réseau: {self.interface}")
        self.print_info(f"Durée maximale: {self.duration_minutes} minutes ({self.duration_minutes * 60} secondes)")
        self.print_info(f"Fichier de sortie: {capture_path}")
        
        self.print_warning(f"La capture va démarrer. Générez du trafic réseau pour améliorer l'entraînement.")
        self.print_info(f"Vous serez invité à continuer ou arrêter toutes les 10 000 paquets")
        
        # Capturer par lots de 10 000 paquets
        packet_batch_size = 10000
        total_packets_captured = 0
        batch_number = 0
        temp_files = []
        
        start_time = time.time()
        max_duration_seconds = self.duration_minutes * 60
        
        while True:
            batch_number += 1
            elapsed_time = time.time() - start_time
            
            # Vérifier si on a dépassé le temps maximum
            if elapsed_time >= max_duration_seconds:
                self.print_warning(f"Durée maximale de {self.duration_minutes} minutes atteinte")
                break
            
            # Nom du fichier temporaire pour ce lot
            temp_pcap = f"temp_batch_{batch_number}_{self.timestamp}.pcap"
            temp_files.append(temp_pcap)
            
            self.print_info(f"\n📦 Lot #{batch_number} - Capture de {packet_batch_size} paquets")
            
            cmd = [
                sys.executable,
                "capture_reseau.py",
                "-i", self.interface,
                "-c", str(packet_batch_size),
                "-o", f"captures/{temp_pcap}"
            ]
            
            # Timeout pour un lot: 5 minutes max
            batch_timeout = 300
            
            success, output = self.run_capture_command(
                cmd, 
                cwd=self.zeus_dir, 
                timeout=batch_timeout,
                packet_target=packet_batch_size
            )
            
            if not success:
                self.print_error(f"Échec de la capture du lot #{batch_number}")
                break
            
            # Vérifier le fichier temporaire
            temp_path = self.zeus_dir / "captures" / temp_pcap
            if temp_path.exists():
                size_mb = temp_path.stat().st_size / (1024 * 1024)
                total_packets_captured += packet_batch_size
                self.print_success(f"Lot #{batch_number} capturé: {size_mb:.2f} MB")
                self.print_info(f"Total de paquets capturés: {total_packets_captured}")
            else:
                self.print_error(f"Le fichier temporaire n'a pas été créé: {temp_pcap}")
                break
            
            # Demander à l'utilisateur s'il veut continuer
            print(f"\n{Colors.WARNING}{'='*70}{Colors.ENDC}")
            print(f"{Colors.BOLD}Continuer la capture?{Colors.ENDC}")
            print(f"  - Paquets capturés: {total_packets_captured}")
            print(f"  - Lots capturés: {batch_number}")
            print(f"  - Temps écoulé: {int(elapsed_time // 60)}m {int(elapsed_time % 60)}s")
            print(f"{Colors.WARNING}{'='*70}{Colors.ENDC}")
            
            try:
                response = input(f"{Colors.OKCYAN}Continuer? [O/n]: {Colors.ENDC}").strip().lower()
                if response in ['n', 'non', 'no']:
                    self.print_info("Arrêt de la capture demandé par l'utilisateur")
                    break
            except (KeyboardInterrupt, EOFError):
                self.print_warning("\nInterruption détectée, arrêt de la capture")
                break
        
        # Fusionner tous les fichiers PCAP temporaires en un seul
        if not temp_files:
            self.print_error("Aucun fichier capturé")
            return False
        
        self.print_info(f"\n📚 Fusion de {len(temp_files)} fichier(s) PCAP...")
        
        if len(temp_files) == 1:
            # Un seul fichier, simplement le renommer
            temp_path = self.zeus_dir / "captures" / temp_files[0]
            temp_path.rename(capture_path)
            self.print_success("Fichier unique renommé")
        else:
            # Plusieurs fichiers, les fusionner avec mergecap (si disponible) ou en Python
            try:
                # Essayer avec mergecap (partie de Wireshark)
                merge_cmd = ["mergecap", "-w", str(capture_path)]
                for temp_file in temp_files:
                    merge_cmd.append(str(self.zeus_dir / "captures" / temp_file))
                
                result = subprocess.run(merge_cmd, capture_output=True, text=True, timeout=300)
                
                if result.returncode == 0:
                    self.print_success("Fichiers fusionnés avec mergecap")
                    # Supprimer les fichiers temporaires
                    for temp_file in temp_files:
                        temp_path = self.zeus_dir / "captures" / temp_file
                        if temp_path.exists():
                            temp_path.unlink()
                else:
                    raise Exception("mergecap non disponible")
            except:
                # Si mergecap n'est pas disponible, simplement renommer le dernier fichier
                # et garder les autres (l'ingestion pourra traiter plusieurs fichiers)
                self.print_warning("mergecap non disponible, utilisation du dernier lot capturé")
                last_temp = self.zeus_dir / "captures" / temp_files[-1]
                last_temp.rename(capture_path)
                self.print_info(f"Note: Les lots précédents sont toujours disponibles dans zeus/captures/")
        
        if capture_path.exists():
            size_mb = capture_path.stat().st_size / (1024 * 1024)
            elapsed_total = time.time() - start_time
            self.print_success(f"Capture terminée! Fichier: {self.pcap_file} ({size_mb:.2f} MB)")
            self.print_success(f"Total de paquets: ~{total_packets_captured}")
            self.print_success(f"Durée totale: {int(elapsed_total // 60)}m {int(elapsed_total % 60)}s")
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
        
        success, output = self.run_command(
            cmd, 
            cwd=self.zeus_dir, 
            timeout=600,
            progress_msg="Ingestion et analyse YARA"
        )
        
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
        
        success, output = self.run_command(
            cmd, 
            cwd=self.ml_dir, 
            timeout=300,
            progress_msg="Construction du dataset ML"
        )
        
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
        
        success, output = self.run_command(
            cmd, 
            cwd=self.ml_dir, 
            timeout=600,
            progress_msg="Entraînement du modèle Random Forest"
        )
        
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
        
        success, output = self.run_command(
            cmd, 
            cwd=self.ml_dir, 
            timeout=300,
            progress_msg="Test du modèle"
        )
        
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
