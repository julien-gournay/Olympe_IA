#!/usr/bin/env python3
# -*- coding: utf-8 -*-
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
        # Si la configuration échoue, les caractères ASCII seront utilisés
        pass

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
    
    def __init__(
        self,
        network_interface="Wi-Fi",
        duration_minutes=15,
        cv_folds=5,
        enable_tuning=True,
        enable_group_split=True,
        use_flow_dataset=False,
        auto_open_validation_ui=False,
        prompt_validation_ui=True,
        active_model_name="threat_detector",
        enable_model_comparison=True,
        auto_promote=False,
    ):
        self.root_dir = Path(__file__).parent
        self.zeus_dir = self.root_dir / "zeus"
        self.ml_dir = self.root_dir / "ml"
        self.interface = network_interface
        self.duration_minutes = duration_minutes
        self.cv_folds = max(2, int(cv_folds))
        self.enable_tuning = bool(enable_tuning)
        self.enable_group_split = bool(enable_group_split)
        self.use_flow_dataset = bool(use_flow_dataset)
        self.auto_open_validation_ui = bool(auto_open_validation_ui)
        self.prompt_validation_ui = bool(prompt_validation_ui)
        self.active_model_name = active_model_name
        self.enable_model_comparison = bool(enable_model_comparison)
        self.auto_promote = bool(auto_promote)
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.pcap_file = "training_ai.pcap"
        self.db_path = self.zeus_dir / "pcap_database.db"
        self.use_existing_capture = False

    def open_manual_validation_ui(self):
        """Lance l'interface de validation manuelle des alertes."""
        self.print_info("Ouverture de l'interface de validation manuelle...")

        cmd = [
            sys.executable,
            "manual_validation_ui.py",
            "--db", str(self.db_path),
        ]

        success, _ = self.run_command(
            cmd,
            cwd=self.ml_dir,
            timeout=None,
            progress_msg="Validation manuelle",
        )

        if success:
            self.print_success("Interface de validation manuelle fermee")
            return True

        self.print_warning("Impossible d'ouvrir l'interface de validation manuelle")
        return False
        
    def print_step(self, step_num, total_steps, message):
        """Affiche un message de progression"""
        print(f"\n{Colors.HEADER}{'='*70}{Colors.ENDC}")
        print(f"{Colors.BOLD}Étape {step_num}/{total_steps}: {message}{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*70}{Colors.ENDC}\n")
    
    def print_success(self, message):
        """Affiche un message de succès"""
        print(f"{Colors.OKGREEN}[OK] {message}{Colors.ENDC}")
    
    def print_error(self, message):
        """Affiche un message d'erreur"""
        print(f"{Colors.FAIL}[X] {message}{Colors.ENDC}")
    
    def print_info(self, message):
        """Affiche un message d'information"""
        print(f"{Colors.OKCYAN}[i] {message}{Colors.ENDC}")
    
    def print_warning(self, message):
        """Affiche un message d'avertissement"""
        print(f"{Colors.WARNING}[!] {message}{Colors.ENDC}")
    
    def _get_next_zeus_version(self) -> str:
        """Détermine le prochain numéro de version Zeus pour le modèle"""
        model_dir = self.ml_dir / "models"
        model_dir.mkdir(parents=True, exist_ok=True)
        
        # Trouver tous les fichiers de modèles Zeus existants
        existing_models = list(model_dir.glob("Zeus*.pkl"))
        
        if not existing_models:
            return "Zeus1"
        
        # Extraire les numéros de version
        versions = []
        for model_file in existing_models:
            model_name = model_file.stem  # Ex: "Zeus1", "Zeus2"
            try:
                version_str = model_name.replace("Zeus", "")
                version_num = int(version_str)
                versions.append(version_num)
            except ValueError:
                continue
        
        if versions:
            next_version = max(versions) + 1
        else:
            next_version = 1
        
        return f"Zeus{next_version}"
    
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
    
    def check_existing_capture(self):
        """Vérifie si une capture existe déjà et demande à l'utilisateur quoi faire"""
        capture_path = self.zeus_dir / "captures" / self.pcap_file
        
        if not capture_path.exists():
            return True  # Pas de fichier existant, on continue normalement
        
        size_mb = capture_path.stat().st_size / (1024 * 1024)
        mod_time = datetime.fromtimestamp(capture_path.stat().st_mtime)
        
        print(f"\n{Colors.WARNING}{'='*70}{Colors.ENDC}")
        print(f"{Colors.BOLD}[!] Capture existante détectée!{Colors.ENDC}")
        print(f"  Fichier: {self.pcap_file}")
        print(f"  Taille: {size_mb:.2f} MB")
        print(f"  Date de modification: {mod_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{Colors.WARNING}{'='*70}{Colors.ENDC}\n")
        
        print(f"{Colors.OKCYAN}Que voulez-vous faire?{Colors.ENDC}")
        print(f"  1. {Colors.OKGREEN}Utiliser la capture existante{Colors.ENDC} (sauter l'étape de capture)")
        print(f"  2. {Colors.WARNING}Supprimer et créer une nouvelle capture{Colors.ENDC}")
        print(f"  3. {Colors.FAIL}Annuler{Colors.ENDC}\n")
        
        while True:
            try:
                choice = input(f"{Colors.OKCYAN}Votre choix [1/2/3]: {Colors.ENDC}").strip()
                
                if choice == '1':
                    self.print_success("Utilisation de la capture existante")
                    self.use_existing_capture = True
                    return True
                elif choice == '2':
                    self.print_warning("Suppression de la capture existante...")
                    capture_path.unlink()
                    self.print_success("Capture supprimée")
                    return True
                elif choice == '3':
                    self.print_info("Workflow annulé par l'utilisateur")
                    return False
                else:
                    print(f"{Colors.FAIL}Choix invalide. Veuillez entrer 1, 2 ou 3.{Colors.ENDC}")
            except (KeyboardInterrupt, EOFError):
                print(f"\n{Colors.WARNING}Workflow annulé{Colors.ENDC}")
                return False
    
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
                if process.stdout is None:
                    break
                line = process.stdout.readline()
                if not line and process.poll() is not None:
                    break
                
                if line:
                    line = line.strip()
                    output_lines.append(line)
                    
                    # Essayer d'extraire le nombre de paquets de la ligne
                    # Rechercher des patterns spécifiques indiquant la progression réelle
                    # Patterns acceptés: "Captured: 1234", "Paquets capturés: 1234", "Progress: 1234/10000"
                    packet_match = re.search(r'(?:captured|capturés?|progress)[\s:]+(\d+)', line.lower())
                    if packet_match:
                        new_count = int(packet_match.group(1))
                        # Ne mettre à jour que si c'est inférieur au target (évite de capturer le nombre cible)
                        if new_count <= packet_target:
                            packets_captured = new_count
                
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
        """Étape 1: Capturer le trafic réseau (5 000 paquets)"""
        capture_path = self.zeus_dir / "captures" / self.pcap_file
        
        # Si on utilise une capture existante, on saute cette étape
        if self.use_existing_capture:
            self.print_step(1, 5, f"Utilisation de la capture existante")
            size_mb = capture_path.stat().st_size / (1024 * 1024)
            self.print_success(f"Fichier existant utilisé: {self.pcap_file} ({size_mb:.2f} MB)")
            return True
        
        self.print_step(1, 5, f"Capture du trafic réseau (5 000 paquets)")
        
        # Créer le dossier captures s'il n'existe pas
        capture_path.parent.mkdir(parents=True, exist_ok=True)
        
        self.print_info(f"Interface réseau: {self.interface}")
        self.print_info(f"Nombre de paquets: 5 000")
        self.print_info(f"Fichier de sortie: {self.pcap_file}")
        
        self.print_warning(f"La capture va démarrer. Générez du trafic réseau pour améliorer l'entraînement.")
        
        start_time = time.time()
        
        # Commande de capture directe
        cmd = [
            sys.executable,
            "capture_reseau.py",
            "-i", self.interface,
            "-c", "5000",
            "-o", "captures",
            "-n", self.pcap_file
        ]
        
        success, output = self.run_capture_command(
            cmd, 
            cwd=self.zeus_dir, 
            timeout=None,
            packet_target=5000
        )
        
        if not success:
            self.print_error(f"Échec de la capture")
            return False
        
        # Vérifier le fichier capturé
        if capture_path.exists() and capture_path.is_file():
            size_mb = capture_path.stat().st_size / (1024 * 1024)
            elapsed_total = time.time() - start_time
            self.print_success(f"Capture terminée! Fichier: {self.pcap_file} ({size_mb:.2f} MB)")
            self.print_success(f"Paquets capturés: 5 000")
            self.print_success(f"Durée: {int(elapsed_total // 60)}m {int(elapsed_total % 60)}s")
            return True
        else:
            self.print_error(f"Le fichier de capture n'a pas été créé correctement: {capture_path}")
            return False
    
    def step2_ingest_pcap(self):
        """Étape 2: Ingérer et analyser le PCAP avec YARA"""
        self.print_step(2, 5, "Ingestion et analyse du PCAP avec règles YARA")
        
        # Utiliser le chemin complet du fichier PCAP
        capture_path = self.zeus_dir / "captures" / self.pcap_file
        
        cmd = [
            sys.executable,
            "ingestion_pcap.py",
            "-f", str(capture_path),
            "--enable-yara"
        ]
        
        success, output = self.run_command(
            cmd, 
            cwd=self.zeus_dir, 
            timeout=None,
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

        dataset_mode = "flow" if self.use_flow_dataset else "packet"
        
        cmd = [
            sys.executable,
            "trainer.py",
            "--build-dataset",
            "--db", str(self.db_path),
            "--dataset-mode", dataset_mode,
        ]
        
        success, output = self.run_command(
            cmd, 
            cwd=self.ml_dir, 
            timeout=None,
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
        
        # Utiliser le versionnement Zeus automatique
        model_name = self._get_next_zeus_version()
        
        dataset_mode = "flow" if self.use_flow_dataset else "packet"

        cmd = [
            sys.executable,
            "trainer.py",
            "--train",
            "--model-type", "random_forest",
            "--model-name", model_name,
            "--db", str(self.db_path),
            "--cv-folds", str(self.cv_folds),
            "--dataset-mode", dataset_mode,
        ]

        if self.enable_tuning:
            cmd.append("--tune-hyperparams")
        if not self.enable_group_split:
            cmd.append("--no-group-split")
        
        self.print_info(f"Nom du modèle: {model_name}")
        self.print_info(f"Mode dataset: {dataset_mode}")
        self.print_info(f"Validation croisée: {self.cv_folds} folds")
        self.print_info(f"Recherche d'hyperparamètres: {'activée' if self.enable_tuning else 'désactivée'}")
        self.print_info(f"Split anti-fuite par PCAP: {'activé' if self.enable_group_split else 'désactivé'}")
        
        success, output = self.run_command(
            cmd, 
            cwd=self.ml_dir, 
            timeout=None,
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
            timeout=None,
            progress_msg="Test du modèle"
        )
        
        if success:
            self.print_success("Test du modèle terminé")
            return True
        else:
            self.print_warning("Le test du modèle a échoué (cela peut être normal)")
            return True  # On ne bloque pas le workflow

    def step6_evaluate_model(self, model_name):
        """Étape 6: Évaluer le modèle entraîné sur le dataset courant."""
        self.print_step(6, 7, "Évaluation du modèle entraîné")

        dataset_mode = "flow" if self.use_flow_dataset else "packet"
        cmd = [
            sys.executable,
            "trainer.py",
            "--evaluate",
            "--model-type", "random_forest",
            "--model-name", model_name,
            "--db", str(self.db_path),
            "--dataset-mode", dataset_mode,
        ]

        success, output = self.run_command(
            cmd,
            cwd=self.ml_dir,
            timeout=None,
            progress_msg="Évaluation du modèle",
        )

        if success:
            self.print_success(f"Évaluation terminée pour {model_name}")
            if output:
                print(f"\n{Colors.OKGREEN}{output}{Colors.ENDC}")
            return True

        self.print_warning("L'évaluation du modèle a échoué")
        return True  # Workflow non bloquant

    def step7_compare_and_promote(self, model_name):
        """Étape 7: Comparer au modèle actif et éventuellement promouvoir."""
        self.print_step(7, 7, "Comparaison au modèle actif et promotion")

        active_model_file = self.ml_dir / "models" / f"{self.active_model_name}.pkl"
        if not active_model_file.exists():
            self.print_warning(
                f"Aucun modèle actif trouvé ({self.active_model_name}). "
                "Comparaison ignorée pour ce run."
            )
            return True

        dataset_mode = "flow" if self.use_flow_dataset else "packet"
        cmd = [
            sys.executable,
            "trainer.py",
            "--compare",
            "--model-type", "random_forest",
            "--model-name", self.active_model_name,
            "--candidate-model-name", model_name,
            "--db", str(self.db_path),
            "--dataset-mode", dataset_mode,
            "--active-model-name", self.active_model_name,
        ]

        if self.auto_promote:
            cmd.append("--promote-if-better")

        success, output = self.run_command(
            cmd,
            cwd=self.ml_dir,
            timeout=None,
            progress_msg="Comparaison des modèles",
        )

        if success:
            self.print_success("Comparaison des modèles terminée")
            if output:
                print(f"\n{Colors.OKBLUE}{output}{Colors.ENDC}")
            return True

        self.print_warning("La comparaison des modèles a échoué")
        return True  # Workflow non bloquant
    
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
        self.print_info(f"Mode dataset: {'flow' if self.use_flow_dataset else 'packet'}")
        self.print_info(f"CV folds (entraînement): {self.cv_folds}")
        self.print_info(f"Tuning hyperparamètres: {'oui' if self.enable_tuning else 'non'}")
        self.print_info(f"Split anti-fuite PCAP: {'oui' if self.enable_group_split else 'non'}")
        self.print_info(f"Modèle actif cible: {self.active_model_name}")
        self.print_info(f"Comparaison modèle actif: {'oui' if self.enable_model_comparison else 'non'}")
        self.print_info(f"Promotion automatique: {'oui' if self.auto_promote else 'non'}")
        
        start_time = time.time()
        
        # Vérifier si une capture existe déjà et demander à l'utilisateur
        if not self.check_existing_capture():
            return False
        
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
            self.step6_evaluate_model(model_name)
            if self.enable_model_comparison:
                self.step7_compare_and_promote(model_name)
        
        # Résumé final
        elapsed_time = time.time() - start_time
        minutes = int(elapsed_time // 60)
        seconds = int(elapsed_time % 60)
        
        print(f"\n{Colors.BOLD}{Colors.OKGREEN}")
        print("╭──────────────────────────────────────────────────────────────────────╮")
        print("│              [OK] WORKFLOW TERMINÉ AVEC SUCCÈS [OK]                  │")
        print("╰──────────────────────────────────────────────────────────────────────╯")
        print(f"{Colors.ENDC}")
        
        self.print_success(f"Temps total d'exécution: {minutes}m {seconds}s")
        
        # Afficher les détails du fichier PCAP
        capture_path = self.zeus_dir / "captures" / self.pcap_file
        if capture_path.exists() and capture_path.is_file():
            size_mb = capture_path.stat().st_size / (1024 * 1024)
            self.print_success(f"Fichier PCAP: {self.pcap_file} ({size_mb:.2f} MB)")
            self.print_success(f"Emplacement: {capture_path}")
        
        if model_name:
            self.print_success(f"Modèle entraîné: {model_name}")
            model_path = self.ml_dir / "models" / f"{model_name}.pkl"
            report_path = self.ml_dir / "models" / f"{model_name}_report.txt"
            if model_path.exists():
                model_size_kb = model_path.stat().st_size / 1024
                self.print_success(f"Emplacement modèle: {model_path} ({model_size_kb:.2f} KB)")
            if report_path.exists():
                report_size_kb = report_path.stat().st_size / 1024
                self.print_success(f"Rapport détaillé: {report_path} ({report_size_kb:.2f} KB)")
        
        print(f"\n{Colors.OKCYAN}Prochaines étapes:{Colors.ENDC}")
        print(f"  1. Tester le modèle: cd ml && python ml_detector.py -f ../zeus/{self.pcap_file} --model models/{model_name}")
        print(f"  2. Évaluer le modèle: cd ml && python trainer.py --evaluate --model-type random_forest --model-name {model_name} --db ../zeus/pcap_database.db --dataset-mode {'flow' if self.use_flow_dataset else 'packet'}")
        print(f"  3. Comparer au modèle actif: cd ml && python trainer.py --compare --model-type random_forest --model-name {self.active_model_name} --candidate-model-name {model_name} --db ../zeus/pcap_database.db --dataset-mode {'flow' if self.use_flow_dataset else 'packet'}")
        print(f"  4. Utiliser l'analyse hybride: cd ml && python hybrid_analyzer.py -f ../zeus/{self.pcap_file}")
        print(f"  5. Améliorer avec feedback: Voir ml/QUICKSTART.md section 'Cas 2: Amélioration Continue'")

        if self.auto_open_validation_ui:
            self.open_manual_validation_ui()
        elif self.prompt_validation_ui:
            try:
                response = input(
                    f"\n{Colors.OKCYAN}Ouvrir l'interface de validation manuelle maintenant ? [o/N]: {Colors.ENDC}"
                ).strip().lower()
                if response in ['o', 'oui', 'y', 'yes']:
                    self.open_manual_validation_ui()
            except (KeyboardInterrupt, EOFError):
                print(f"\n{Colors.WARNING}Ouverture de l'interface ignoree{Colors.ENDC}")
        
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

    parser.add_argument(
        "--cv-folds",
        type=int,
        default=5,
        help="Nombre de folds pour la validation croisée ML (défaut: 5)"
    )

    parser.add_argument(
        "--disable-tuning",
        action="store_true",
        help="Désactiver la recherche d'hyperparamètres pendant l'entraînement"
    )

    parser.add_argument(
        "--disable-group-split",
        action="store_true",
        help="Désactiver le split anti-fuite par fichier PCAP"
    )

    parser.add_argument(
        "--use-flow-dataset",
        action="store_true",
        help="Utiliser le dataset par flux au lieu du dataset par paquet"
    )

    parser.add_argument(
        "--open-validation-ui",
        action="store_true",
        help="Ouvrir automatiquement l'interface de validation manuelle en fin de workflow"
    )

    parser.add_argument(
        "--no-validation-ui-prompt",
        action="store_true",
        help="Ne pas demander d'ouvrir l'interface de validation manuelle en fin de workflow"
    )

    parser.add_argument(
        "--active-model-name",
        default="threat_detector",
        help="Nom du modèle actif utilisé comme baseline pour la comparaison (défaut: threat_detector)"
    )

    parser.add_argument(
        "--disable-model-comparison",
        action="store_true",
        help="Désactiver la comparaison du nouveau modèle avec le modèle actif"
    )

    parser.add_argument(
        "--auto-promote",
        action="store_true",
        help="Promouvoir automatiquement le nouveau modèle s'il est meilleur"
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

    if args.cv_folds < 2:
        print(f"{Colors.FAIL}Erreur: --cv-folds doit être >= 2{Colors.ENDC}")
        return 1
    
    # Lancer le workflow
    workflow = AITrainingWorkflow(
        network_interface=args.interface,
        duration_minutes=args.duration,
        cv_folds=args.cv_folds,
        enable_tuning=not args.disable_tuning,
        enable_group_split=not args.disable_group_split,
        use_flow_dataset=args.use_flow_dataset,
        auto_open_validation_ui=args.open_validation_ui,
        prompt_validation_ui=not args.no_validation_ui_prompt,
        active_model_name=args.active_model_name,
        enable_model_comparison=not args.disable_model_comparison,
        auto_promote=args.auto_promote,
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
