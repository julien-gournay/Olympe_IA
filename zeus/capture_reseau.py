#!/usr/bin/env python3
"""
Script de capture de trames réseau pour analyse PCAP
Celestis_IA - Module Zeus
"""

import argparse
import datetime
import logging
import os
import signal
import sys
from pathlib import Path

try:
    from scapy.all import sniff, wrpcap, get_if_list, conf
except ImportError:
    print("Erreur: Scapy n'est pas installé. Installez-le avec: pip install scapy")
    sys.exit(1)


class NetworkCapture:
    """Classe pour gérer la capture de trames réseau"""
    
    def __init__(self, interface=None, output_dir="captures", filter_bpf=None):
        """
        Initialise le capteur réseau
        
        Args:
            interface: Interface réseau à capturer (None = toutes)
            output_dir: Répertoire de sortie pour les fichiers PCAP
            filter_bpf: Filtre BPF optionnel (ex: "tcp port 80")
        """
        self.interface = interface
        self.output_dir = Path(output_dir)
        self.filter_bpf = filter_bpf
        self.packets = []
        self.capture_active = False
        
        # Créer le répertoire de sortie si nécessaire
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Configuration du logging
        self._setup_logging()
        
    def _setup_logging(self):
        """Configure le système de logging"""
        log_file = self.output_dir / "capture.log"
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def _packet_callback(self, packet):
        """
        Callback appelé pour chaque paquet capturé
        
        Args:
            packet: Paquet Scapy capturé
        """
        self.packets.append(packet)
        if len(self.packets) % 100 == 0:
            self.logger.info(f"Paquets capturés: {len(self.packets)}")
            
    def _signal_handler(self, signum, frame):
        """Gestionnaire de signal pour arrêt gracieux"""
        self.logger.info("\nArrêt de la capture...")
        self.capture_active = False
        
    def list_interfaces(self):
        """Liste toutes les interfaces réseau disponibles"""
        interfaces = get_if_list()
        self.logger.info("Interfaces réseau disponibles:")
        for i, iface in enumerate(interfaces, 1):
            self.logger.info(f"  {i}. {iface}")
        return interfaces
    
    def choose_interface(self):
        """
        Permet à l'utilisateur de choisir une interface réseau
        
        Returns:
            str: Nom de l'interface choisie ou None pour toutes
        """
        interfaces = get_if_list()
        
        if not interfaces:
            self.logger.error("Aucune interface réseau trouvée")
            return None
        
        print("\n=== Interfaces réseau disponibles ===")
        for i, iface in enumerate(interfaces, 1):
            print(f"  {i}. {iface}")
        print(f"  0. Toutes les interfaces")
        
        while True:
            try:
                choice = input("\nChoisissez le numéro de l'interface à capturer (0 pour toutes): ").strip()
                choice_num = int(choice)
                
                if choice_num == 0:
                    print("Capture sur toutes les interfaces")
                    return None
                elif 1 <= choice_num <= len(interfaces):
                    selected = interfaces[choice_num - 1]
                    print(f"Interface sélectionnée: {selected}")
                    return selected
                else:
                    print(f"Erreur: Choisissez un numéro entre 0 et {len(interfaces)}")
            except ValueError:
                print("Erreur: Entrez un numéro valide")
            except KeyboardInterrupt:
                print("\nAnnulé par l'utilisateur")
                sys.exit(0)
        
    def start_capture(self, count=0, timeout=None, prn_callback=None):
        """
        Démarre la capture de paquets
        
        Args:
            count: Nombre de paquets à capturer (0 = infini)
            timeout: Durée de capture en secondes (None = infini)
            prn_callback: Fonction de callback personnalisée pour chaque paquet
        """
        self.capture_active = True
        self.packets = []  # Réinitialiser la liste des paquets
        
        # Enregistrer le gestionnaire de signal pour Ctrl+C
        signal.signal(signal.SIGINT, self._signal_handler)
        
        try:
            self.logger.info(f"Démarrage de la capture sur l'interface: {self.interface or 'toutes'}")
            if self.filter_bpf:
                self.logger.info(f"Filtre BPF appliqué: {self.filter_bpf}")
            
            # Paramètres de capture
            capture_params = {
                'prn': self._packet_callback,  # Toujours utiliser le callback pour stocker
                'store': False,  # On stocke via le callback
                'iface': self.interface,
                'filter': self.filter_bpf,
                'stop_filter': lambda x: not self.capture_active  # Arrêter si capture_active = False
            }
            
            if count > 0:
                capture_params['count'] = count
                self.logger.info(f"Capture de {count} paquets...")
            else:
                self.logger.info("Capture continue (Ctrl+C pour arrêter)...")
                
            if timeout:
                capture_params['timeout'] = timeout
                self.logger.info(f"Timeout: {timeout} secondes")
            
            # Lancer la capture
            sniff(**capture_params)
                
            self.logger.info(f"Capture terminée. Total de paquets: {len(self.packets)}")
            
        except PermissionError:
            self.logger.error("Erreur: Permissions insuffisantes. Exécutez avec des privilèges administrateur.")
            sys.exit(1)
        except Exception as e:
            self.logger.error(f"Erreur lors de la capture: {e}")
            raise
            
    def save_capture(self, filename=None):
        """
        Sauvegarde les paquets capturés dans un fichier PCAP
        
        Args:
            filename: Nom du fichier (None = génération automatique)
        
        Returns:
            Path: Chemin du fichier sauvegardé
        """
        if not self.packets:
            self.logger.warning(f"Aucun paquet à sauvegarder (total: {len(self.packets)})")
            return None
            
        if filename is None:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"capture_{timestamp}.pcap"
            
        output_file = self.output_dir / filename
        
        try:
            wrpcap(str(output_file), self.packets)
            self.logger.info(f"Capture sauvegardée: {output_file}")
            self.logger.info(f"Nombre de paquets: {len(self.packets)}")
            self.logger.info(f"Taille du fichier: {output_file.stat().st_size / 1024:.2f} KB")
            return output_file
        except Exception as e:
            self.logger.error(f"Erreur lors de la sauvegarde: {e}")
            raise
            
    def get_capture_stats(self):
        """
        Retourne des statistiques sur la capture
        
        Returns:
            dict: Statistiques de capture
        """
        if not self.packets:
            return {}
            
        stats = {
            'total_packets': len(self.packets),
            'protocols': {},
            'src_ips': set(),
            'dst_ips': set(),
        }
        
        for packet in self.packets:
            # Compter les protocoles
            if packet.haslayer('IP'):
                stats['src_ips'].add(packet['IP'].src)
                stats['dst_ips'].add(packet['IP'].dst)
                
            # Protocole de couche transport
            if packet.haslayer('TCP'):
                stats['protocols']['TCP'] = stats['protocols'].get('TCP', 0) + 1
            elif packet.haslayer('UDP'):
                stats['protocols']['UDP'] = stats['protocols'].get('UDP', 0) + 1
            elif packet.haslayer('ICMP'):
                stats['protocols']['ICMP'] = stats['protocols'].get('ICMP', 0) + 1
            else:
                stats['protocols']['OTHER'] = stats['protocols'].get('OTHER', 0) + 1
                
        stats['unique_src_ips'] = len(stats['src_ips'])
        stats['unique_dst_ips'] = len(stats['dst_ips'])
        
        return stats
        
    def print_stats(self):
        """Affiche les statistiques de capture"""
        stats = self.get_capture_stats()
        
        if not stats:
            self.logger.info("Aucune statistique disponible")
            return
            
        self.logger.info("\n=== Statistiques de capture ===")
        self.logger.info(f"Total de paquets: {stats['total_packets']}")
        self.logger.info(f"IPs sources uniques: {stats['unique_src_ips']}")
        self.logger.info(f"IPs destinations uniques: {stats['unique_dst_ips']}")
        self.logger.info("\nProtocoles:")
        for proto, count in stats['protocols'].items():
            percentage = (count / stats['total_packets']) * 100
            self.logger.info(f"  {proto}: {count} ({percentage:.1f}%)")


def main():
    """Fonction principale"""
    parser = argparse.ArgumentParser(
        description="Capture de trames réseau pour analyse PCAP - Celestis_IA",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation:
  # Lister les interfaces
  python capture_reseau.py --list-interfaces
  
  # Capturer 1000 paquets sur l'interface eth0
  python capture_reseau.py -i eth0 -c 1000
  
  # Capturer pendant 60 secondes avec filtre HTTP
  python capture_reseau.py -t 60 -f "tcp port 80"
  
  # Capturer tout le trafic TCP/IP
  python capture_reseau.py -f "ip"
        """
    )
    
    parser.add_argument('-i', '--interface', 
                        help='Interface réseau à capturer (défaut: toutes)')
    parser.add_argument('-o', '--output-dir', 
                        default='captures',
                        help='Répertoire de sortie (défaut: captures)')
    parser.add_argument('-f', '--filter', 
                        help='Filtre BPF (ex: "tcp port 80")')
    parser.add_argument('-c', '--count', 
                        type=int, 
                        default=0,
                        help='Nombre de paquets à capturer (défaut: infini)')
    parser.add_argument('-t', '--timeout', 
                        type=int,
                        help='Durée de capture en secondes')
    parser.add_argument('-n', '--filename',
                        help='Nom du fichier PCAP de sortie')
    parser.add_argument('--list-interfaces', 
                        action='store_true',
                        help='Lister les interfaces disponibles')
    parser.add_argument('--no-stats', 
                        action='store_true',
                        help='Ne pas afficher les statistiques')
    
    args = parser.parse_args()
    
    # Créer le capteur
    capture = NetworkCapture(
        interface=args.interface,
        output_dir=args.output_dir,
        filter_bpf=args.filter
    )
    
    # Lister les interfaces si demandé
    if args.list_interfaces:
        capture.list_interfaces()
        return
    
    # Si aucune interface n'est spécifiée, demander à l'utilisateur
    if args.interface is None:
        selected_interface = capture.choose_interface()
        capture.interface = selected_interface
    
    # Vérifier les permissions sur Windows
    if sys.platform == 'win32':
        try:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                capture.logger.warning("Avertissement: Exécution sans privilèges administrateur.")
                capture.logger.warning("La capture peut ne pas fonctionner correctement.")
        except:
            pass
    
    # Démarrer la capture
    try:
        capture.start_capture(count=args.count, timeout=args.timeout)
        
        # Debug: vérifier le nombre de paquets
        capture.logger.info(f"Paquets capturés avant sauvegarde: {len(capture.packets)}")
        
        # Sauvegarder
        if capture.packets:
            output_file = capture.save_capture(filename=args.filename)
            
            # Afficher les statistiques
            if not args.no_stats and output_file:
                capture.print_stats()
        else:
            capture.logger.warning("Aucun paquet capturé. Vérifiez l'interface et les permissions.")
            
    except KeyboardInterrupt:
        capture.logger.info("\nCapture interrompue par l'utilisateur")
        capture.logger.info(f"Paquets capturés: {len(capture.packets)}")
        if capture.packets:
            output_file = capture.save_capture(filename=args.filename)
            if not args.no_stats and output_file:
                capture.print_stats()
        else:
            capture.logger.warning("Aucun paquet capturé avant l'interruption.")
    except Exception as e:
        capture.logger.error(f"Erreur: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
