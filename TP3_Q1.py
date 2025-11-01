"""\
GLO-2000 Travail pratique 3 2024
"""

import argparse
import socket
import sys
import logging
from typing import NoReturn

import glosocket
import glocrypto

logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s', level=logging.INFO, filename='logs/TP3.log')
logger = logging.getLogger()

def _parse_args(argv: list[str]) -> tuple[str, int]:
    """
    Utilise `argparse` pour récupérer les arguments contenus dans argv.

    Retourne un tuple contenant:
    - l'adresse IP du serveur (vide en mode serveur).
    - le port.
    """
    # init d'un parser pour lire les commandes dans le terminal
    parser = argparse.ArgumentParser("1er serveur en mode ecoute")

    parser.add_argument("-t", "--target-port",
                        dest="port",
                        type=int,
                        action="store",
                        default=11037,
                        help="Choisir un port (Par defaut: 11037)")

    # Option -l et -d ne peuvent etre utilisees en meme temps,
    # cependant au moins une doit etre utilisee
    group = parser.add_mutually_exclusive_group(required=True) 
    group.add_argument("-l", "--listen",
                        dest="listen",
                        action="store_true",
                        default=False,
                        help="Initialise la communication en mode 'serveur' (Par defaut : Faux)")
    group.add_argument('-d', "--destination",
                        dest="destination",
                        action="store",
                        help="Indiquer l'adresse de l'hote")

    arguments = parser.parse_args(argv)

    # parsed values
    dest = arguments.destination
    port = arguments.port

    return dest if dest else "", port


def _generate_modulus_base(destination: socket.socket) -> tuple[int, int]:
    """
    Cette fonction génère le modulo et la base à l'aide du module `glocrypto`.

    Elle les transmet respectivement dans deux
    messages distincts à la destination.

    Retourne un tuple contenant respectivement:
    - le modulo,
    - la base.
    """
    modulus = glocrypto.find_prime()
    base = glocrypto.generate_random_integer(modulus)

    # Transmission de `modulus` et de `base` dans deux messages differents
    glosocket.send_mesg(destination, str(modulus))
    glosocket.send_mesg(destination, str(base))

    return (modulus, base)

def _receive_modulus_base(source: socket.socket) -> tuple[int, int]:
    """
    Cette fonction reçoit le modulo et la base depuis le socket source.

    Retourne un tuple contenant respectivement:
    - le modulo,
    - la base.
    """
    modulus = int(glosocket.recv_mesg(source))
    base = int(glosocket.recv_mesg(source))

    return (modulus, base)


def _compute_two_keys(modulus: int, base: int) -> tuple[int, int]:
    """
    Génère une clé privée et en déduit une clé publique.

    Retourne un tuple contenant respectivement:
    - la clé privée,
    - la clé publique.
    """
    private_key = glocrypto.generate_random_integer(modulus)
    public_key = glocrypto.modular_exponentiation(base, private_key, modulus)

    return (private_key, public_key)


def _exchange_public_keys(own_pubkey: int, peer: socket.socket) -> int:
    """
    Envoie sa propre clé publique, récupère la
    clé publique de l'autre et la retourne.
    """
    glosocket.send_mesg(peer, str(own_pubkey))

    return int(glosocket.recv_mesg(peer))


def _compute_shared_key(private_key: int,
                        public_key: int,
                        modulus: int) -> int:
    """Calcule et retourne la clé partagée."""
    return glocrypto.modular_exponentiation(public_key, private_key, modulus)


def _server(port: int) -> NoReturn:
    """
    Boucle principale du serveur.

    Prépare son socket, puis gère les clients à l'infini.
    """
    # init d'un socket (AF_INET, SOCK_STREAM) = (IPv4, TCP)
    server_soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # server laisse la porte <port> de l'immeuble <loopback_ip_address> ouverte (mode 'ecoute')
    loopback_ip_address = "127.0.0.1"
    try:
        server_soc.bind((loopback_ip_address, port))
    except OverflowError as err:
        logger.critical(f"Le port {port} est invalide -> {err}")
        sys.exit(-1)
    
    server_soc.listen(5)
    print(f"Ecoute sur le port: {port}")

    client_num = 1

    while True:

        # accept() : waiting for an incoming connection
        client_soc, client_addr = server_soc.accept()
        print(f"[LISTENING] Server listening to {client_addr}")
        print(f"Connexion nr{client_num}")
        client_num += 1

        try:

            # MOT DE BIENVENUE (*temporary: to remove*)
            GREETING = "Bienvenue sur le serveur, quel est votre nom?"
            glosocket.send_mesg(client_soc, GREETING)
            client_reply = glosocket.recv_mesg(client_soc)
            print("Reponse: " + client_reply)

            # PROTOCOLE D'ECHANGE
            modulus, base = _generate_modulus_base(client_soc)
            private_key, public_key = _compute_two_keys(modulus, base)
            peer_pubkey = _exchange_public_keys(public_key, client_soc)
            shared_key = _compute_shared_key(private_key, peer_pubkey, modulus)

            # Afficher la cle partagee dans le terminal ici
            print(f"Cle partagee : {shared_key}")
        
        except glosocket.GLOSocketError:
            client_soc.close()

def _client(destination: str, port: int) -> None:
    """
    Point d'entrée du client.

    Crée et connecte son socket, puis procède aux échanges.
    """
    # init d'un socket en mode IPv4 (AF_INET), TCP (SOCK_STREAM)
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # client se connecte au serveur (qui est en mode 'ecoute')
    address = (destination, port)
    try:
        soc.connect(address)
    except OverflowError as err:
        logger.critical(f"Le port {port} est invalide -> {err}")
        sys.exit(-1)
    except ConnectionRefusedError as err:
        logger.critical(f"L'adresse {destination} est invalide -> {err}")
        sys.exit(-1)

    connected = True
    while connected:

        try:

            # MOT DE BIENVENUE (*temporary: to remove*)
            message = glosocket.recv_mesg(soc)
            print(message)
            reponse = input()
            glosocket.send_mesg(soc, reponse)

            # PROTOCOLE D'ECHANGE
            modulus, base = _receive_modulus_base(soc)
            private_key, public_key = _compute_two_keys(modulus, base)
            peer_pubkey = _exchange_public_keys(public_key, soc)
            shared_key = _compute_shared_key(private_key, peer_pubkey, modulus)

            # Afficher la cle partagee dans le terminal ici
            print(f"Cle partagee : {shared_key}")

            connected = False

        except glosocket.GLOSocketError:
            logger.warning("Le client rencontre une erreur.")
            sys.exit(-1)

    soc.close()

# NE PAS ÉDITER PASSÉ CE POINT
# NE PAS ÉDITER PASSÉ CE POINT
# NE PAS ÉDITER PASSÉ CE POINT
# NE PAS ÉDITER PASSÉ CE POINT

def _main() -> int:
    destination, port = _parse_args(sys.argv[1:])
    if destination:
        _client(destination, port)
    else:
        _server(port)
    return 0


if __name__ == '__main__':
    sys.exit(_main())
