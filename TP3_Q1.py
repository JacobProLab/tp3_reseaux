"""\
GLO-2000 Travail pratique 3 2024
"""

import argparse
import socket
import sys
from typing import NoReturn

import glosocket
import glocrypto

def _parse_args(argv: list[str]) -> tuple[str, int]:
    """
    Utilise `argparse` pour récupérer les arguments contenus dans argv.

    Retourne un tuple contenant:
    - l'adresse IP du serveur (vide en mode serveur).
    - le port.
    """
    # init d'un parser pour lire les commandes dans le terminal
    parser = argparse.ArgumentParser("Programme d'échange de clés cryptées entre serveur-client avec TCP")

    parser.add_argument("-t", "--target-port",
                        dest="port",
                        type=int,
                        action="store",
                        required=True,
                        help="Choisir un numero de port.")

    # Option -l et -d ne peuvent etre utilisees en meme temps,
    # cependant au moins une doit etre utilisee
    group = parser.add_mutually_exclusive_group(required=True) 
    group.add_argument("-l", "--listen",
                        dest="listen",
                        action="store_true",
                        help="Initialise la communication en mode 'serveur'")
    group.add_argument('-d', "--destination",
                        dest="destination",
                        action="store",
                        help="Indiquer l'adresse IP de l'hote")

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
    other_pubkey = int(glosocket.recv_mesg(peer))

    return other_pubkey


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

    # server laisse la porte <port> de l'immeuble <addr> ouverte (mode 'ecoute')
    try:
        server_soc.bind(("127.0.0.1", port))
    except OSError:
        sys.exit(-1)
    
    server_soc.listen()

    while True:

        # accept() : waiting for an incoming connection
        client_soc, _ = server_soc.accept()

        try:

            # PROTOCOLE D'ECHANGE
            modulus, base = _generate_modulus_base(client_soc)
            private_key, public_key = _compute_two_keys(modulus, base)
            other_pubkey = _exchange_public_keys(public_key, client_soc)
            shared_key = _compute_shared_key(private_key, other_pubkey, modulus)
        
        except (glosocket.GLOSocketError, ValueError):
            client_soc.close()

        else:
            print(f"Cle partagee: {shared_key}")
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
    except OSError:
        sys.exit(-1)

    try:

        # PROTOCOLE D'ECHANGE
        modulus, base = _receive_modulus_base(soc)
        private_key, public_key = _compute_two_keys(modulus, base)
        peer_pubkey = _exchange_public_keys(public_key, soc)
        shared_key = _compute_shared_key(private_key, peer_pubkey, modulus)

    except (glosocket.GLOSocketError, ValueError):
        sys.exit(-1)

    else:
        print(f"Cle partagee : {shared_key}")

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
