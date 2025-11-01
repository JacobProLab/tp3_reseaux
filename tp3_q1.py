import argparse
import socket
import sys
import logging
from typing import NoReturn
from glocrypto import find_prime, generate_random_integer, modular_exponentiation
from glosocket import send_mesg, recv_mesg

def _parse_args(argv: list[str]) -> tuple[str, int]:

    # init d'un parser pour lire les commandes dans le terminal
    parser = argparse.ArgumentParser("1er serveur en mode ecoute")

    parser.add_argument("-t", "--target-port",
                        dest="port",
                        type=int,
                        action="store",
                        default=11037,
                        help="Choisir un port (Par defaut: 11037)")

    # Option -l et -d ne peuvent etre utilisees en meme tmeps,
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

def _compute_two_keys(modulus: int, base :int) -> tuple[int, int]:

    private_key = generate_random_integer(modulus)
    public_key = modular_exponentiation(base, private_key, modulus)

    return (private_key, public_key)

def _exchange_public_keys(own_pubkey: int, peer: socket.socket) -> int:

    send_mesg(peer, str(own_pubkey))

    return int(recv_mesg(peer))

def _compute_shared_key(private_key: int,public_key: int,modulus: int) -> int:
    return modular_exponentiation(public_key, private_key, modulus)

def _generate_modulus_base(destination: socket.socket) -> tuple[int, int]:
    
    modulus = find_prime()
    base = generate_random_integer(modulus)

    # Transmission de `modulus` et de `base` dans deux messages differents
    send_mesg(destination, str(modulus))
    send_mesg(destination, str(base))

    return (modulus, base)

def _receive_modulus_base(source: socket.socket) -> tuple[int, int]:

    modulus = int(recv_mesg(source))
    base = int(recv_mesg(source))

    return (modulus, base)

def _server(port: int) -> NoReturn:

    # init d'un socket (AF_INET, SOCK_STREAM) = (IPv4, TCP)
    socket_serveur = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket_serveur.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # server laisse la porte <port> de l'immeuble <loopback_ip_address> ouverte (mode 'ecoute')
    loopback_ip_address = "127.0.0.1"
    socket_serveur.bind((loopback_ip_address, port))
    socket_serveur.listen(5)
    print(f"Ecoute sur le port: {port}")

    client_num = 1

    while True:

        # accept() : waiting for an incoming connection
        client_soc, client_addr = socket_serveur.accept()
        print(f"[LISTENING] Server listening to {client_addr}")
        client_num += 1

        # MOT DE BIENVENUE (*temporary: to remove*)
        GREETING = "Bienvenue sur le serveur, quel est votre nom?"
        send_mesg(client_soc, GREETING)
        client_reply = recv_mesg(client_soc)
        print("Reponse: " + client_reply)

        # PROTOCOLE D'ECHANGE
        modulus, base = _generate_modulus_base(client_soc) # `serveur` genere le modulus et la base, et l'envoye a `client`
        private_key, public_key = _compute_two_keys(modulus, base) # `serveur` calcule sa cle privee et publique
        peer_pubkey = _exchange_public_keys(public_key, client_soc) # echange des cles publiques
        shared_key = _compute_shared_key(private_key, peer_pubkey, modulus) # `serveur` calcule sa cle partagee (sans la transmettre via le reseau)

        # Afficher la cle partagee dans le terminal ici
        print(f"Cle partagee : {shared_key}")

        client_soc.close()

def _client(destination: str, port: int) -> None:

    # init d'un socket en mode IPv4 (AF_INET), TCP (SOCK_STREAM)
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # client se connecte au serveur (qui etait en mode 'ecoute')
    address = (destination, port)
    soc.connect(address)

    connected = True
    while connected:

        # MOT DE BIENVENUE (*temporary: to remove*)
        message = recv_mesg(soc)
        print(message)
        reponse = input()
        send_mesg(soc, reponse)

        # PROTOCOLE D'ECHANGE
        modulus, base = _receive_modulus_base(soc) # `client` recoit le modulus et la base, genere par `serveur`
        private_key, public_key = _compute_two_keys(modulus, base) # `client` calcul sa cle privee et publique
        peer_pubkey = _exchange_public_keys(public_key, soc) # echange des cles publiques
        shared_key = _compute_shared_key(private_key, peer_pubkey, modulus) # `client` calcule sa cle partagee (sans la transmettre via le reseau)

        # Afficher la cle partagee dans le terminal ici
        print(f"Cle partagee : {shared_key}")

        soc.close()

def _main() -> int:
    destination, port = _parse_args(sys.argv[1:])
    if destination:
        _client(destination, port)
    else:
        _server(port)
    return 0

if __name__ == '__main__':
    sys.exit(_main())
