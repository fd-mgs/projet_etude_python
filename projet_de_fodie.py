import subprocess
import socket
from scapy.all import * #pip install scapy
import keyboard #pip install keyboard
import argparse
import git #pip install gitpython
import os
import requests
import shodan #pip install shodan

def main_menu():
    print("1. Nmap Scan")
    print("2. NexFil")
    print("3. Hunter")
    print("4. Shodan")
    print("5. Exit")

    choice = input("Enter your choice: ")

    if choice == "1":
        print("\n1. Nmap Scan")
        nmap_scan()
    elif choice == "2":
        print("\n2. NexFil")
        nexfil()
    elif choice == "3":
        print("\n3. Hunter")
        hunter()
    elif choice == "4":
        print("\n4. Shodan")
        scan_shodan()
    elif choice == "5":
        print("\n5. Exit")
        exit()
    else:
        print("Veuillez contacter le service Mr Magassa au numéro suivant : \n")
        main_menu()

def nmap_scan():
    # Demande à l'utilisateur d'entrer l'adresse IP de la cible
    target = input("Entrez l'adresse IP cible : ")
    print("Scan en cours de", target)

    # Initialise une variable pour stocker le port ouvert trouvé
    open_port = None

    # Parcourt chaque port de 1 à 1000
    for port in range(1, 1000):
        # Si un port ouvert a déjà été trouvé, arrête la recherche de ports
        if open_port:
            break
        
        # Crée un socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Définit un temps limite de connexion
        sock.settimeout(0.1)
        # Tente de se connecter au port de la cible
        result = sock.connect_ex((target, port))
        # Si la connexion est réussie
        if result == 0:
            # Trouve le nom du service correspondant au port
            service = socket.getservbyport(port, 'tcp')
            # Affiche que le port est ouvert et son nom de service
            print(f"Le port {port} est ouvert , nom du service : {service}\n")
            # Stocke le port ouvert trouvé dans la variable
            open_port = port
            try:
                with open("resultat_code.txt","a") as f:
                    f.write(f"ip : {str(target)} , port : {str(port)} , service : {service}\n")
                    print(f"port {port} enregistré dans le fichier")
                f.close()
            except Exception as e:
                print(f"erreur : {e}")
        else:
            print(f"result = {str(result)}\nport = {str(port)}\nTentative de connection au port de la cible échoué\n")
        # Ferme la connexion
        sock.close()

    # Si un port ouvert a été trouvé, affiche un message avec le numéro de port
    if open_port:
        print(f"Port ouvert trouvé : {open_port}")
    # Sinon, affiche un message indiquant que tous les ports sont fermés
    else:
        print("Tous les ports sont fermés")
        
def nexfil():
    # Analyser les arguments en ligne de commande
    parser = argparse.ArgumentParser(description="Find profiles by username on the web")
    parser.add_argument("-u", "--username", help="Username to search for.")
    parser.add_argument("-l", "--userlist", help="Comma-separated list of usernames to search for.")
    parser.add_argument("-f", "--file", help="File containing a list of usernames to search for.")
    args = parser.parse_args()

    # Vérifier si le dépôt a déjà été cloné
    if os.path.isdir("nexfil/.git"):
        repo = git.Repo("nexfil")
    else:
        # Cloner le dépôt en mémoire
        repo = git.Repo.clone_from("https://github.com/thewhiteh4t/nexfil.git", "nexfil", branch='main')

    os.chdir("nexfil")

    # Installer les dépendances requises
    os.system("pip install -r requirements.txt")

    # Demander à l'utilisateur de saisir l'argument
    print("\nPlease provide one of the following:")
    print("* Username [-u]")
    print("* Comma separated usernames [-l]")
    print("* File containing list of usernames [-f]")

    arg = input("Enter argument: ")

    # Exécuter la commande avec l'argument fourni
    if arg == "-u":
        username = input("Enter username: ")
        os.system(f"python nexfil.py -u {username}")
    elif arg == "-l":
        userlist = input("Enter comma-separated list of usernames: ")
        os.system(f"python nexfil.py -l {userlist}")
    elif arg == "-f":
        filename = input("Enter file name: ")
        os.system(f"python nexfil.py -f {filename}")
    else:
        print("Invalid argument. Please enter one of the following: -u, -l, -f")

def scan_shodan():
    # Initialize the Shodan API object with your API key
    SHODAN_API_KEY = "ncUcft5EwlkQnnTVcqKKhyywTQv96Iv3" #pour l'utiliser il faut avoir un compte payant sinon ca renvoie une erreur
    api = shodan.Shodan(SHODAN_API_KEY)

    # Get information about a specific device using its IP address
    ip = "74.208.229.191"
    info = api.host(ip)

    # Print the information
    print(f"IP: {info['ip_str']}")
    print(f"Hostnames: {', '.join(info.get('hostnames', []))}")
    print(f"Operating system: {info.get('os', 'Unknown')}")
    print(f"Open ports: {', '.join(str(p) for p in info['ports'])}")

    

def hunter():
    api_key = "18630aa4aeab8782aca6a60ec8c34debea039588"
    domain = "cyna"

    url = f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key={api_key}"

    response = requests.get(url)

    if response.status_code == 200:
        data = response.json()
        #print(data)
        if 'emails' in data['data']:
            #print(f'len(data["data"]["emails"]) = {len(data["data"]["emails"])}')
            if len(data['data']['emails']) != 0:
                emails = data['data']['emails']
                for email in emails:
                    print(email['value'])
            else:
                print(f"Aucun email pour {domain}")
    else:
        print(f"Error: {response.status_code}")
    #c'est une autre partie de hunter 

    

if __name__ == "__main__":
    main_menu()
