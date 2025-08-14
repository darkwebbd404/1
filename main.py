import threading
import jwt
import random
import json
import requests
import socket
import os
import sys
import time
from time import sleep
from google.protobuf.timestamp_pb2 import Timestamp
from google.protobuf.json_format import MessageToJson
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import urllib3

# Import local modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src.packet_builder import *
from src.protobuf.MajorLoginRes_pb2 import MajorLoginRes
from src.protobuf.output_pb2 import Lokesh
from src.core.ff_client import FF_CLIENT
from src.utils.helpers import *
from src.core.game_functions import *

# Disable insecure request warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def load_accounts():
    try:
        with open(os.path.join(os.path.dirname(__file__), 'accs.json'), 'r') as file:
            data = json.load(file)
            return list(data.items())  # Returns list of (id, pass)
    except Exception as e:
        print(f"[!] Error loading accounts: {e}")
        return []


def run_client(id, password):
    print(f"Launching client → ID: {id} | Password: Hidden due to security reasons.")
    try:
        client = FF_CLIENT(id, password)
        client.start()
    except Exception as e:
        print(f"Error starting client for ID {id}: {e}")

def main():
    print("Starting Free Fire Bot...\n")
    sleep(1)

    ids_passwords = load_accounts()
    if not ids_passwords:
        print("⚠️ No accounts found in accs.txt\n")
        return
    sleep(1)

    max_range = 300000
    num_clients = len(ids_passwords)
    num_threads = 1
    start = 0
    end = max_range
    step = (end - start) // num_threads

    threads = []
    for i in range(num_threads):
        ids_for_thread = ids_passwords[i % num_clients]
        id, password = ids_for_thread
        thread = threading.Thread(target=run_client, args=(id, password))
        threads.append(thread)
        sleep(3)
        thread.start()

    for thread in threads:
        thread.join()

def restart_program():
    print("\nRestarting program...")
    python = sys.executable
    os.execl(python, python, *sys.argv)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logging.error(f"Unhandled error occurred: {e}")
        restart_program()
