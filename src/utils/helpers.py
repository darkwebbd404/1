import random
import json
import time
import httpx
import requests
from datetime import datetime
from threading import Thread

# Import local modules
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.packet_builder import *
from src.core.game_functions import *

# Global variables
jwt_token = None

def fix_word(num):
    fixed = ""
    count = 0
    
    for char in num:
        if char:
            count += 1
        fixed += char
        if count == 3:
            fixed += "[c]"
            count = 0  
    return fixed
def rrrrrrrrrrrrrr(number):
    if isinstance(number, str) and '***' in number:
        return number.replace('***', '106')
    return number


def  generate_random_word():
    word_list = [
        "XNXXX", "ZBI", "CODEX TEAM", "NIKMOK",
    "PUSY", "FUCK YOU", "FUCK ANY TEAM", "FUCK YOUR MOM", "PORNO",
    "FUCK YOUR MOTHER", "FUCK YOUR SISTER", "MOROCCO", "KISS YOUR MOM", "YOUR MOM'S PUSSY IS PINK",
    "WAAA DAK W9", "ZAMEL", "YOU ENGRAVER", "KIDS", "YOUR VAGINA IS TWISTED",
    "YOUR PUSSY", "I'LL FUCK YOU", "SIT DOWN, PIMP", "MOANING", "DIMA RAJA",
    "FAILED STREAMERS", "FOXXXX", "GAY", "YOUR MOM IS A GOOSE", "YOUR VOICE IS BEAUTIFUL",
    "HAHAHAHAHAHA", "GOOSE VOICE", "I’LL FUCK YOU", "SWALLOW IT, PIMP", "TOMBOY",
    "DICK", "STRONG PUSSY", "PUSSY", "CHARGE INTO YOUR PUSSY", "LOSER",
    "SLUT", "LITTLE DONKEY", "FUCK YOUR MOM", "YOUR VOICE", "FUCK YOU",
    "FUCK YOUR MOM", "FUCK YOUR MOM", "FUCK YOUR MOM", "I'LL MASTURBATE TO YOU", "ASS LICKER", "FOXXX"
    ]

    return random.choice(word_list)
def generate_random_color():
	color_list = [
    "[00FF00]"
]
	random_color = random.choice(color_list)
	return  random_color
def get_random_avatar():
    avatar_list = [
        '902000061', '902000060', '902000064', '902000065', '902000066', 
        '902000074', '902000075', '902000077', '902000078', '902000084', 
        '902000085', '902000087', '902000091', '902000094', '902000306','902000091','902000208','902000209','902000210','902000211','902047016','902047016','902000347'
    ]
    return random.choice(avatar_list)

def get_jwt_token():
    global jwt_token
    url = "https://jwt-server-ind.vercel.app/token?uid=3939725907&password=MAZID_8FIYV98WWW"
    try:
        response = httpx.get(url)
        if response.status_code == 200:
            data = response.json()
            if data['status'] == 'success':
                jwt_token = data['token']
                print(jwt_token)
            else:
                pass
        else:
            pass
    except httpx.RequestError as e:
        print(f"Request error: {e}")
def token_updater():
    while True:
        get_jwt_token()
        time.sleep(8 * 3600)
token_thread = Thread(target=token_updater, daemon=True)
token_thread.start()
def get_time(uid):
    url = f"http://168.231.113.96:8118/get_time/{uid}"
    res = requests.get(url)
    data = res.json()
    if "error" in data:
        return "time:Expired - Player has been removed"
        remove_result = remove_player(uid)
    else:
        data = res.json()['remaining_time']
        days = data['days']
        hours = data['hours']
        minutes = data['minutes']
        seconds = data['seconds']
        time = f"""
[C][B][11EAFD]‎━━━━━━━━━━━━
[FFFFFF]Days: [FFA500]{days}
[FFFFFF]Hours: [32CD32]{hours}
[FFFFFF]Minutes: [1E90FF]{minutes}
[FFFFFF]Seconds: [FF4500]{seconds}
        """
        return time

def remove_player(player_id):
    url = f"http://168.231.113.96:1882/remove_friend?token={jwt_token}&id={player_id}"
    res = requests.get(url)
    if res.status_code == 200:
        print('Done')
        data = res.json()
        return data
    else:
        print("Error removing player")
        return None
def spam_requests(player_id):
    url = f"https://vercel.app/send_request-dev?uid={player_id}&server=IND&key=MAZIDxBIG-DADDY"
    res = requests.get(url)
    if res.status_code() == 200:
        print("Done-Spam")
    else:
        print("Fuck-Spam")


