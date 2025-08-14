import requests
import json

def talk_with_ai(question):
    url = f"https://princeaiapi.vercel.app/prince/api/v1/ask?key=prince&ask={question}"
    res = requests.get(url)
    if res.status_code == 200:
        data = res.json()
        msg = data["message"]["content"]
        return msg
    else:
        return "Something went wrong."

import requests

def send_likes(uid):
    try:
        # Make the API request
        url = f"https://narayan-like-api-wine.vercel.app/{uid}/ind/narayan200"
        response = requests.get(url)

        # Handle request failure
        if response.status_code != 200:
            return "[fd8da3] Like request failed. Please check your UID or try again later."

        data = response.json()

        # Check if daily limit is reached
        if data.get('status') == 2:
            return f"""
You have reached your daily limit of likes.
Try again in 24 hours.
"""

        # Handle other errors
        if data.get('status') != 1:
            return "Something went wrong with the like operation."

        # If successful
        player_name = data.get('PlayerNickname', 'Unknown')
        likes_before = data.get('LikesbeforeCommand', 0)
        likes_after = data.get('LikesafterCommand', 0)
        likes_added = likes_after - likes_before

        return f"""
[00FF00]Likes Sent Successfully!

[FFFFFF]Player Name : [00FF00]{player_name}  
[FFFFFF]Likes Added : [00FF00]{likes_added}  
[FFFFFF]Likes Before : [00FF00]{likes_before}  
[FFFFFF]Likes After : [00FF00]{likes_after}  
[C][B][11EAFD]‎━━━━━━━━━━━━
[C][B][FFB300]Credits: [FFFFFF]NARAYAN [00FF00]VERMA!!
"""

    except Exception as e:
        return f"⚠️ An error occurred: {str(e)}"


def check_banned_status(player_id):
    url = f"https://syncstatus.vercel.app/check?uid={player_id}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            return data  
        else:
            return {"error": f"Failed to fetch data. Status code: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}
