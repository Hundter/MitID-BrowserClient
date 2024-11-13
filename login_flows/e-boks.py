# Script for https://private.e-boks.com/danmark/da/
import json, base64, re, requests, sys, random
from urllib.parse import urlparse, parse_qs, unquote
from bs4 import BeautifulSoup
sys.path.append("..")
from BrowserClient.Helpers import get_authentication_code, process_args, generate_nem_login_parameters, get_default_args

aux_in_js_regex = re.compile(r"\$\(function\(\)\{initiateMitId\((\{.*\})\)\}\);")

argparser = get_default_args()
args = argparser.parse_args()

method, user_id, password, proxy, queueit = process_args(args)
session = requests.Session()
if proxy:
    session.proxies.update({"http": f"socks5://{proxy}", "https": f"socks5://{proxy}" })

# First part of eboks procedure
nem_login_state, nem_login_nonce, nem_login_code_verifier, nem_login_code_challenge = generate_nem_login_parameters()

params = {
    "response_type": "code",
    "client_id": "e-boks-web",
    "redirect_uri": "https://digitalpost.e-boks.dk",
    "scope": "openid",
    "state": nem_login_state,
    "nonce": nem_login_nonce,
    "code_challenge": nem_login_code_challenge,
    "code_challenge_method": "S256",
    "idp": "nemloginEboksRealm"
}

# Possibly you are going to need a QueueIT cookie.
# Log on to e-boks in your browser with developer tools enabled to get this cookie
# and uncomment the next line
#session.cookies.update({"QueueITAccepted-SDFrts345E-V3_prod01": "ENTER VALUE FROM BROWSER HERE"})

request = session.get("https://gateway.digitalpost.dk/auth/oauth/authorize", params=params)

if request.status_code != 200:
    print(f"Failed session setup attempt, status code {request.status_code}")
    raise Exception(request.content)
elif '.queue-it.net/softblock' in request.url and queueit:
    print('Queue-it CAPTCHA challenge detected. Trying to pass...')
    search_string = "decodeURIComponent('"
    start_of_target_url = request.text.index(search_string)+len(search_string)
    end_of_target_url = request.text.index("'", start_of_target_url)
    target_url = unquote(request.text[start_of_target_url:end_of_target_url])
    
    passed_captcha = False
    try_count = 0
    while passed_captcha == False and try_count < 5:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:130.0) Gecko/20100101 Firefox/130.0',
            'Referer': request.url,
            'X-Queueit-Challange-reason': '0',
            'X-Queueit-Challange-CustomerId': 'digitalpost',
            'X-Queueit-Challange-EventId': 'prod01',
            'X-Queueit-Challange-Hash': 'iSoytOXf18UKTxmuzeklxZXwh6nGBz61kVP7dhijAE8=',
            'Origin': 'https://digitalpost.queue-it.net',
        }
        queue_request = session.post("https://digitalpost.queue-it.net/challengeapi/queueitcaptcha/challenge/da-dk", headers=headers)
        queue_request_json = queue_request.json()
        image = queue_request.json()["imageBase64"]
        
        if queueit == 'API':
            # Try API
            # https://github.com/ganhj99/queueit-captcha-handler/tree/master
            capt_json = {"image_data": image}
            capt_request = session.post("https://ocr.ganhj.dev/queueit", json=capt_json)
            solution = capt_request.json()['answer']
        elif queueit == 'OCR':
            # Try OCR
            print("Decoding CAPTCHA using OCR. This may be slow.")
            from paddleocr import PaddleOCR
            ocr = PaddleOCR(lang='en', show_log=False)
            result = ocr.ocr(base64.b64decode(image), det=False, cls=False)
            solution = result[0][0][0].replace(" ","")

        json_queue = {
            "challengeType": "botdetect",
            "sessionId": queue_request_json['sessionId'],
            "challengeDetails": queue_request_json['challengeDetails'],
            "solution": capt_request.json()['answer'],
            "stats": {
                "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0",
                "screen": "1024 x 768",
                "browser": "Firefox",
                "browserVersion": "130.0",
                "isMobile": False,
                "os": "Windows",
                "osVersion": "10",
                "cookiesEnabled": True,
                "tries": 1,
                "duration": random.randint(9000, 15000)
            },
            "customerId": "digitalpost",
            "eventId": "prod01",
            "version": 6
        }    
        verify_request = session.post("https://digitalpost.queue-it.net/challengeapi/verify", json=json_queue)
        verify_request_json = verify_request.json()
        if verify_request_json['isVerified'] == True:
            print("Passed CAPTCHA!")
            # This request should redirect to https://nemlog-in.mitid.dk/login/mitid
            request = session.get(f"https://digitalpost.queue-it.net/?c=digitalpost&e=prod01&t={target_url}&cid=da-DK&scv={json.dumps(verify_request_json['sessionInfo'])}")
            breakpoint()
            if request.url == "https://nemlog-in.mitid.dk/login/mitid":
                passed_captcha = True
            else:
                sys.exit('Passed CAPTCHA but was unable to progress for an unknown reason (maybe some kind of rate limiting?). Exiting.')
        else:
            print("Failed CAPTCHA. Trying again in a second.")
            try_count += 1
            time.sleep(1)
elif '.queue-it.net/softblock' in request.url and not queueit:
    sys.exit('Queue-it CAPTCHA challenge detected. Please use the --queueit argument to try to pass this challenge. Exiting.')
elif request.url != "https://nemlog-in.mitid.dk/login/mitid":
    print(f"Unexpected URL, maybe something from QueueIT {request.url}")
    raise Exception(request.content)

soup = BeautifulSoup(request.text, features="html.parser")
request_verification_token = soup.find('input', {'name': '__RequestVerificationToken'}).get('value')
initialise_mitid_parameters = json.loads(aux_in_js_regex.findall(request.text)[0])

# MitID procedure
aux = json.loads(base64.b64decode(initialise_mitid_parameters["Aux"]))
authorization_code = get_authentication_code(session, aux, method, user_id, password)
print(f"Your MitID authorization code was ({authorization_code})")

# Second part of eboks procedure
params = {
    "__RequestVerificationToken": request_verification_token,
    "MitIDAuthCode": authorization_code
}

request = session.post("https://nemlog-in.mitid.dk/login/mitid", data=params)

soup = BeautifulSoup(request.text, features="html.parser")

# User has more than one login option
if request.url == 'https://nemlog-in.mitid.dk/loginoption':
    data = {}
    for soup_input in soup.form.select("input"):
        try:
            data[soup_input["name"]] = soup_input["value"]
        except:    
            data[soup_input["name"]] = ""
    login_options = soup.select("div.list-link-box")
    print('You can choose between different identities:\n')
    identities = []
    for i, login_option in enumerate(login_options):
        print(f'{i+1}: {login_option.select_one("div.list-link-text").string}')
        identities.append(i+1)
    identity = input("Enter the identity you want to use:\n").strip()
    try:
        if int(identity) in identities:
            selected_option = login_options[int(identity)-1].a["data-loginoptions"]
            data["ChosenOptionJson"] = selected_option
        else: 
            raise Exception(f"Identity not in list of identities")
    except:
        raise Exception(f"Wrongly entered identity")
    request = session.post(request.url, data=data)
    soup = BeautifulSoup(request.text, features="html.parser")
        
relay_state = soup.find('input', {'name': 'RelayState'}).get('value')
saml_response = soup.find('input', {'name': 'SAMLResponse'}).get('value')

params = {
    "RelayState": relay_state,
    "SAMLResponse": saml_response
}

request = session.post("https://gateway.digitalpost.dk/auth/s9/e-boks-nemlogin/ssoack", data=params)
parsed_url = urlparse(request.url)
code = parse_qs(parsed_url.query)['code'][0]

params = {
    "code": code,
    "code_verifier": nem_login_code_verifier,
    "grant_type": "authorization_code",
    "nonce": nem_login_nonce,
    "redirect_uri": "https://digitalpost.e-boks.dk"
}

request = session.post("https://digitalpostproxy.e-boks.dk/loginservice/v2/connect/token", json=params)

request = session.post("https://digitalpostproxy.e-boks.dk/loginservice/v2/connect/usertoken", json={"cpr": None})
user_token = request.json()["userToken"]

request = session.post("https://www.e-boks.dk/privat/api_eb/logon/authenticateusertoken", data={"userToken": user_token})

request = session.post("https://www.e-boks.dk/privat/api_eb/logon/antiforgery")
anti_forgery_token = request.json()["Data"]

session.headers.update({ "Antiforgery": anti_forgery_token })

request = session.get("https://www.e-boks.dk/privat/api_eb/users/userInfo")

print(request.content)