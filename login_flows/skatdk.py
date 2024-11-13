# Script for https://www.tastselv.skat.dk
import requests, json, base64, argparse, sys, string, secrets, uuid, random
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup
sys.path.append("..")
from BrowserClient.BrowserClient import BrowserClient
from BrowserClient.Helpers import get_authentication_code, process_args, generate_nem_login_parameters, get_default_args

import easyocr

argparser = get_default_args()
args = argparser.parse_args()

method, user_id, password, proxy, queueit = process_args(args)
session = requests.Session()
if proxy:
    session.proxies.update({"http": f"socks5://{proxy}", "https": f"socks5://{proxy}" })

# First part of skat.dk procedure
nem_login_state = uuid.uuid4()
digits = string.digits
form_digits = ''.join(secrets.choice(digits) for i in range(29))

# Possibly you are going to need a QueueIT part of the login url.
# Log on to skat.dk in your browser with developer tools enabled
# and find the part to add to the url. 
queue_it_url_params = ""

request = session.get(f"https://www.tastselv.skat.dk/borger/loginsso{queue_it_url_params}")

if request.status_code != 200:
    print(f"Failed session setup attempt, status code {request.status_code}")
    raise Exception(request.content)
elif 'vent.skat.dk/softblock' in request.url and queueit:
    print('Queue-it CAPTCHA challenge detected. Trying to pass...')
    passed_captcha = False
    try_count = 0
    while passed_captcha == False and try_count < 5:    
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:130.0) Gecko/20100101 Firefox/130.0',
            'Referer': request.url,
            'X-Queueit-Challange-reason': '0',
            'X-Queueit-Challange-CustomerId': 'skat',
            'X-Queueit-Challange-EventId': 'prod241104login',
            'X-Queueit-Challange-Hash': 'gfo6/+gigQqytYEiDzDgvtTgtYDLePoPAs7ndGqwBzU=',
            'Origin': 'https://vent.skat.dk',
        }
        queue_request = session.post("https://vent.skat.dk/challengeapi/queueitcaptcha/challenge/da-dk", headers=headers)
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
            "solution": solution,
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
            "customerId": "skat",
            "eventId": "prod241104login",
            "version": 6
        }
        verify_request = session.post("https://vent.skat.dk/challengeapi/verify", json=json_queue)
        verify_request_json = verify_request.json()
        if verify_request_json['isVerified'] == True:
            print("Passed CAPTCHA!")
            # This request should redirect to https://nemlog-in.mitid.dk/login/mitid        
            request = session.get(f"https://vent.skat.dk/?c=skat&e=prod241104login&t=https://www.tastselv.skat.dk/borger/loginsso&cid=da-DK&scv={json.dumps(verify_request_json['sessionInfo'])}")
            breakpoint()
            if request.url == "https://nemlog-in.mitid.dk/login/mitid":
                passed_captcha = True
            elif 'https://vent.skat.dk/?c=skat' in request.url:
                sys.exit('It seems you have been placed in a Queue-it waiting line. Currently no way to bypass this. Exiting.')
            else:
                sys.exit('Passed CAPTCHA but was unable to progress for an unknown reason (maybe some kind of rate limiting?). Exiting.')
        else:
            print("Failed CAPTCHA. Trying again in a second.")
            try_count += 1
            time.sleep(1)                
elif 'vent.skat.dk/softblock' in request.url and not queueit:
    sys.exit('Queue-it CAPTCHA challenge detected. Please use the --queueit argument to try to pass this challenge. Exiting.')
elif request.url != "https://nemlog-in.mitid.dk/login/mitid":
    print(f"Unexpected URL, maybe something from QueueIT {request.url}")
    raise Exception(request.content)   

soup = BeautifulSoup(request.text, 'lxml')
request_verification_token = soup.find('input', {'name': '__RequestVerificationToken'}).get('value')

search_string = '"Aux":"'
start_aux = request.text.index(search_string)+len(search_string)
end_aux = request.text.index('"', start_aux)

# MitID procedure
aux = json.loads(base64.b64decode(request.text[start_aux:end_aux]))
authorization_code = get_authentication_code(session, aux, method, user_id, password)
print(f"Your MitID authorization code was ({authorization_code})")

# Second part of skat.dk procedure
params = {
    "__RequestVerificationToken": request_verification_token,
    "MitIDAuthCode": authorization_code
}

request = session.post("https://nemlog-in.mitid.dk/login/mitid", data=params)

soup = BeautifulSoup(request.text, features="html.parser")
relay_state = soup.find('input', {'name': 'RelayState'}).get('value')
saml_response = soup.find('input', {'name': 'SAMLResponse'}).get('value')

params = {
    "RelayState": relay_state,
    "SAMLResponse": saml_response
}

request = session.post(soup.form['action'], data=params)
params = {"post": "ja"}
request = session.post(request.url, data=params)
request = session.post(request.url, data=params)
soup = BeautifulSoup(request.text, 'lxml')
print(soup.select_one("div.infocontent").text.replace("Log af","").strip())