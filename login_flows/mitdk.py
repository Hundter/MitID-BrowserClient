# Script for https://mit.dk
import requests, json, base64, sys
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup
sys.path.append("..")
from BrowserClient.Helpers import get_authentication_code, process_args, generate_nem_login_parameters, get_default_args, choose_between_multiple_identitites
from ScrapingHelp.QueueIt import bypass_botdetect

argparser = get_default_args()
args = argparser.parse_args()

method, user_id, password, proxy = process_args(args)
session = requests.Session()
if proxy:
    session.proxies.update({"http": f"socks5://{proxy}", "https": f"socks5://{proxy}" })

# First part of mit.dk procedure
state, nonce, code_verifier, code_challenge = generate_nem_login_parameters()
redirect_url = 'https://post.mit.dk/main'

params = {
    "response_type": "code",
    "client_id": "view-client-id-mobile-prod-1-id",
    "redirect_uri": "https://post.mit.dk/main",
    "scope": "openid",
    "state": state,
    "nonce": nonce,
    "code_challenge": code_challenge,
    "code_challenge_method": "S256",
    "response_mode": "query",
    "deviceName": "digitalpost-utilities",
    "deviceId": "pc",
    "lang": "en_US"
}
 
#request = session.get(f"https://gateway.mit.dk/view/client/authorization/login", params=params)
request = bypass_botdetect(session, "https://gateway.mit.dk/view/client/authorization/login", params)

if request.status_code != 200:
    print(f"Failed session setup attempt, status code {request.status_code}")
    raise Exception(request.content)
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

# Second part of mit.dk procedure
params = {
    "__RequestVerificationToken": request_verification_token,
    "MitIDAuthCode": authorization_code
}

request = session.post("https://nemlog-in.mitid.dk/login/mitid", data=params)

soup = BeautifulSoup(request.text, features="html.parser")

# User has more than one login option
if request.url == 'https://nemlog-in.mitid.dk/loginoption':
    request = choose_between_multiple_identitites(session, request, soup)
    soup = BeautifulSoup(request.text, "lxml")
        
relay_state = soup.find('input', {'name': 'RelayState'}).get('value')
saml_response = soup.find('input', {'name': 'SAMLResponse'}).get('value')

params = {
    "RelayState": relay_state,
    "SAMLResponse": saml_response
}

request = session.post("https://gateway.digitalpost.dk/auth/s9/mit-dk-nemlogin/ssoack", data=params)

parsed_url = urlparse(request.url)
code = parse_qs(parsed_url.query)['code'][0]

request = session.post(f"https://gateway.mit.dk/view/client/authorization/token?grant_type=authorization_code&redirect_uri={redirect_url}&client_id=view-client-id-mobile-prod-1-id&code={code}&code_verifier={code_verifier}")

tokens = json.loads(request.text)
session.headers['mitdkToken'] = tokens['access_token']
session.headers['ngdpToken'] = tokens['ngdp']['access_token']
session.headers['platform'] = 'web'

request = session.get("https://gateway.mit.dk/view/client/users")
print(request.json())