# Script for https://private.e-boks.com/danmark/da/
import json, base64, re, requests, sys
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup
sys.path.append("..")
from BrowserClient.Helpers import get_authentication_code, process_args, generate_nem_login_parameters, get_default_args, choose_between_multiple_identitites
from ScrapingHelp.QueueIt import bypass_botdetect

aux_in_js_regex = re.compile(r"\$\(function\(\)\{initiateMitId\((\{.*\})\)\}\);")

argparser = get_default_args()
args = argparser.parse_args()

method, user_id, password, proxy = process_args(args)
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

#request = session.get("https://gateway.digitalpost.dk/auth/oauth/authorize", params=params)
request = bypass_botdetect(session, "https://gateway.digitalpost.dk/auth/oauth/authorize", params)

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
    request = choose_between_multiple_identitites(session, request, soup)
    soup = BeautifulSoup(request.text, "lxml")
        
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