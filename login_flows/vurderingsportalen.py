# Script for https://www.vurderingsportalen.dk
import requests, json, base64, sys
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup
sys.path.append("..")
sys.path.append(".")
from BrowserClient.Helpers import get_authentication_code, process_args, get_default_args, choose_between_multiple_identitites
from ScrapingHelp.QueueIt import bypass_botdetect

argparser = get_default_args()
args = argparser.parse_args()

method, user_id, password, proxy = process_args(args)
session = requests.Session()
if proxy:
    session.proxies.update({"http": f"socks5://{proxy}", "https": f"socks5://{proxy}" })

# First part of vurderingsportalen.dk procedure
request = bypass_botdetect(session, "https://api.vurderingsportalen.dk/auth/login?redirectUrl=https%3A%2F%2Fwww.vurderingsportalen.dk%2Fnemlogin-viderestilling%2F")

if request.status_code != 200:
    print(f"Failed session setup attempt, status code {request.status_code}")
    raise Exception(request.content)
if request.url != "https://nemlog-in.mitid.dk/login/mitid":
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

# Second part of vurderingsportalen.dk procedure
params = {
    "__RequestVerificationToken": request_verification_token,
    "MitIDAuthCode": authorization_code
}

request = session.post("https://nemlog-in.mitid.dk/login/mitid", data=params)
soup = BeautifulSoup(request.text, "lxml")

# User has more than one login option
if request.url == 'https://nemlog-in.mitid.dk/loginoption':
    request, soup = choose_between_multiple_identitites(session, request, soup)
    
relay_state = soup.find('input', {'name': 'RelayState'}).get('value')
saml_response = soup.find('input', {'name': 'SAMLResponse'}).get('value')

params = {
    "RelayState": relay_state,
    "SAMLResponse": saml_response
}

request = session.post(soup.form['action'], data=params)
# Strangely, parameters are started with # instead of ?, this is edited for easier parsing
parsable_url = request.url.replace("/#access_token","?access_token")
parsed_url = urlparse(parsable_url)
access_token = parse_qs(parsed_url.query)['access_token'][0]
refresh_token = parse_qs(parsed_url.query)['refresh_token'][0]

session.headers['authorization'] = f"Bearer {access_token}"
api_json = {
	"operationName": "GetUser",
	"variables": {},
	"query": "query GetUser {\n  bruger_session {\n    uid\n    access_level\n    efternavn\n    fornavn\n    firma_navn\n    kan_repraesentere {\n      id\n      navn\n      rolle\n      seneste_dokument_aktivitet\n      type\n      __typename\n    }\n    navn\n    repraesenterer {\n      id\n      navn\n      rolle\n      type\n      __typename\n    }\n    role\n    sagsperson {\n      id\n      type\n      navn\n      __typename\n    }\n    __typename\n  }\n}\n"
}
request = session.post("https://api.vurderingsportalen.dk/graphql", json=api_json)
print(request.json())