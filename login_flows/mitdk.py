# Script for https://mit.dk
import requests, json, base64, sys
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup
sys.path.append("..")
from BrowserClient.Helpers import get_authentication_code, process_args, generate_nem_login_parameters, get_default_args

argparser = get_default_args()
args = argparser.parse_args()

method, user_id, password, proxy = process_args(args)
session = requests.Session()
if proxy:
    session.proxies.update({"http": f"socks5://{proxy}", "https": f"socks5://{proxy}" })

# First part of mit.dk procedure
state, nonce, code_verifier, code_challenge = generate_nem_login_parameters()
redirect_url = 'https://post.mit.dk/main'
 
# Possibly you are going to need a QueueIT cookie.
# Log on to mit.dk in your browser with developer tools enabled to get this cookie
# and uncomment the next line
#session.cookies.update({"QueueITAccepted-SDFrts345E-V3_prod01": "ENTER VALUE FROM BROWSER HERE"}) 

request = session.get(f"https://gateway.mit.dk/view/client/authorization/login?client_id=view-client-id-mobile-prod-1-id&response_type=code&scope=openid&state={state}&code_challenge={code_challenge}&code_challenge_method=S256&response_mode=query&nonce={nonce}&redirect_uri={redirect_url}&deviceName=digitalpost-utilities&deviceId=pc&lang=en_US")

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