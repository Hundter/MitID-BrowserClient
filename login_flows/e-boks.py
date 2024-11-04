import json, base64, re, hashlib, requests, argparse, sys
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup
from Crypto import Random
sys.path.append("..")
from BrowserClient.BrowserClient import BrowserClient, get_authentication_code, process_args

parser = argparse.ArgumentParser(description="argparser")
parser.add_argument('--user', help='Your MitID username. For example: "GenericDanishCitizen"', required=True)
parser.add_argument('--password', help='Your MitID password. For example: "CorrectHorseBatteryStaple"', required=False)
parser.add_argument('--proxy', help='An optional socks5 proxy to use for all communication with MitID', required=False)
parser.add_argument('--method', choices=['APP', 'TOKEN'], help='Which method to use when logging in to MitID, default APP', default='APP', required=False)
args = parser.parse_args()

aux_in_js_regex = re.compile(r"\$\(function\(\)\{initiateMitId\((\{.*\})\)\}\);")

def generateRandomString():
    return binascii.hexlify(Random.new().read(28)).decode("utf-8")

def generateChallenge(verifier):
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("utf-8")).digest()).decode("utf-8").rstrip("=")

method, user_id, password = process_args(args)
session = requests.Session()
if args.proxy:
    session.proxies.update({"http": f"socks5://{args.proxy}", "https": f"socks5://{args.proxy}" })

nem_login_state = generateRandomString()
nem_login_nonce = generateRandomString()
nem_login_code_verifier = generateRandomString()
nem_login_code_challenge = generateChallenge(nem_login_code_verifier)

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
soup = BeautifulSoup(request.text, features="html.parser")
request_verification_token = soup.find('input', {'name': '__RequestVerificationToken'}).get('value')

initialise_mitid_parameters = json.loads(aux_in_js_regex.findall(request.text)[0])
aux = json.loads(base64.b64decode(initialise_mitid_parameters["Aux"]))
authorization_code = get_authentication_code(session, aux, method, user_id, password)
print(f"Your MitID authorization code was ({authorization_code})")

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