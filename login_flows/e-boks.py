import binascii, json, base64, re, hashlib, requests, argparse, sys
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup
from Crypto import Random

sys.path.append("..")
from BrowserClient.BrowserClient import BrowserClient

parser = argparse.ArgumentParser(description="argparser")
parser.add_argument('--user', help='Your MitID username. For example: "GenericDanishCitizen"', required=True)
parser.add_argument('--proxy', help='An optional socks5 proxy to use for all communication with MitID', required=False)
parser.add_argument('--method', choices=['APP', 'TOKEN'], help='Which method to use when logging in to MitID, default APP', default='APP', required=False)
args = parser.parse_args()

aux_in_js_regex = re.compile(r"\$\(function\(\)\{initiateMitId\((\{.*\})\)\}\);")

def generateRandomString():
    return binascii.hexlify(Random.new().read(28)).decode("utf-8")

def generateChallenge(verifier):
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("utf-8")).digest()).decode("utf-8").rstrip("=")

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

# Possibly you are going to need a QueueIT cookie
#session.cookies.update({
#    "QueueITAccepted-SDFrts345E-V3_prod01": ""
#})

r = session.get("https://gateway.digitalpost.dk/auth/oauth/authorize", params=params)

initialise_mitid_parameters = json.loads(aux_in_js_regex.findall(r.text)[0])
aux = json.loads(base64.b64decode(initialise_mitid_parameters["Aux"]))

soup = BeautifulSoup(r.text, features="html.parser")

request_verification_token = soup.find('input', {'name': '__RequestVerificationToken'}).get('value')

client_hash = binascii.hexlify(base64.b64decode(aux["coreClient"]["checksum"])).decode('ascii')
authentication_session_id = aux["parameters"]["authenticationSessionId"]

MitIDClient = BrowserClient(client_hash, authentication_session_id, session)
MitIDClient.identify_as_user_and_get_available_authenticators(args.user)

if args.method == "TOKEN":
    token_digits = input("Please input the 6 digits from your code token\n").strip()
    MitIDClient.authenticate_with_token(token_digits)

    password = input("Please input your password\n").strip()
    MitIDClient.authenticate_with_password(password)
elif args.method == "APP":
    MitIDClient.authenticate_with_app()
else:
    raise Exception(f"Unknown authenticator method {args.method}")

authorization_code = MitIDClient.finalize_authentication_and_get_authorization_code()

params = {
    "__RequestVerificationToken": request_verification_token,
    "MitIDAuthCode": authorization_code
}

r = session.post("https://nemlog-in.mitid.dk/login/mitid", data=params)

soup = BeautifulSoup(r.text, features="html.parser")

relay_state = soup.find('input', {'name': 'RelayState'}).get('value')
saml_response = soup.find('input', {'name': 'SAMLResponse'}).get('value')

params = {
    "RelayState": relay_state,
    "SAMLResponse": saml_response
}

r = session.post("https://gateway.digitalpost.dk/auth/s9/e-boks-nemlogin/ssoack", data=params)
parsed_url = urlparse(r.url)
code = parse_qs(parsed_url.query)['code'][0]

params = {
    "code": code,
    "code_verifier": nem_login_code_verifier,
    "grant_type": "authorization_code",
    "nonce": nem_login_nonce,
    "redirect_uri": "https://digitalpost.e-boks.dk"
}

r = session.post("https://digitalpostproxy.e-boks.dk/loginservice/v2/connect/token", json=params)


r = session.post("https://digitalpostproxy.e-boks.dk/loginservice/v2/connect/usertoken", json={"cpr": None})

user_token = r.json()["userToken"]

r = session.post("https://www.e-boks.dk/privat/api_eb/logon/authenticateusertoken", data={"userToken": user_token})

r = session.post("https://www.e-boks.dk/privat/api_eb/logon/antiforgery")

anti_forgery_token = r.json()["Data"]

session.headers.update({ "Antiforgery": anti_forgery_token })

r = session.get("https://www.e-boks.dk/privat/api_eb/users/userInfo")

print(r.content)