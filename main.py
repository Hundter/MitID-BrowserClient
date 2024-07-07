import requests, binascii, json, base64, jwt, argparse
from urllib.parse import parse_qs, urlparse
from BrowserClient.BrowserClient import BrowserClient

parser = argparse.ArgumentParser(description="argparser")
parser.add_argument('--user', help='Your MitID username. For example: "GenericDanishCitizen"', required=True)
parser.add_argument('--proxy', help='An optional socks5 proxy to use for all communication with MitID', required=False)
parser.add_argument('--method', choices=['APP', 'TOKEN'], help='Which method to use when logging in to MitID, default APP', default='APP', required=False)
args = parser.parse_args()

user_id = args.user

session = requests.Session()

if args.proxy:
    session.proxies.update({"http": f"socks5://{args.proxy}", "https": f"socks5://{args.proxy}" })

# This URL will be different for each MitID site, would be nice to generalize this somehow
r = session.get("https://www.mitid.dk/administration/oauth/authorize?response_type=code&serviceProvider=SELF_SERVICE_PORTAL&serviceProviderReference=Self Service Login&serviceProviderId=9d09e4fb-a05e-4cd2-832f-efa1dd245e9b&requestedAttributes=IDENTITY_NAME&exchangeUrl=/administration/oauth/exchange&redirect_uri=https://www.mitid.dk/service-provider/login&ssoGroupId=ceaef5ba-4f9e-4c9d-9814-3bd9e7ecb2e1&requestedAal=SUBSTANTIAL&language=EN&client_id=d49gtfqbkr9j1v60lr554ltk8q6e7tlt")
if r.status_code != 200:
    print(f"Failed session setup attempt, status code {r.status_code}")
    raise Exception(r.content)


r = session.post("https://www.mitid.dk/mitid-administrative-idp/v1/initialize")
if r.status_code != 200:
    print(f"Failed session setup attempt, status code {r.status_code}")
    raise Exception(r.content)

if "aux" not in r.json():
    print(f"Bad response for https://www.mitid.dk/mitid-administrative-idp/v1/initialize, could not find aux, or status code bad: {r.status_code}")
    raise Exception(r.content)

aux = json.loads(base64.b64decode(r.json()["aux"]))

client_hash = binascii.hexlify(base64.b64decode(aux["coreClient"]["checksum"])).decode('ascii')
authentication_session_id = aux["parameters"]["authenticationSessionId"]

MitIDClient = BrowserClient(client_hash, authentication_session_id, session)
available_authenticators = MitIDClient.identify_as_user_and_get_available_authenticators(user_id)

print(f"Available authenticator: {available_authenticators}")

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

print(f"Your MitID authorization code was ({authorization_code})")

r = session.post("https://www.mitid.dk/mitid-administrative-idp/login", params={"AuthCode": authorization_code})
parsed_url = parse_qs(urlparse(r.url).query)

authorization_code_2 = parsed_url["code"][0]
state = parsed_url["state"][0]

r = session.get("https://www.mitid.dk/administration/oauth/exchange?authorization-code="+authorization_code_2+"&service-provider=SELF_SERVICE_PORTAL&state="+state)
print(r.status_code)

access_token = r.json()["access_token"]
access_token_payload = jwt.decode(access_token, options={"verify_signature": False})
uuid = access_token_payload["sub"]

r = session.get("https://www.mitid.dk/administration/v6/identities/"+uuid, headers={"Authorization": "Bearer "+access_token})
print(r.status_code)
print(r.content)

print(f"Your access token was: '{access_token}'")