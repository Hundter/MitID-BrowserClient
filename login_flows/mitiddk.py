# Script for https://mitid.dk
import requests, json, base64, jwt, sys
from urllib.parse import urlparse, parse_qs
sys.path.append("..")
sys.path.append(".")
from BrowserClient.Helpers import get_authentication_code, process_args, get_default_args

argparser = get_default_args()
args = argparser.parse_args()

method, user_id, password, proxy = process_args(args)
session = requests.Session()
if proxy:
    session.proxies.update({"http": f"socks5://{proxy}", "https": f"socks5://{proxy}" })

# First part of mitid.dk procedure
params = {
    "serviceProvider": "SELF_SERVICE_PORTAL",
    "serviceProviderReference": "Self Service Login",
    "response_type": "code",
    "serviceProviderId": "9d09e4fb-a05e-4cd2-832f-efa1dd245e9b",
    "requestedAttributes": "IDENTITY_NAME",
    "exchangeUrl": "/administration/oauth/exchange",
    "redirect_uri": "https://www.mitid.dk/service-provider/login",
    "ssoGroupId": "ceaef5ba-4f9e-4c9d-9814-3bd9e7ecb2e1",
    "requestedAal": "SUBSTANTIAL",
    "language": "EN",
    "client_id": "d49gtfqbkr9j1v60lr554ltk8q6e7tlt"
}
request = session.get("https://www.mitid.dk/administration/oauth/authorize", params=params)
if request.status_code != 200:
    print(f"Failed session setup attempt, status code {request.status_code}")
    raise Exception(request.content)


request = session.post("https://www.mitid.dk/mitid-administrative-idp/v1/initialize")
if request.status_code != 200:
    print(f"Failed session setup attempt, status code {request.status_code}")
    raise Exception(request.content)

if "aux" not in request.json():
    print(f"Bad response for https://www.mitid.dk/mitid-administrative-idp/v1/initialize, could not find aux, or status code bad: {request.status_code}")
    raise Exception(request.content)

aux = json.loads(base64.b64decode(request.json()["aux"]))
authorization_code = get_authentication_code(session, aux, method, user_id, password)
print(f"Your MitID authorization code was ({authorization_code})")

request = session.post("https://www.mitid.dk/mitid-administrative-idp/login", params={"AuthCode": authorization_code})
parsed_url = parse_qs(urlparse(request.url).query)

authorization_code_2 = parsed_url["code"][0]
state = parsed_url["state"][0]

request = session.get(f"https://www.mitid.dk/administration/oauth/exchange?authorization-code={authorization_code_2}&service-provider=SELF_SERVICE_PORTAL&state={state}")
if request.status_code != 200:
    print(f"Failed to exchange authorization_code_2 for JWT access token, status code {request.status_code}")
    raise Exception(request.content)

access_token = request.json()["access_token"]
access_token_payload = jwt.decode(access_token, options={"verify_signature": False})
uuid = access_token_payload["sub"]

# Login complete, now use the credentials

session = requests.Session()
session.headers["Authorization"] = f"Bearer {access_token}"
request = session.get(f"https://www.mitid.dk/administration/v6/identities/{uuid}")
identity_response = request.json()

print("You have the following identities:")
for identity in identity_response:
    print(identity["identityName"])
