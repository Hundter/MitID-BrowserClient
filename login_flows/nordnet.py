# Script for https://www.nordnet.dk/logind
import requests, json, base64, sys, string, secrets, uuid
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup
sys.path.append("..")
from BrowserClient.Helpers import get_authentication_code, process_args, get_default_args

argparser = get_default_args()
args = argparser.parse_args()

method, user_id, password, proxy = process_args(args)
session = requests.Session()
if proxy:
    session.proxies.update({"http": f"socks5://{proxy}", "https": f"socks5://{proxy}" })
    
# First part of Nordnet procedure
nem_login_state = uuid.uuid4()
digits = string.digits
form_digits = ''.join(secrets.choice(digits) for i in range(29))

login_url = f"https://id.signicat.com/oidc/authorize?client_id=prod.nordnet.dk.8x&response_type=code&redirect_uri=https://www.nordnet.dk/login&scope=openid signicat.national_id&acr_values=urn:signicat:oidc:method:mitid-cpr&state=NEXT_OIDC_STATE_{nem_login_state}"

request = session.get(login_url)
if request.status_code != 200:
    print(f"Failed session setup attempt, status code {request.status_code}")
    raise Exception(request.content)

soup = BeautifulSoup(request.text, 'lxml')
next = soup.div['data-index-url']
request = session.get(next)
soup = BeautifulSoup(request.text, 'lxml')

request = session.post(soup.div.next['data-base-url']+soup.div.next['data-init-auth-path'])
if request.status_code != 200:
    print(f"Failed session setup attempt, status code {request.status_code}")
    raise Exception(request.content)

# MitID procedure
aux = json.loads(base64.b64decode(request.json()["aux"]))
authorization_code = get_authentication_code(session, aux, method, user_id, password)
print(f"Your MitID authorization code was ({authorization_code})")

# Second part of Nordnet procedure
payload = f'''-----------------------------{form_digits}\r\nContent-Disposition: form-data; name="authCode"\r\n\r\n{authorization_code}\r\n-----------------------------{form_digits}--\r\n'''

headers = {'Content-Type': f'multipart/form-data; boundary=---------------------------{form_digits}'}
request = session.post(soup.div.next['data-base-url']+soup.div.next['data-auth-code-path'], data=payload, headers=headers)
request = session.get(soup.div.next['data-base-url']+soup.div.next['data-finalize-auth-path'])
parsed_url = urlparse(request.url)
code = parse_qs(parsed_url.query)['code'][0]

payload = {
    "authenticationProvider": "SIGNICAT",
    "countryCode":"DK", 
    "signicat": {
        "authorizationCode": code,
        "redirectUri":"https://www.nordnet.dk/login"
        }
    }

session.headers['client-id'] = 'NEXT'
request = session.post('https://www.nordnet.dk/nnxapi/authentication/v2/sessions', json=payload)
request = session.post('https://www.nordnet.dk/api/2/authentication/nnx-session/login', json={})
accounts = session.get('https://www.nordnet.dk/api/2/accounts')
print(accounts.json())