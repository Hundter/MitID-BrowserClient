# Script for https://www.lb.dk/minside
import requests, json, base64, sys
from bs4 import BeautifulSoup
sys.path.append("..")
from BrowserClient.BrowserClient import BrowserClient
from BrowserClient.Helpers import get_authentication_code, process_args, generate_nem_login_parameters, get_default_args

argparser = get_default_args()
args = argparser.parse_args()

method, user_id, password, proxy = process_args(args)
session = requests.Session()
if proxy:
    session.proxies.update({"http": f"socks5://{proxy}", "https": f"socks5://{proxy}" })

# First part of lb.dk procedure
request = session.get("https://minside.lb.dk/mitid/mitidlogin/loginopenidconnect")

if request.status_code != 200:
    print(f"Failed session setup attempt, status code {request.status_code}")
    raise Exception(request.content)
if not 'https://netseidbroker.mitid.dk/login' in request.url:
    print(f"Unexpected URL, failure to proceed.")
    raise Exception(request.content)   

soup = BeautifulSoup(request.text, 'lxml')
request_verification_token = soup.find('input', {'name': '__RequestVerificationToken'}).get('value')
return_url = soup.find('input', {'name': 'ReturnUrl'}).get('value')
aux = soup.find('input', {'name': 'ClientInfo.Aux'}).get('value')

# MitID procedure
aux = json.loads(base64.b64decode(aux))
authorization_code = get_authentication_code(session, aux, method, user_id, password)
print(f"Your MitID authorization code was ({authorization_code})")

# Second part of lb.dk procedure
params = {
    "__RequestVerificationToken": request_verification_token,
    "AuthCode": authorization_code,
    "ReturnUrl": return_url
}

request = session.post("https://netseidbroker.mitid.dk/signin", data=params)
soup = BeautifulSoup(request.text, "lxml")

params = {}
form_inputs = soup.form.find_all('input')
for form_input in form_inputs:
    params[form_input['name']] = form_input['value']

request = session.post(soup.form['action'], data=params)
soup = BeautifulSoup(request.text, "lxml")

params = {}
form_inputs = soup.form.find_all('input')
for form_input in form_inputs:
    params[form_input['name']] = form_input['value']

request = session.post(soup.form['action'], data=params)

request = session.get("https://minside.lb.dk/api/member/welcomemodule")
print(request.json())