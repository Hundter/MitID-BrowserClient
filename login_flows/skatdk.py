# Script for https://www.tastselv.skat.dk
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

# Possibly you are going to need a QueueIT part of the login url.
# Log on to skat.dk in your browser with developer tools enabled
# and find the part to add to the url. 
queue_it_url_params = ""

request = session.get(f"https://www.tastselv.skat.dk/borger/loginsso{queue_it_url_params}")

if request.status_code != 200:
    print(f"Failed session setup attempt, status code {request.status_code}")
    raise Exception(request.content)
elif 'vent.skat.dk/softblock' in request.url and queueit:
    print('Queue-it CAPTCHA challenge detected. Trying to pass...')
    from ScrapingHelp.QueueIt import bypass_botdetect
    request = bypass_botdetect(session, f"https://www.tastselv.skat.dk/borger/loginsso{queue_it_url_params}")    
if 'https://vent.skat.dk/?c=skat' in request.url:
    sys.exit('It seems you have been placed in a Queue-it waiting line. Currently no way to bypass this. Exiting.')
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

# Second part of skat.dk procedure
params = {
    "__RequestVerificationToken": request_verification_token,
    "MitIDAuthCode": authorization_code
}

request = session.post("https://nemlog-in.mitid.dk/login/mitid", data=params)

soup = BeautifulSoup(request.text, features="html.parser")
relay_state = soup.find('input', {'name': 'RelayState'}).get('value')
saml_response = soup.find('input', {'name': 'SAMLResponse'}).get('value')

params = {
    "RelayState": relay_state,
    "SAMLResponse": saml_response
}

request = session.post(soup.form['action'], data=params)
params = {"post": "ja"}
request = session.post(request.url, data=params)
request = session.post(request.url, data=params)
soup = BeautifulSoup(request.text, 'lxml')
print(soup.select_one("div.infocontent").text.replace("Log af","").strip())