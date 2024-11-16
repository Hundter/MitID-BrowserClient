# Script for https://post.borger.dk
import requests, json, base64, sys
from bs4 import BeautifulSoup
sys.path.append("..")
from BrowserClient.Helpers import get_authentication_code, process_args, get_default_args, choose_between_multiple_identitites
from ScrapingHelp.QueueIt import bypass_botdetect

argparser = get_default_args()
args = argparser.parse_args()

method, user_id, password, proxy = process_args(args)
session = requests.Session()
if proxy:
    session.proxies.update({"http": f"socks5://{proxy}", "https": f"socks5://{proxy}" })

# First part of post.borger.dk procedure
request = bypass_botdetect(session, "https://auth.post.borger.dk/web/auth/login?returnurl=https://post.borger.dk/&idp=nemloginRealm")

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

# Use https://api.post.borger.dk/api/streamaddresses (or developer tools in your browser)
# for a list of API calls
session.headers['X-XSRF-TOKEN'] = session.cookies['XSRF-REQUEST-TOKEN']
request = session.get("https://api.post.borger.dk/api/mailboxes?size=1000")
print(request.json())