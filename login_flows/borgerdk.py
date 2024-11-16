# Script for https://www.borger.dk/mitoverblik
import requests, json, base64, sys
from bs4 import BeautifulSoup
sys.path.append("..")
from BrowserClient.BrowserClient import BrowserClient
from BrowserClient.Helpers import get_authentication_code, process_args, generate_nem_login_parameters, get_default_args, choose_between_multiple_identitites

argparser = get_default_args()
args = argparser.parse_args()

method, user_id, password, proxy = process_args(args)
session = requests.Session()
if proxy:
    session.proxies.update({"http": f"socks5://{proxy}", "https": f"socks5://{proxy}" })

# First part of borger.dk procedure
request = session.get(f"https://www.borger.dk/mitoverblik")
soup = BeautifulSoup(request.text, "xml")
params = {soup.form.input['name']: soup.form.input['value']}
request = session.post(soup.form['action'], data=params)

if request.status_code != 200:
    print(f"Failed session setup attempt, status code {request.status_code}")
    raise Exception(request.content)
if request.url != "https://nemlog-in.mitid.dk/login/mitid":
    print(f"Unexpected URL, failure to proceed.")
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

# Second part of borger.dk procedure
params = {
    "__RequestVerificationToken": request_verification_token,
    "MitIDAuthCode": authorization_code
}

request = session.post("https://nemlog-in.mitid.dk/login/mitid", data=params)
soup = BeautifulSoup(request.text, "lxml")

# User has more than one login option
if request.url == 'https://nemlog-in.mitid.dk/loginoption':
    request = choose_between_multiple_identitites(session, request, soup)
    soup = BeautifulSoup(request.text, "xml")

params = {soup.form.input['name']: soup.form.input['value']}
request = session.post(soup.form['action'], data=params)

request = session.get("https://www.borger.dk/mitoverblik")
soup = BeautifulSoup(request.text, "lxml")
print(f'You are {soup.select_one("span.subheader__username").text.strip()}')