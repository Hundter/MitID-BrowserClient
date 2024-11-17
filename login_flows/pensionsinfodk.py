# Script for https://pensionsinfo.dk
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

# First part of pensionsinfo.dk procedure
request = session.get("https://pensionsinfo.dk/loginMitId")

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

# Second part of pensionsinfo.dk procedure
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

request = session.get("https://pensionsinfo.dk/DataGathering")
soup = BeautifulSoup(request.text, "lxml")
request_verification_token = soup.find('input', {'name': '__RequestVerificationToken'}).get('value')
customer_id_and_pension_plans = soup.datagathering[':loading-data']
search_string = 'customerId:"'
start_of_customer_id = customer_id_and_pension_plans.index(search_string)+len(search_string)
end_of_customer_id = customer_id_and_pension_plans.index('"', start_of_customer_id)
customer_id = customer_id_and_pension_plans[start_of_customer_id:end_of_customer_id]
search_string = 'pensionProviders'
pension_plans = json.loads('{' + customer_id_and_pension_plans[customer_id_and_pension_plans.index(search_string):-1].replace(search_string, f'"{search_string}"') + '}')
for provider in pension_plans["pensionProviders"]:
    request = session.get(f"https://pensionsinfo.dk/GetPensionPlan?customerId={customer_id}&pensionProviderId={provider['id']}")
    breakpoint()

params = {
    'ssoType': "1",
    'closeClick': "0",
    '__RequestVerificationToken': request_verification_token
}
request = session.post("https://pensionsinfo.dk/DataGathering", data=params)
soup = BeautifulSoup(request.text, "lxml")
print(soup.select_one("div.containerUser").text.strip().replace("Velkommen ",""))

# Some example requests
#pension_info = session.get("https://pensionsinfo.dk/viewdata/singlePerson?benefittypes=allpensions&lang=da")
#print(pension_info.json())
#pension_rapport_pdf = session.get("https://pensionsinfo.dk/GetReport?print=true&chkboxAge=64&chkboxAge=65&chkboxAge=66&chkboxAge=67&chkboxAge=68&chkboxAge=69&chkboxAge=70&chkboxAge=71&chkboxAge=72&chkboxAge=73&chkboxAge=74&chkboxAge=75")