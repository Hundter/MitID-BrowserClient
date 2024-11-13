# Script for https://netbank.santanderconsumer.dk/dk/login
import requests, json, base64, sys, string, secrets
from bs4 import BeautifulSoup
sys.path.append("..")
from BrowserClient.Helpers import get_authentication_code, process_args, generate_nem_login_parameters, get_default_args

argparser = get_default_args()
args = argparser.parse_args()

method, user_id, password, proxy, queueit = process_args(args)
session = requests.Session()
if proxy:
    session.proxies.update({"http": f"socks5://{proxy}", "https": f"socks5://{proxy}" })

# First part of Santander procedure
nem_login_state, _, nem_login_code_verifier, nem_login_code_challenge = generate_nem_login_parameters()
digits = string.digits
form_digits = ''.join(secrets.choice(digits) for i in range(29))

request = session.get(f"https://oauth.scb.nu/oauth/v2/authorize?response_type=code&client_id=SCBDK.Netbank.Client&redirect_uri=https://netbank.santanderconsumer.dk/dk/auth/callback&code_challenge_method=S256&scope=netbank.customer.read netbank.customer.write netbank.customer-product.read netbank.customer-product.write netbank.deposit.read netbank.deposit.write netbank.loan.read netbank.loan.write netbank.credit.read netbank.credit.write netbank.leasing.read netbank.leasing.write netbank.transfer-account.read netbank.transfer-account.write netbank.customer-compliance.read netbank.customer-compliance.write netbank.message.read netbank.message.write netbank.chat.read netbank.chat.write banking.mysantander openid profile&code_challenge={nem_login_code_challenge}&state={nem_login_state}")
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

# Second part of Santander procedure
payload = f'''-----------------------------{form_digits}\r\nContent-Disposition: form-data; name="authCode"\r\n\r\n{authorization_code}\r\n-----------------------------{form_digits}--\r\n'''

headers = {'Content-Type': f'multipart/form-data; boundary=---------------------------{form_digits}'}
request = session.post(soup.div.next['data-base-url']+soup.div.next['data-auth-code-path'], data=payload, headers=headers)
request = session.get(soup.div.next['data-base-url']+soup.div.next['data-finalize-auth-path'])
soup = BeautifulSoup(request.text, 'lxml')
inputs = soup.find_all('input')
json_payload = {}
for input in inputs:
    json_payload[input['name']] = input['value']

payload = f"code={json_payload['code']}&session_state={json_payload['session_state']}&state={json_payload['state']}"
headers = {'Content-Type': 'application/x-www-form-urlencoded'}
request = session.post('https://oauth.scb.nu/oauth/v2/authentication/scb-obas-denmark/callback', data=payload, headers=headers)
soup = BeautifulSoup(request.text, 'lxml')
inputs = soup.find_all('input')
json_payload = {}
for input in inputs:
    try:
        json_payload[input['name']] = input['value']
    except:
        pass

payload = f"token={json_payload['token']}&state={json_payload['state']}"
request = session.post('https://oauth.scb.nu' + soup.form['action'], data=payload, headers=headers)
code = request.url[request.url.index('code=')+5:request.url.index('&',request.url.index('code='))]
payload = f"client_id=SCBDK.Netbank.Client&redirect_uri=https%3A%2F%2Fnetbank.santanderconsumer.dk%2Fdk%2Fauth%2Fcallback&grant_type=authorization_code&code={code}&code_verifier={nem_login_code_verifier}"

headers = {'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'}
request = session.post('https://oauth.scb.nu/oauth/v2/token', data=payload, headers=headers)
request_json = request.json()

access_token = request_json['access_token']

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:126.0) Gecko/20100101 Firefox/126.0',
    'Accept': 'application/json',
    'Ocp-Apim-Subscription-Key': 'e11f034d95144b7a9f1427932fccf853',
    'x-country': 'DK',
    'X-Platform': 'Windows:Firefox(126)',
    'Authorization': "Bearer "+access_token,
}

user_info = session.get('https://apim.scb.nu/netbank/customer/v1/', headers=headers)
print(user_info.json())
products = session.get('https://apim.scb.nu/netbank/customer-product/v1/', headers=headers)
print(products.json())
for deposit in products.json()['depositCustomerProducts']:
    account_id = deposit['accountId']
    account_info = session.get('https://apim.scb.nu/netbank/deposit/v1/'+account_id, headers=headers)
    print(account_info.json())