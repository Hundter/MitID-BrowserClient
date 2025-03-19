# Script for https://www.nordnet.dk/logind
import requests, json, base64, sys, string, secrets, uuid
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup
sys.path.append("..")
from BrowserClient.Helpers import get_authentication_code, process_args, get_default_args
from datetime import datetime, date

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

# Get accounts
#accounts = session.get('https://www.nordnet.dk/api/2/accounts')
#print(accounts.json())

# Get transactions
#accids = (',').join([str(account['accid']) for account in accounts.json()])
#fromdate = '2013-01-01'
#todate = datetime.strftime(date.today(), '%Y-%m-%d')

bearer_token = request.headers['nn-jwt']
print(bearer_token)

# Get JSON transactions
# Limited to 800 results, the maximum may be larger
# Change offset to get subsequent transactions
# You can get total transactions by requesting: 
# f'https://api.prod.nntech.io/transaction/transaction-and-notes/v1/transaction-summary?fromDate={fromdate}&toDate={todate}&accids={accids}&includeCancellations=false'
#transactions_json = session.get(f'https://api.prod.nntech.io/transaction/transaction-and-notes/v1/transactions/page?fromDate={fromdate}&toDate={todate}&accids={accids}&offset=0&limit=800&sort=ACCOUNTING_DATE&sortOrder=DESC&includeCancellations=false')

# Get CSV transactions
# Tab delimited. To change to semicolon-delimited, add:
# csv_file = csv_file.replace('\t',';')
#transactions_csv = session.get(f'https://api.prod.nntech.io/transaction/transaction-and-notes/v1/transactions/csv/filter?accids={accids}&fromDate={fromdate}&toDate={todate}&sort=ACCOUNTING_DATE&sortOrder=DESC&includeCancellations=false')
#transactions_csv_bytes = transactions_csv.json()['bytes']
#transactions_csv_decoded_bytes = base64.b64decode(transactions_csv_bytes)
#csv_file = transactions_csv_decoded_bytes.decode('utf-16')