# Script for https://www.lsb.dk/login
import requests, json, base64, sys, json, re
from bs4 import BeautifulSoup
sys.path.append("..")
from BrowserClient.Helpers import get_authentication_code, process_args, get_default_args

argparser = get_default_args()
args = argparser.parse_args()

method, user_id, password, proxy, queueit = process_args(args)
session = requests.Session()
if proxy:
    session.proxies.update({"http": f"socks5://{proxy}", "https": f"socks5://{proxy}" })
    
# First part of LSB procedure
request = session.get('https://www.lsb.dk/login')
soup = BeautifulSoup(request.text, 'lxml')

login_url = json.loads(soup.find('script', string=re.compile("SDCNEoS.views.Login")).string)['props']['contextModel']['loginTypes'][0]['url']
request = session.get(login_url)
soup = BeautifulSoup(request.text, 'lxml')

login_script = soup.find('script', string=re.compile("mitIDLoginViewModel")).string
searchstring = 'mitIDLoginViewModel = '
initial_login_info = json.loads(login_script[login_script.index(searchstring)+len(searchstring):login_script.index(';', login_script.index(searchstring))])
payload = 'MitIDLoginViewModel=' + json.dumps(initial_login_info)
brokerpageurl = 'https://lsb.mitid.dk/authorize'
headers = {'Content-Type': 'application/x-www-form-urlencoded'}
request = session.post(brokerpageurl, data=payload, headers=headers)

searchstring = 'authenticationRequest = '
login_info = json.loads(request.text[request.text.index(searchstring)+len(searchstring):request.text.index(';', request.text.index(searchstring))])
searchstring = "'SDCGuid', '"
headers = {
    'Content-Type': 'application/json',
    'SDCGuid': request.text[request.text.index(searchstring)+len(searchstring):request.text.index("'", request.text.index(searchstring)+len(searchstring))]
}
authentication_url = 'https://mitid-bbs-p1.sdc.eu/mitid-broker/authentication-sessions/authentication'
request = session.post(authentication_url, json=login_info, headers=headers)

# MitID procedure
aux = json.loads(base64.b64decode(request.json()["aux"]))
authorization_code = get_authentication_code(session, aux, method, user_id, password)
print(f"Your MitID authorization code was ({authorization_code})")

# Second part of LSB procedure
login_info = initial_login_info['MitIDBrokerBackendModel']
request = session.post('https://mitid-bbs-p1.sdc.eu/mitid-broker/access-token/' + authorization_code, json=login_info, headers=headers)
session_id = request.json()['sessionId']
payload = f'sessionId={session_id}&result=Complete&errorCode=null&description=null'
headers = {'Content-Type': 'application/x-www-form-urlencoded'}
request = session.post('https://auth.sdc.dk/MitID/MitIDComplete', data=payload, headers=headers)
soup = BeautifulSoup(request.text, 'lxml')
subscription_key = json.loads(soup.find('script', {'id': 'neos'}).string)['api']['services']['subscriptionKey']

approval_url_script = soup.find('script', string=re.compile("https://www.lsb.dk")).string
searchstring = "window.location = '"
approval_url = approval_url_script[approval_url_script.index(searchstring)+len(searchstring):approval_url_script.index("'",approval_url_script.index(searchstring)+len(searchstring))]
request = session.get(approval_url)

headers = {
    'Authorization': "Bearer "+session.cookies['sdc_token'],
    'Ocp-Apim-Subscription-Key': subscription_key,
    'SDCGuid': session.cookies['SDCGuid'],
    'traceparent': session.cookies['traceparent'],
}
user_info = session.get('https://api-proxy-neos.sdc.eu/api/neos/ebanking-users/v1/api/users/current', headers=headers)
print(user_info.json())