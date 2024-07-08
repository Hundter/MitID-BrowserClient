# Script for https://www.lsb.dk/login
import requests, binascii, json, base64, argparse, sys, json, re
from bs4 import BeautifulSoup
sys.path.append("..")
from BrowserClient.BrowserClient import BrowserClient

parser = argparse.ArgumentParser(description="argparser")
parser.add_argument('--user', help='Your MitID username. For example: "GenericDanishCitizen"', required=True)
parser.add_argument('--proxy', help='An optional socks5 proxy to use for all communication with MitID', required=False)
parser.add_argument('--method', choices=['APP', 'TOKEN'], help='Which method to use when logging in to MitID, default APP', default='APP', required=False)
args = parser.parse_args()

user_id = args.user

session = requests.Session()

if args.proxy:
    session.proxies.update({"http": f"socks5://{args.proxy}", "https": f"socks5://{args.proxy}" })
    
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

client_hash = binascii.hexlify(base64.b64decode(aux["coreClient"]["checksum"])).decode('ascii')
authentication_session_id = aux["parameters"]["authenticationSessionId"]

MitIDClient = BrowserClient(client_hash, authentication_session_id, session)
available_authenticators = MitIDClient.identify_as_user_and_get_available_authenticators(user_id)

print(f"Available authenticator: {available_authenticators}")

if args.method == "TOKEN":
    token_digits = input("Please input the 6 digits from your code token\n").strip()
    MitIDClient.authenticate_with_token(token_digits)

    password = input("Please input your password\n").strip()
    MitIDClient.authenticate_with_password(password)
elif args.method == "APP":
    MitIDClient.authenticate_with_app()
else:
    raise Exception(f"Unknown authenticator method {args.method}")

authorization_code = MitIDClient.finalize_authentication_and_get_authorization_code()

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