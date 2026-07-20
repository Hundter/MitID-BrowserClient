# Script for https://www.nordnet.dk/logind
import requests, json, base64, sys, string, secrets, uuid, getpass
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup
sys.path.append("..")
sys.path.append(".")
from BrowserClient.Helpers import get_authentication_code, process_args, get_default_args

def nordnet_login(user_id, password='', method="APP", proxy=None):
    nordnet_session = requests.Session()
    if proxy:
        nordnet_session.proxies.update({"http": f"socks5://{proxy}", "https": f"socks5://{proxy}" })

    # First part of Nordnet procedure
    nem_login_state = uuid.uuid4()
    digits = string.digits
    form_digits = ''.join(secrets.choice(digits) for i in range(29))

    login_url = f"https://id.signicat.com/oidc/authorize?client_id=prod.nordnet.dk.8x&response_type=code&redirect_uri=https://www.nordnet.dk/login&scope=openid signicat.national_id&acr_values=urn:signicat:oidc:method:mitid-cpr&state=NEXT_OIDC_STATE_{nem_login_state}"

    request = nordnet_session.get(login_url)
    if request.status_code != 200:
        msg = f"\n  Failed Nordnet session.get attempt:\n"\
              f"    Status code: {request.status_code}\n"\
              f"    Reason: {request.reason}\n"\
              f"    Content: {request.content}"
        raise Exception(msg)

    soup = BeautifulSoup(request.text, 'lxml')
    next = soup.div['data-index-url']

    request = nordnet_session.get(next)
    if request.status_code != 200:
        msg = f"\n  Failed Nordnet session.get attempt:\n"\
              f"    Status code: {request.status_code}\n"\
              f"    Reason: {request.reason}\n"\
              f"    Content: {request.content}"
        raise Exception(msg)

    soup = BeautifulSoup(request.text, 'lxml')

    request = nordnet_session.post(soup.div.next['data-base-url']+soup.div.next['data-init-auth-path'])
    if request.status_code != 200:
        msg = f"\n  Failed Nordnet session.post attempt:\n"\
              f"    Status code: {request.status_code}\n"\
              f"    Reason: {request.reason}\n"\
              f"    Content: {request.content}"
        raise Exception(msg)

    # MitID procedure
    aux = json.loads(base64.b64decode(request.json()["aux"]))
    authorization_code = get_authentication_code(nordnet_session, aux, method, user_id, password)
    print(f"Your MitID authorization code was ({authorization_code})")

    # Second part of Nordnet procedure
    payload = f'''-----------------------------{form_digits}\r\nContent-Disposition: form-data; name="authCode"\r\n\r\n{authorization_code}\r\n-----------------------------{form_digits}--\r\n'''
    headers = {'Content-Type': f'multipart/form-data; boundary=---------------------------{form_digits}'}

    request = nordnet_session.post(soup.div.next['data-base-url']+soup.div.next['data-auth-code-path'], data=payload, headers=headers)
    if request.status_code != 200:
        msg = f"\n  Failed Nordnet session.post attempt:\n"\
              f"    Status code: {request.status_code}\n"\
              f"    Reason: {request.reason}\n"\
              f"    Content: {request.content}"
        raise Exception(msg)

    request = nordnet_session.get(soup.div.next['data-base-url']+soup.div.next['data-finalize-auth-path'])
    if request.status_code != 200:
        msg = f"\n  Failed Nordnet session.get attempt:\n"\
              f"    Status code: {request.status_code}\n"\
              f"    Reason: {request.reason}\n"\
              f"    Content: {request.content}"
        raise Exception(msg)

    # Since the summer of 2026, Nordnet sometimes shows an extra page after the
    # MitID approval, asking for your CPR number. The page is a small app that
    # sends the number to its own "verify" address, so we do the same here.
    if urlparse(request.url).path.endswith('/cpr'):
        cpr_soup = BeautifulSoup(request.text, 'lxml')
        cpr_page = cpr_soup.find(id='cpr-form')
        cpr_base_url = cpr_page['data-base-url']
        # The input is hidden and the number is only sent to the mitid.dk page,
        # never saved anywhere.
        cpr = getpass.getpass('Enter your CPR number (10 digits, input is hidden): ').replace('-', '').strip()
        # Send the number the same way the page's own JavaScript does: as a
        # single "cpr" form field to the verify address.
        request = nordnet_session.post(cpr_base_url + cpr_page.get('data-verify-path', 'api/verify'), files={'cpr': (None, cpr)})
        if request.status_code != 200:
            msg = f"\n  Failed Nordnet CPR verify attempt:\n"\
                  f"    Status code: {request.status_code}\n"\
                  f"    Reason: {request.reason}\n"\
                  f"    Content: {request.content}"
            raise Exception(msg)
        cpr_answer = request.json()
        if not cpr_answer.get('success'):
            # Careful here: the page only allows a few wrong attempts before it
            # locks, so we show how many are left instead of retrying blindly.
            raise Exception(f"Signicat did not accept the CPR number (remaining attempts: {cpr_answer.get('remainingAttempts')})")
        # With the CPR number accepted we continue to the final address, which
        # sends us onwards with the login code.
        request = nordnet_session.get(cpr_base_url + cpr_page.get('data-finalize-cpr-path', 'finalizeCpr'))
        if request.status_code != 200:
            msg = f"\n  Failed Nordnet CPR finalize attempt:\n"\
                  f"    Status code: {request.status_code}\n"\
                  f"    Reason: {request.reason}\n"\
                  f"    Content: {request.content}"
            raise Exception(msg)

    # The CPR step adds an extra mitid.dk stop on the way, and that stop has
    # its own "code" value in the address. Nordnet only accepts the code that
    # belongs to nordnet.dk, so we look through all the addresses we were sent
    # through and prefer the one on nordnet.dk instead of just taking the first.
    code = None
    for visited_url in [earlier.url for earlier in request.history] + [request.url]:
        found = parse_qs(urlparse(visited_url).query).get('code')
        if found:
            code = found[0]
            if urlparse(visited_url).netloc == 'www.nordnet.dk':
                break
    if code is None:
        raise Exception('No login code found after the finalize/CPR step - the login flow may have changed again.')

    payload = {
        "authenticationProvider": "SIGNICAT",
        "countryCode":"DK", 
        "signicat": {
            "authorizationCode": code,
            "redirectUri":"https://www.nordnet.dk/login"
            }
        }

    nordnet_session.headers['client-id'] = 'NEXT'

    request = nordnet_session.post('https://www.nordnet.dk/nnxapi/authentication/v2/sessions', json=payload)
    if request.status_code != 200:
        msg = f"\n  Failed Nordnet session.post attempt:\n"\
              f"    Status code: {request.status_code}\n"\
              f"    Reason: {request.reason}\n"\
              f"    Content: {request.content}"
        raise Exception(msg)
    
    request = nordnet_session.post('https://www.nordnet.dk/api/2/authentication/nnx-session/login', json={})
    if request.status_code != 200:
        msg = f"\n  Failed Nordnet session.post attempt:\n"\
              f"    Status code: {request.status_code}\n"\
              f"    Reason: {request.reason}\n"\
              f"    Content: {request.content}"
        raise Exception(msg)

    nordnet_session.headers['ntag'] = request.headers['ntag']

    request = nordnet_session.post('https://www.nordnet.dk/nnxapi/authorization/v1/tokens', json={})
    if request.status_code not in (200,201):
        msg = f"\n  Failed Nordnet session.post attempt:\n"\
              f"    Status code: {request.status_code}\n"\
              f"    Reason: {request.reason}\n"\
              f"    Content: {request.content}"
        raise Exception(msg)

    bearer_token = request.json()['jwt']

    nntech_session = requests.Session()
    if proxy:
        nntech_session.proxies.update({"http": f"socks5://{proxy}", "https": f"socks5://{proxy}" })
    nntech_session.headers['authorization'] = f'Bearer {bearer_token}'
    nntech_session.headers['x-locale'] = 'da-DK'

    return nordnet_session, nntech_session

if __name__ == "__main__":
    argparser = get_default_args()
    args = argparser.parse_args()
    method, user_id, password, proxy = process_args(args)

    nordnet_session, nntech_session = nordnet_login(user_id, password, method, proxy)

    # Get accounts
    #accounts = nordnet_session.get('https://www.nordnet.dk/api/2/accounts')
    #print(accounts.json())

    # Get transactions
    # accids = (',').join([str(account['accid']) for account in accounts.json()])
    # fromdate = '2013-01-01'
    # todate = datetime.strftime(date.today(), '%Y-%m-%d')

    # Get JSON transactions
    # Limited to 800 results, the maximum may be larger
    # Change offset to get subsequent transactions
    # You can get total transactions by requesting: 
    # f'https://api.prod.nntech.io/transaction/transaction-and-notes/v1/transaction-summary?fromDate={fromdate}&toDate={todate}&accids={accids}&includeCancellations=false'
    # transactions_json = nntech_session.get(f'https://api.prod.nntech.io/transaction/transaction-and-notes/v1/transactions/page?fromDate={fromdate}&toDate={todate}&accids={accids}&offset=0&limit=800&sort=ACCOUNTING_DATE&sortOrder=DESC&includeCancellations=false')
    # print(transactions_json.json())

    # Get CSV transactions
    # Tab delimited. To change to semicolon-delimited, add:
    # csv_file = csv_file.replace('\t',';')
    #transactions_csv = nntech_session.get(f'https://api.prod.nntech.io/transaction/transaction-and-notes/v1/transactions/csv/filter?accids={accids}&fromDate={fromdate}&toDate={todate}&sort=ACCOUNTING_DATE&sortOrder=DESC&includeCancellations=false')
    #transactions_csv_bytes = transactions_csv.json()['bytes']
    #transactions_csv_decoded_bytes = base64.b64decode(transactions_csv_bytes)
    #csv_file = transactions_csv_decoded_bytes.decode('utf-16')
    #print(csv_file)