import requests, binascii, json, base64, time, hashlib, jwt, hmac, argparse, sys
from urllib.parse import parse_qs, urlparse
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from CustomSRP import CustomSRP, bytes_to_hex, hex_to_bytes

parser = argparse.ArgumentParser(description="argparser")
parser.add_argument('--user', help='Your MitID username. For example: "GenericDanishCitizen"', required=True)
parser.add_argument('--proxy', help='An optional socks5 proxy to use for all communication with MitID', required=False)
parser.add_argument('--method', choices=['APP', 'TOKEN'], help='Which method to use when logging in to MitID, default APP', default='APP', required=False)
args = parser.parse_args()

user_id = args.user

s = requests.Session()

if args.proxy:
    s.proxies.update({"http": f"socks5://{args.proxy}", "https": f"socks5://{args.proxy}" })

"""
This is an example of what an initial URL might compose of, specifically this is mitid.dk's login url
https://www.mitid.dk/administration/oauth/authorize?
    response_type=code&
    client_id=d49gtfqbkr9j1v60lr554ltk8q6e7tlt&
    exchangeUrl=%2Fadministration%2Foauth%2Fexchange&
    language=EN&
    redirect_uri=https%3A%2F%2Fwww.mitid.dk%2Fservice-provider%2Flogin&
    requestedAal=SUBSTANTIAL&
    requestedLoa=&
    serviceProvider=SELF_SERVICE_PORTAL&
    serviceProviderId=9d09e4fb-a05e-4cd2-832f-efa1dd245e9b&
    serviceProviderReference=Self%20Service%20Login&
    ssoGroupId=ceaef5ba-4f9e-4c9d-9814-3bd9e7ecb2e1&
    requestedAttributes=&
    referenceText=Log%20on%20at%20MitID.dk%20to%20view%20or%20change%20your%20MitID%20profile&
    roleNotAllowed=undefined
"""

# This URL will be different for each MitID site, would be nice to generalize this somehow
r = s.get("https://www.mitid.dk/administration/oauth/authorize?response_type=code&serviceProvider=SELF_SERVICE_PORTAL&serviceProviderReference=Self Service Login&serviceProviderId=9d09e4fb-a05e-4cd2-832f-efa1dd245e9b&requestedAttributes=IDENTITY_NAME&exchangeUrl=/administration/oauth/exchange&redirect_uri=https://www.mitid.dk/service-provider/login&ssoGroupId=ceaef5ba-4f9e-4c9d-9814-3bd9e7ecb2e1&requestedAal=SUBSTANTIAL&language=EN&client_id=d49gtfqbkr9j1v60lr554ltk8q6e7tlt")
if r.status_code != 200:
    print(f"Failed session setup attempt, status code {r.status_code}")
    raise Exception(r.content)


r = s.post("https://www.mitid.dk/mitid-administrative-idp/v1/initialize")

if r.status_code != 200 or "aux" not in r.json():
    print(f"Bad response for https://www.mitid.dk/mitid-administrative-idp/v1/initialize, could not find aux, or status code bad: {r.status_code}")
    raise Exception(r.content)

client_hash_option = binascii.hexlify(base64.b64decode(json.loads(base64.b64decode(r.json()["aux"]))["coreClient"]["checksum"])).decode('ascii')
auth_session_id = json.loads(base64.b64decode(r.json()["aux"]))["parameters"]["authenticationSessionId"]

r = s.get(f"https://www.mitid.dk/mitid-core-client-backend/v1/authentication-sessions/{auth_session_id}")
if r.status_code != 200:
    print(f"Failed to get authentication session, status code {r.status_code}")
    raise Exception(r.content)

r = r.json()
# This is all needed for proofs later on
broker_security_context = r["brokerSecurityContext"]
service_provider_name = r["serviceProviderName"]
reference_text_header = r["referenceTextHeader"]
reference_text_body = r["referenceTextBody"]


r = s.put(f"https://www.mitid.dk/mitid-core-client-backend/v1/authentication-sessions/{auth_session_id}", json={"identityClaim": user_id})

if r.status_code != 200:
    if r.status_code == 400 and r.json()["errorCode"] == "control.identity_not_found":
        raise Exception(f"User '{user_id}' does not exist.")

    if r.status_code == 400 and r.json()["errorCode"] == "control.authentication_session_not_found":
        print("Authentication session not found")
        raise Exception(r.content)

    raise Exception(r.content)

r = s.post(f"https://www.mitid.dk/mitid-core-client-backend/v2/authentication-sessions/{auth_session_id}/next", json={"combinationId": ""})

if r.status_code != 200:
    raise Exception(r.content)

if r.status_code == 200 and r.json()["errors"] and len(r.json()["errors"]) > 0 and r.json()["errors"][0]["errorCode"] == "control.authenticator_cannot_be_started":
    error_text = r.json()["errors"][0]["userMessage"]["text"]["text"]
    raise Exception(f"Could not start authenticator, got the following error text: {error_text}")

r = r.json()
authenticator_type = r["nextAuthenticator"]["authenticatorType"]
auth_flow_key = r["nextAuthenticator"]["authenticatorSessionFlowKey"]
eafe_hash = r["nextAuthenticator"]["eafeHash"]
auth_session_id_spec = r["nextAuthenticator"]["authenticatorSessionId"]

if authenticator_type != args.method:
    desiredCombinationId = "S1" if args.method == "TOKEN" else "S3"
    r = s.post(f"https://www.mitid.dk/mitid-core-client-backend/v2/authentication-sessions/{auth_session_id}/next", json={ "combinationId": desiredCombinationId })
    print(r.content)
    r = r.json()
    authenticator_type = r["nextAuthenticator"]["authenticatorType"]
    auth_flow_key = r["nextAuthenticator"]["authenticatorSessionFlowKey"]
    eafe_hash = r["nextAuthenticator"]["eafeHash"]
    auth_session_id_spec = r["nextAuthenticator"]["authenticatorSessionId"]

if authenticator_type == "TOKEN":
    code_token = input("Please input the 6 digits from your code token\n").strip()

    t1 = time.time()
    SRP = CustomSRP()
    A = SRP.SRPStage1()
    t1 = time.time() - t1

    r = s.post(f"https://www.mitid.dk/mitid-code-token-auth/v1/authenticator-sessions/{auth_session_id_spec}/codetoken-init", json={"randomA": {"value": A}})
    if r.status_code != 200:
        print(f"Failed to init TOTP code protocol, status code {r.status_code}")
        raise Exception(r.content)

    t2 = time.time()
    # pbkdfSalt is not actually used even though we receive it, what the hell are they doing here?
    # This seems like schlock
    #pbkdfSalt = r.json()["pbkdf2Salt"]["value"]
    srpSalt = r.json()["srpSalt"]["value"]
    randomB = r.json()["randomB"]["value"]

    m1 = SRP.SRPStage3(srpSalt, randomB, binascii.hexlify(auth_flow_key.encode("utf-8")).decode("utf-8"), auth_session_id_spec)

    flow_value_proof_step_1 = auth_session_id_spec+","+auth_flow_key+","+client_hash_option+","+eafe_hash+","+hashlib.sha256(broker_security_context.encode("utf8")).hexdigest()+","+base64.b64encode((reference_text_header.encode('utf8'))).decode("ascii")+","+base64.b64encode((reference_text_body.encode('utf8'))).decode("ascii")+","+base64.b64encode((service_provider_name.encode('utf8'))).decode("ascii")
    m = hashlib.sha256()
    up = "OTP" + code_token + binascii.hexlify(SRP.K_bits).decode("ascii")
    m.update(up.encode("utf8"))
    flow_value_proof_step_2 = m.digest()

    flow_value_proof = hmac.new(flow_value_proof_step_2, flow_value_proof_step_1.encode('utf8'), hashlib.sha256).hexdigest()

    t2 = time.time() - t2
    front_end_processing_time = int((t1 + t2) * 1000)

    response = {"m1": {"value": m1}, "flowValueProof": {"value": flow_value_proof}, "frontEndProcessingTime": front_end_processing_time}

    r = s.post(f"https://www.mitid.dk/mitid-code-token-auth/v1/authenticator-sessions/{auth_session_id_spec}/codetoken-prove", json=response)
    if r.status_code != 204:
        print(f"Failed to submit TOTP code, status code {r.status_code}")
        raise Exception(r.content)

    r = s.post(f"https://www.mitid.dk/mitid-core-client-backend/v2/authentication-sessions/{auth_session_id}/next", json={"combinationId": ""})

    if r.status_code != 200:
        print(f"Failed to prove TOTP code, status code {r.status_code}")
        raise Exception(r.content)

    if r.status_code == 200 and r.json()["errors"] and len(r.json()["errors"]) > 0 and r.json()["errors"][0]["errorCode"] == "TOTP_INVALID":
        error_text = r.json()["errors"][0]["message"]
        raise Exception(f"Could log in with the provided TOTP code, got the following message: {error_text}")

    r = r.json()
    authenticator_type = r["nextAuthenticator"]["authenticatorType"]
    auth_flow_key = r["nextAuthenticator"]["authenticatorSessionFlowKey"]
    eafe_hash = r["nextAuthenticator"]["eafeHash"]
    auth_session_id_spec = r["nextAuthenticator"]["authenticatorSessionId"]

    password = input("TOTP code accepted, Please input password\n").strip()

    t1 = time.time()
    SRP = CustomSRP()
    A = SRP.SRPStage1()
    t1 = time.time() - t1

    r = s.post(f"https://www.mitid.dk/mitid-password-auth/v1/authenticator-sessions/{auth_session_id_spec}/init", json={"randomA": {"value": A}})
    print(r.status_code)
    print(r.content)
    if r.status_code != 200:
        print(f"Failed to init TOTP code protocol, status code {r.status_code}")
        raise Exception(r.content)

    t2 = time.time()
    pbkdfSalt = r.json()["pbkdf2Salt"]["value"]
    srpSalt = r.json()["srpSalt"]["value"]
    randomB = r.json()["randomB"]["value"]

    password = bytes_to_hex(PBKDF2(password, hex_to_bytes(pbkdfSalt), 32, count=20000, hmac_hash_module=SHA256))

    m1 = SRP.SRPStage3(srpSalt, randomB, password, auth_session_id_spec)

    flow_value_proof_step_1 = auth_session_id_spec+","+auth_flow_key+","+client_hash_option+","+eafe_hash+","+hashlib.sha256(broker_security_context.encode("utf8")).hexdigest()+","+base64.b64encode((reference_text_header.encode('utf8'))).decode("ascii")+","+base64.b64encode((reference_text_body.encode('utf8'))).decode("ascii")+","+base64.b64encode((service_provider_name.encode('utf8'))).decode("ascii")
    m = hashlib.sha256()
    up = "flowValues" + binascii.hexlify(SRP.K_bits).decode("ascii")
    m.update(up.encode("utf8"))
    flow_value_proof_step_2 = m.digest()

    flow_value_proof = hmac.new(flow_value_proof_step_2, flow_value_proof_step_1.encode('utf8'), hashlib.sha256).hexdigest()

    t2 = time.time() - t2
    front_end_processing_time = int((t1 + t2) * 1000)

    response = {"m1": {"value": m1}, "flowValueProof": {"value": flow_value_proof}, "frontEndProcessingTime": front_end_processing_time}

    r = s.post(f"https://www.mitid.dk/mitid-password-auth/v1/authenticator-sessions/{auth_session_id_spec}/password-prove", json=response)
    print(r.status_code)
    print(r.content)
    if r.status_code != 204:
        print(f"Failed to submit password, status code {r.status_code}")
        raise Exception(r.content)
elif authenticator_type == "APP":
    r = s.post(f"https://www.mitid.dk/mitid-code-app-auth/v1/authenticator-sessions/web/{auth_session_id_spec}/init-auth", json={})

    if r.status_code != 200:
        print(f"Got status code: {r.status_code}")
        raise Exception(r.content)

    r = r.json()
    if "errorCode" in r and r["errorCode"] == "auth.codeapp.authentication.parallel_sessions_detected":
        print("Parallel sessions detected")
        raise Exception(r)

    poll_url = r["pollUrl"]
    ticket = r["ticket"]

    print("Login request has been made, open your MitID app now")
    while True:
        r = s.post(poll_url, json={"ticket": ticket})

        if r.status_code == 200 and r.json()["status"] == "timeout":
            continue

        if r.status_code == 200 and r.json()["status"] == "channel_validation_otp":
            print(f"Please use the following OTP code in the app: {r.json()['channelBindingValue']}")
            continue

        if r.status_code == 200 and r.json()["status"] == "channel_verified":
            print("The OTP/QR code has been verified, now waiting user to approve login")
            continue

        if not (r.status_code == 200 and r.json()["status"] == "OK" and r.json()["confirmation"] == True):
            print("Login request was not accepted")
            raise Exception(r.content)

        break

    response = r.json()["payload"]["response"]
    response_signature = r.json()["payload"]["responseSignature"]

    t1 = time.time()
    SRP = CustomSRP()
    A = SRP.SRPStage1()
    t1 = time.time() - t1

    r = s.post("https://www.mitid.dk/mitid-code-app-auth/v1/authenticator-sessions/web/"+auth_session_id_spec+"/init", json={"randomA": {"value": A}})
    print(r.status_code)
    #print(r.content)

    t2 = time.time()
    srpSalt = r.json()["srpSalt"]["value"]
    randomB = r.json()["randomB"]["value"]

    m = hashlib.sha256()
    m.update(base64.b64decode(response) + auth_flow_key.encode("utf8"))
    password = m.hexdigest()

    m1 = SRP.SRPStage3(srpSalt, randomB, password, auth_session_id_spec)

    m = hashlib.sha256()
    m.update(broker_security_context.encode("utf8"))
    broker_security_context = m.hexdigest()
    flow_value_proof_step_1 = auth_session_id_spec+","+auth_flow_key+","+client_hash_option+","+eafe_hash+","+broker_security_context+","+base64.b64encode((reference_text_header.encode('utf8'))).decode("ascii")+","+base64.b64encode((reference_text_body.encode('utf8'))).decode("ascii")+","+base64.b64encode((service_provider_name.encode('utf8'))).decode("ascii")
    m = hashlib.sha256()
    up = "flowValues" + binascii.hexlify(SRP.K_bits).decode("ascii")
    m.update(up.encode("utf8"))
    flow_value_proof_step_2 = m.digest()

    flow_value_proof = hmac.new(flow_value_proof_step_2, flow_value_proof_step_1.encode('utf8'), hashlib.sha256).hexdigest()

    response = {"m1": {"value": m1}, "flowValueProof": {"value": flow_value_proof}}

    t2 = time.time() - t2
    r = s.post("https://www.mitid.dk/mitid-code-app-auth/v1/authenticator-sessions/web/"+auth_session_id_spec+"/prove", json=response)
    print(r.status_code)
    t3 = time.time()
    m2 = r.json()["m2"]["value"]
    auth_enc = SRP.AuthEnc(response_signature)
    t3 = time.time() - t3

    front_end_processing_time = int((t1 + t2 + t3) * 1000)

    r = s.post("https://www.mitid.dk/mitid-code-app-auth/v1/authenticator-sessions/web/"+auth_session_id_spec+"/verify", json={"encAuth": auth_enc, "frontEndProcessingTime": front_end_processing_time})
    print(r.status_code)

r = s.post(f"https://www.mitid.dk/mitid-core-client-backend/v2/authentication-sessions/{auth_session_id}/next", json={"combinationId":""})
print(r.status_code)
print(r.content)
next_session_id = r.json()["nextSessionId"]

r = s.put("https://www.mitid.dk/mitid-core-client-backend/v1/authentication-sessions/"+next_session_id+"/finalization")
print(r.status_code)

authorization_code = r.json()["authorizationCode"]

r = s.post("https://www.mitid.dk/mitid-administrative-idp/login", params={"AuthCode": authorization_code})
parsed_url = parse_qs(urlparse(r.url).query)

authorization_code_2 = parsed_url["code"][0]
state = parsed_url["state"][0]

r = s.get("https://www.mitid.dk/administration/oauth/exchange?authorization-code="+authorization_code_2+"&service-provider=SELF_SERVICE_PORTAL&state="+state)
print(r.status_code)

access_token = r.json()["access_token"]
access_token_payload = jwt.decode(access_token, options={"verify_signature": False})
uuid = access_token_payload["sub"]

r = s.get("https://www.mitid.dk/administration/v6/identities/"+uuid, headers={"Authorization": "Bearer "+access_token})
print(r.status_code)
print(r.content)

print(f"Your access token was: '{access_token}'")