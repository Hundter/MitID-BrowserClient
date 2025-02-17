import requests, time, hashlib, base64, hmac, qrcode, imageio, tempfile
from BrowserClient.CustomSRP import CustomSRP, hex_to_bytes, bytes_to_hex, pad

class BrowserClient():
    def __init__(self, client_hash: str, authentication_session_id: str, requests_session = requests.Session()):
        self.session = requests_session

        self.client_hash = client_hash
        self.authentication_session_id = authentication_session_id

        r = self.session.get(f"https://www.mitid.dk/mitid-core-client-backend/v1/authentication-sessions/{authentication_session_id}")
        if r.status_code != 200:
            print(f"Failed to get authentication session ({authentication_session_id}), status code {r.status_code}")
            raise Exception(r.content)
        
        r = r.json()
        # This is all needed for flowValueProofs later on
        self.broker_security_context = r["brokerSecurityContext"]
        self.service_provider_name = r["serviceProviderName"]
        self.reference_text_header = r["referenceTextHeader"]
        self.reference_text_body = r["referenceTextBody"]
        print(f"Beginning login session for {self.service_provider_name}:")
        print(f"{self.reference_text_header}")
        print(f"{self.reference_text_body}")

    def __convert_human_authenticator_name_to_combination_id(self, authenticator_name):
        match authenticator_name:
            case "APP":
                return "S3"
            case "TOKEN":
                return "S1"
            case _:
                raise Exception(f"No such authenticator name ({authenticator_name})")
    
    def __convert_combination_id_to_human_authenticator_name(self, combination_id):
        match combination_id:
            case "S3":
                return "APP"
            case "S1":
                return "TOKEN"
            case _:
                raise Exception(f"No such combination ID ({combination_id})")
    
    def identify_as_user_and_get_available_authenticators(self, user_id):
        self.user_id = user_id
        r = self.session.put(f"https://www.mitid.dk/mitid-core-client-backend/v1/authentication-sessions/{self.authentication_session_id}", json={"identityClaim": user_id})

        if r.status_code != 200:
            print(f"Received status code ({r.status_code}) while attempting to identify as user ({user_id})")
            if r.status_code == 400 and r.json()["errorCode"] == "control.identity_not_found":
                print(f"User '{user_id}' does not exist.")
                raise Exception(r.content)

            if r.status_code == 400 and r.json()["errorCode"] == "control.authentication_session_not_found":
                print("Authentication session not found")
                raise Exception(r.content)

            raise Exception(r.content)
        
        r = self.session.post(f"https://www.mitid.dk/mitid-core-client-backend/v2/authentication-sessions/{self.authentication_session_id}/next", json={"combinationId": ""})

        if r.status_code != 200:
            print(f"Received status code ({r.status_code}) while attempting to get authenticators for user ({user_id})")
            raise Exception(r.content)

        r = r.json()
        if r["errors"] and len(r["errors"]) > 0 and r["errors"][0]["errorCode"] == "control.authenticator_cannot_be_started":
            error_text = r["errors"][0]["userMessage"]["text"]["text"]
            print(f"Could not get authenticators, got the following error text: {error_text}")
            raise Exception(r)
        
        self.current_authenticator_type = r["nextAuthenticator"]["authenticatorType"]
        self.current_authenticator_session_flow_key = r["nextAuthenticator"]["authenticatorSessionFlowKey"]
        self.current_authenticator_eafe_hash = r["nextAuthenticator"]["eafeHash"]
        self.current_authenticator_session_id = r["nextAuthenticator"]["authenticatorSessionId"]

        available_combinations = r["combinations"]
        available_authenticators = {}
        for available_combination in available_combinations:
            available_authenticators[self.__convert_combination_id_to_human_authenticator_name(available_combination["id"])] = available_combination["combinationItems"][0]["name"]

        return available_authenticators
    
    def __create_flow_value_proof(self):
        hashed_broker_security_context = hashlib.sha256(self.broker_security_context.encode("utf8")).hexdigest()
        base64_reference_text_header = base64.b64encode((self.reference_text_header.encode('utf8'))).decode("ascii")
        base64_reference_text_body = base64.b64encode((self.reference_text_body.encode('utf8'))).decode("ascii")
        base64_service_provider_name = base64.b64encode((self.service_provider_name.encode('utf8'))).decode("ascii")
        return f"{self.current_authenticator_session_id},{self.current_authenticator_session_flow_key},{self.client_hash},{self.current_authenticator_eafe_hash},{hashed_broker_security_context},{base64_reference_text_header},{base64_reference_text_body},{base64_service_provider_name}".encode("utf-8")
    
    def __select_authenticator(self, authenticator_type: str):
        if authenticator_type == self.current_authenticator_type:
            return
        
        combination_id = self.__convert_human_authenticator_name_to_combination_id(authenticator_type)

        r = self.session.post(f"https://www.mitid.dk/mitid-core-client-backend/v2/authentication-sessions/{self.authentication_session_id}/next", json={"combinationId": combination_id})
        
        if r.status_code != 200:
            print(f"Received status code ({r.status_code}) while attempting to get authenticators for user ({self.user_id})")
            raise Exception(r.content)

        r = r.json()
        if r["errors"] and len(r["errors"]) > 0 and r["errors"][0]["errorCode"] == "control.authenticator_cannot_be_started":
            error_text = r["errors"][0]["userMessage"]["text"]["text"]
            print(f"Could not get authenticators, got the following error text: {error_text}")
            raise Exception(r.content)
        
        self.current_authenticator_type = r["nextAuthenticator"]["authenticatorType"]
        self.current_authenticator_session_flow_key = r["nextAuthenticator"]["authenticatorSessionFlowKey"]
        self.current_authenticator_eafe_hash = r["nextAuthenticator"]["eafeHash"]
        self.current_authenticator_session_id = r["nextAuthenticator"]["authenticatorSessionId"]

        if self.current_authenticator_type != authenticator_type:
            raise Exception(f"Was not able to choose the desired authenticator ({authenticator_type}), instead we received ({self.current_authenticator_type})")

    def authenticate_with_token(self, token_digits: str):
        self.__select_authenticator("TOKEN")

        timer_1 = time.time()
        SRP = CustomSRP()
        A = SRP.SRPStage1()
        timer_1 = time.time() - timer_1

        r = self.session.post(f"https://www.mitid.dk/mitid-code-token-auth/v1/authenticator-sessions/{self.current_authenticator_session_id}/codetoken-init", json={"randomA": {"value": A}})
        if r.status_code != 200:
            print(f"Failed to init TOTP code protocol, status code {r.status_code}")
            raise Exception(r.content)
        
        timer_2 = time.time()
        r = r.json()
        # pbkdfSalt is not actually used even though we receive it, what the hell are they doing here?
        # This seems like schlock
        #pbkdfSalt = r["pbkdf2Salt"]["value"]
        srpSalt = r["srpSalt"]["value"]
        randomB = r["randomB"]["value"]

        m1 = SRP.SRPStage3(srpSalt, randomB, bytes_to_hex(self.current_authenticator_session_flow_key.encode("utf-8")), self.current_authenticator_session_id)

        unhashed_flow_value_proof = self.__create_flow_value_proof()
        m = hashlib.sha256()
        unhashed_flow_value_proof_key = "OTP" + token_digits + bytes_to_hex(SRP.K_bits)
        m.update(unhashed_flow_value_proof_key.encode("utf8"))
        flow_value_proof_key = m.digest()

        flow_value_proof = hmac.new(flow_value_proof_key, unhashed_flow_value_proof, hashlib.sha256).hexdigest()

        timer_2 = time.time() - timer_2
        front_end_processing_time = int((timer_1 + timer_2) * 1000)

        r = self.session.post(f"https://www.mitid.dk/mitid-code-token-auth/v1/authenticator-sessions/{self.current_authenticator_session_id}/codetoken-prove", json={"m1": {"value": m1}, "flowValueProof": {"value": flow_value_proof}, "frontEndProcessingTime": front_end_processing_time})
        if r.status_code != 204:
            print(f"Failed to submit TOTP code, status code {r.status_code}")
            raise Exception(r.content)

        r = self.session.post(f"https://www.mitid.dk/mitid-core-client-backend/v2/authentication-sessions/{self.authentication_session_id}/next", json={"combinationId": ""})
        if r.status_code != 200:
            print(f"Failed to prove TOTP code, status code {r.status_code}")
            raise Exception(r.content)

        if r.json()["errors"] and len(r.json()["errors"]) > 0 and r.json()["errors"][0]["errorCode"] == "TOTP_INVALID":
            error_text = r.json()["errors"][0]["message"]
            print(f"Could not log in with the provided TOTP code, got the following message: {error_text}")
            raise Exception(r.content)

        r = r.json()
        if "nextAuthenticator" not in r or "authenticatorType" not in r["nextAuthenticator"] or r["nextAuthenticator"]["authenticatorType"] != "PASSWORD":
            print(f"Ran into an unexpected situation, was expecting to be asked for password after TOTP but got the following response")
            raise Exception(r.content)
        
        self.current_authenticator_type = r["nextAuthenticator"]["authenticatorType"]
        self.current_authenticator_session_flow_key = r["nextAuthenticator"]["authenticatorSessionFlowKey"]
        self.current_authenticator_eafe_hash = r["nextAuthenticator"]["eafeHash"]
        self.current_authenticator_session_id = r["nextAuthenticator"]["authenticatorSessionId"]
        print("Token code accepted, you now need to validate your password")

    def authenticate_with_password(self, password: str):
        if self.current_authenticator_type != "PASSWORD":
            raise Exception(f"You cannot authenticate with password before completing authentication with token code, the current authenticator type was ({self.current_authenticator_type})")
        
        timer_1 = time.time()
        SRP = CustomSRP()
        A = SRP.SRPStage1()
        timer_1 = time.time() - timer_1

        r = self.session.post(f"https://www.mitid.dk/mitid-password-auth/v1/authenticator-sessions/{self.current_authenticator_session_id}/init", json={"randomA": {"value": A}})
        if r.status_code != 200:
            print(f"Failed to init password protocol, status code {r.status_code}")
            raise Exception(r.content)

        timer_2 = time.time()
        r = r.json()
        pbkdfSalt = r["pbkdf2Salt"]["value"]
        srpSalt = r["srpSalt"]["value"]
        randomB = r["randomB"]["value"]

        password = hashlib.pbkdf2_hmac('sha256', password.encode("utf-8"), hex_to_bytes(pbkdfSalt), 20000, 32).hex()

        m1 = SRP.SRPStage3(srpSalt, randomB, password, self.current_authenticator_session_id)

        unhashed_flow_value_proof = self.__create_flow_value_proof()
        m = hashlib.sha256()
        unhashed_flow_value_proof_key = "flowValues" + bytes_to_hex(SRP.K_bits)
        m.update(unhashed_flow_value_proof_key.encode("utf8"))
        flow_value_proof_key = m.digest()

        flow_value_proof = hmac.new(flow_value_proof_key, unhashed_flow_value_proof, hashlib.sha256).hexdigest()

        timer_2 = time.time() - timer_2
        front_end_processing_time = int((timer_1 + timer_2) * 1000)

        r = self.session.post(f"https://www.mitid.dk/mitid-password-auth/v1/authenticator-sessions/{self.current_authenticator_session_id}/password-prove", json={"m1": {"value": m1}, "flowValueProof": {"value": flow_value_proof}, "frontEndProcessingTime": front_end_processing_time})
        if r.status_code != 204:
            print(f"Failed to submit password, status code {r.status_code}")
            raise Exception(r.content)
        
        r = self.session.post(f"https://www.mitid.dk/mitid-core-client-backend/v2/authentication-sessions/{self.authentication_session_id}/next", json={"combinationId":""})
        if r.status_code != 200:
            print(f"Failed to prove password, status code {r.status_code}")
            raise Exception(r.content)
        
        r = r.json()
        if r["errors"] and len(r["errors"]) > 0:
            if r["errors"][0]["errorCode"] == "PASSWORD_INVALID":
                error_text = r["errors"][0]["message"]
                print(f"Could not log in with the provided password, got the following message: {error_text}")
                raise Exception(r)
            elif r["errors"][0]["errorCode"] == "core.psd2.error":
                error_text = r["errors"][0]["message"]
                print(f"Could not log in due to an error, probably due to a wrong password provided. Got the following message: {error_text}")
                raise Exception(r)
            else:
                error_text = r["errors"][0]["message"]
                print(f"Could not log in due to an unknown error, got the following message: {error_text}")
                raise Exception(r)
        
        self.finalization_authentication_session_id = r["nextSessionId"]
        print("Password was accepted, you can now finalize authentication and receive your authorization code")

    def authenticate_with_app(self):
        self.__select_authenticator("APP")

        r = self.session.post(f"https://www.mitid.dk/mitid-code-app-auth/v1/authenticator-sessions/web/{self.current_authenticator_session_id}/init-auth", json={})
        if r.status_code != 200:
            print(f"Failed to request app login, status code {r.status_code}")
            raise Exception(r.content)

        r = r.json()
        if "errorCode" in r and r["errorCode"] == "auth.codeapp.authentication.parallel_sessions_detected":
            print("Parallel app sessions detected, only a single app login session can be happening at any one time")
            raise Exception(r)

        poll_url = r["pollUrl"]
        ticket = r["ticket"]
        print("Login request has been made, open your MitID app now")
        gif_tmp_file = None
        while True:
            r = self.session.post(poll_url, json={"ticket": ticket})

            if r.status_code == 200 and r.json()["status"] == "timeout":
                continue

            if r.status_code == 200 and r.json()["status"] == "channel_validation_otp":
                print(f"Please use the following OTP code in the app: {r.json()['channelBindingValue']}")
                continue

            if r.status_code == 200 and r.json()["status"] == "channel_validation_tqr":
                qr_data = {
                    "v": 1,
                    "p": 1,
                    "t": 2,
                    "h": r.json()["channelBindingValue"][:int(len(r.json()["channelBindingValue"])/2)],
                    "uc": r.json()["updateCount"]
                }
                qr1 = qrcode.make(qr_data)

                qr_data["p"] = 2
                qr_data["h"] = r.json()["channelBindingValue"][int(len(r.json()["channelBindingValue"])/2):]
                qr2 = qrcode.make(qr_data)

                qr1_image = qr1.convert("RGB")
                qr2_image = qr2.convert("RGB")

                if gif_tmp_file is None:
                    gif_tmp_file = tempfile.NamedTemporaryFile(suffix=".gif")
                    print(f"Please open the QR code stored at '{gif_tmp_file.name}' and scan it in the app")
                else:
                    print("The QR code has been updated, please reload the QR code in your viewer")

                imageio.mimsave(gif_tmp_file.name, [qr1_image, qr2_image], loop=0, fps=1)
                continue

            if r.status_code == 200 and r.json()["status"] == "channel_verified":
                print("The OTP/QR code has been verified, now waiting user to approve login")
                continue

            if not (r.status_code == 200 and r.json()["status"] == "OK" and r.json()["confirmation"] == True):
                print("Login request was not accepted")
                raise Exception(r.content)

            break

        r = r.json()
        response = r["payload"]["response"]
        response_signature = r["payload"]["responseSignature"]

        timer_1 = time.time()
        SRP = CustomSRP()
        A = SRP.SRPStage1()
        timer_1 = time.time() - timer_1

        r = self.session.post(f"https://www.mitid.dk/mitid-code-app-auth/v1/authenticator-sessions/web/{self.current_authenticator_session_id}/init", json={"randomA": {"value": A}})
        if r.status_code != 200:
            print(f"Failed to init app protocol, status code {r.status_code}")
            raise Exception(r.content)

        timer_2 = time.time()
        srpSalt = r.json()["srpSalt"]["value"]
        randomB = r.json()["randomB"]["value"]

        m = hashlib.sha256()
        m.update(base64.b64decode(response) + self.current_authenticator_session_flow_key.encode("utf8"))
        password = m.hexdigest()

        m1 = SRP.SRPStage3(srpSalt, randomB, password, self.current_authenticator_session_id)

        unhashed_flow_value_proof = self.__create_flow_value_proof()
        m = hashlib.sha256()
        unhashed_flow_value_proof_key = "flowValues" + bytes_to_hex(SRP.K_bits)
        m.update(unhashed_flow_value_proof_key.encode("utf8"))
        flow_value_proof_key = m.digest()

        flow_value_proof = hmac.new(flow_value_proof_key, unhashed_flow_value_proof, hashlib.sha256).hexdigest()

        timer_2 = time.time() - timer_2
        
        r = self.session.post(f"https://www.mitid.dk/mitid-code-app-auth/v1/authenticator-sessions/web/{self.current_authenticator_session_id}/prove", json={"m1": {"value": m1}, "flowValueProof": {"value": flow_value_proof}})
        if r.status_code != 200:
            print(f"Failed to submit app response proof, status code {r.status_code}")
            raise Exception(r.content)
        
        timer_3 = time.time()
        m2 = r.json()["m2"]["value"]
        if not SRP.SRPStage5(m2):
            raise Exception("m2 could not be validated during proving of app response")
        auth_enc = base64.b64encode(SRP.AuthEnc(base64.b64decode(pad(response_signature)))).decode("ascii")
        timer_3 = time.time() - timer_3

        front_end_processing_time = int((timer_1 + timer_2 + timer_3) * 1000)

        r = self.session.post(f"https://www.mitid.dk/mitid-code-app-auth/v1/authenticator-sessions/web/{self.current_authenticator_session_id}/verify", json={"encAuth": auth_enc, "frontEndProcessingTime": front_end_processing_time})
        if r.status_code != 204:
            print(f"Failed to verify app response signature, status code {r.status_code}")
            raise Exception(r.content)

        r = self.session.post(f"https://www.mitid.dk/mitid-core-client-backend/v2/authentication-sessions/{self.authentication_session_id}/next", json={"combinationId":""})
        if r.status_code != 200:
            print(f"Failed to prove app login, status code {r.status_code}")
            raise Exception(r.content)
        
        r = r.json()
        if r["errors"] and len(r["errors"]) > 0:
            print(f"Could not prove the app login")
            raise Exception(r)

        self.finalization_authentication_session_id = r["nextSessionId"]
        print("App login was accepted, you can now finalize authentication and receive your authorization code")

    def finalize_authentication_and_get_authorization_code(self):
        if not self.finalization_authentication_session_id:
            raise Exception("No finalization session ID set, make sure you have completed an authentication flow.")
        
        r = self.session.put(f"https://www.mitid.dk/mitid-core-client-backend/v1/authentication-sessions/{self.finalization_authentication_session_id}/finalization")
        if r.status_code != 200:
            print(f"Failed to retrieve authorization code, status code {r.status_code}")
            raise Exception(r.content)

        return r.json()["authorizationCode"]