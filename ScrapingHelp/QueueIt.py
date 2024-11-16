# Provides functions that may helpful in dealing with sites that use Queue-it as middleware
import json, base64, re, requests, sys, time
from urllib.parse import urlparse, unquote, quote

challenge_checksum_regex = re.compile(r"challengeApiChecksumHash: '(.+?)',")
challenge_reason_regex = re.compile(r"challengesIssuedByReason: ([0-9]+?),")
challenge_customer_regex = re.compile(r"customerId: '(.+?)',")
challenge_eventid_regex = re.compile(r"eventId: '(.+?)',")
challenge_botdetect_host_regex = re.compile(r"botDetectHost: '(.+?)',")
challenge_inqueue_url_regex = re.compile(r"inqueueUrl: '(.+?)',")


def bypass_botdetect(session : requests.Session, url : str, params = {}):
    request = session.get(url, params=params)
    if not urlparse(request.url).path.startswith("/softblock/"):
        return request

    print("Hit Queue-it botdetect captcha, attempting to bypass")

    challenge_checksum = challenge_checksum_regex.findall(request.text)[0]
    challenge_reason = challenge_reason_regex.findall(request.text)[0]
    challenge_customer = challenge_customer_regex.findall(request.text)[0]
    challenge_eventid = challenge_eventid_regex.findall(request.text)[0]
    challenge_botdetect_host = challenge_botdetect_host_regex.findall(request.text)[0]
    challenge_inqueue_url = unquote(challenge_inqueue_url_regex.findall(request.text)[0])

    challenge_headers = {
        "X-Queueit-Challange-Customerid": challenge_customer,
        "X-Queueit-Challange-Eventid": challenge_eventid,
        "X-Queueit-Challange-Hash": challenge_checksum,
        "X-Queueit-Challange-Reason": challenge_reason
    }
    while True:
        challenge_sessionid_url = ""
        tries = 1
        while True:
            request = session.post(f"https://{challenge_botdetect_host}/challengeapi/queueitcaptcha/challenge/da-dk{challenge_sessionid_url}", headers=challenge_headers)
            if request.status_code != 200:
                print(f"Could not get challenge on try number {tries}")
                if request.json()["detail"] == "AllTriesUsed":
                    break
                else:
                    print(request.json())
                    print("Unknown error occured while tring to bypass Queue-it botdetect")
                    sys.exit(0)
            challenge_timer = time.time()
            challenge_details = request.json()["challengeDetails"]
            challenge_sessionid = request.json()["sessionId"]
            challenge_sessionid_url = f"/{challenge_sessionid}"

            image_base64 = request.json()["imageBase64"]

            # Import PaddleOCR here, as the import is slow and should only be done if strictly necessary
            from paddleocr import PaddleOCR
            ocr = PaddleOCR(lang='en', show_log=False)
            result = ocr.ocr(base64.b64decode(image_base64), det=False, cls=False)
            challenge_solution = result[0][0][0].replace(" ", "")
            if not challenge_solution:
                challenge_solution = ""
            else:
                challenge_solution = challenge_solution.splitlines()[0].strip()

            challenge_response = {
                "challengeDetails": challenge_details,
                "challengeType": "botdetect",
                "customerId": challenge_customer,
                "eventId": challenge_eventid,
                "sessionId": challenge_sessionid,
                "solution": challenge_solution,
                "version": 6,
                "stats": {
                    "userAgent": session.headers["User-Agent"],
                    "screen": "1920 x 1080",
                    "browser": "EZ OCR",
                    "browserVersion": "13.37",
                    "isMobile": False,
                    "os": "Windows",
                    "osVersion": "10",
                    "cookiesEnabled": True,
                    "tries": tries,
                    "duration": round((time.time() - challenge_timer) * 1000)
                }
            }
            request = session.post(f"https://{challenge_botdetect_host}/challengeapi/verify", json=challenge_response)
            if request.json()["isVerified"]:
                print(f"Defeated the captcha on try number {tries}, robots are better than humans")
                verification_string = quote(json.dumps(request.json()["sessionInfo"]))
                request = session.get(f"https://{challenge_botdetect_host}{challenge_inqueue_url}&scv={verification_string}", json=challenge_response)
                return request
            else:
                print("Messed up the captcha, trying again")
                tries += 1
