# Provides functions that may helpful in dealing with sites that use Queue-it as middleware
import json, base64, re, requests, sys, pytesseract, io, time
from urllib.parse import urlparse, unquote, quote
from PIL import Image

challenge_checksum_regex = re.compile(r"challengeApiChecksumHash: '(.+?)',")
challenge_reason_regex = re.compile(r"challengesIssuedByReason: ([0-9]+?),")
challenge_customer_regex = re.compile(r"customerId: '(.+?)',")
challenge_eventid_regex = re.compile(r"eventId: '(.+?)',")
challenge_botdetect_host_regex = re.compile(r"botDetectHost: '(.+?)',")
challenge_inqueue_url_regex = re.compile(r"inqueueUrl: '(.+?)',")


# bypass_botdetect requires tesseract-ocr (https://github.com/tesseract-ocr/tesseract)
# It should be installed and available in the environment path
def bypass_botdetect(session : requests.Session, url : str, params = {}):
    request = session.get(url, params=params)
    if "queue-it.net" not in urlparse(request.url).hostname:
        return request

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

            image_string = io.BytesIO(base64.b64decode(image_base64))
            image = Image.open(image_string)

            challenge_solution = pytesseract.image_to_string(image).strip()
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
