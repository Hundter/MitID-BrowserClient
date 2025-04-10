# MitID-BrowserClient
Unofficial python implementation of the MitID javascript browser client

Currently supports logins using the MitID app (OTP and QR Code), and the code token reader device.

In the login_flows folder there are examples of you how can use this MitID BrowserClient with a variety of different sites.

Feel free to pull request a login flow if you have made one.

### Examples
Login to the mitid.dk website using the MitID APP
```
python login_flows/mitiddk.py --user="my-really-easy-to-guess-username" --method=APP
```
\
Login to the mitid.dk website using the code reader and your password
```
python login_flows/mitiddk.py --user="my-really-easy-to-guess-username" --method=TOKEN
```
\
Login to the mitid.dk website using a socks5 proxy to avoid those pesky IP bans when testing
```
python login_flows/mitiddk.py --user="my-really-easy-to-guess-username" --proxy="overpriced-proxy.com:1080" --method=TOKEN
```

### Prerequisites
Prerequisites can be installed by running:
```
pip install -r requirements.txt
```

Some login flows make use of [PaddleOCR](https://github.com/PaddlePaddle/PaddleOCR) for captcha bypassing.
PaddleOCR will spend some time downloading models the first time you run any of these login flows.
