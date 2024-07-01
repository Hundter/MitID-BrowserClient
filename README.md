# MitID-BrowserClient
Unofficial python implementation of the MitID javascript browser client

Currently support logins using the MitID app (if you use 4-digit OTP rather than QR code), and the code token reader device.

It's also hardcoded to use mitid.dk's login page for now

### Examples
Login using the MitID app
```
python main.py --user="my-really-easy-to-guess-username" --method=APP
```
\
Login using the the code reader and your password
```
python main.py --user="my-really-easy-to-guess-username" --method=TOKEN
```
\
Login using a socks5 proxy to avoid those pesky IP bans when testing
```
python main.py --user="my-really-easy-to-guess-username" --proxy="overpriced-proxy.com:1080" --method=TOKEN
```
