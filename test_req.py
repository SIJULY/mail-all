import urllib.request
import urllib.error
import http.cookiejar

cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

# login first
data = b"username=sijuly@outlook.com&password=testpassword" # wait I don't know the password.
