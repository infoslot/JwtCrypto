# authors: Nick Hiemstra and Erik Douwes
# version: 0.2 
# date: 24-01-2018

from Crypto.Cipher import AES
import hmac
import base64
import jwt 
import sys
import urllib

# At first we need to base64 decode and decrypt the string in which the JWT is hidden. For decrypting we need an IV, algoritme and shared secret
# The decrypted JWT is separated by dots in three parts. The first two parts (header and content) must be base64 decoded
# just put the original authenticatio bearer token as argument 

# get the raw original jwt header from stdin
input = sys.argv[1]
raw_token = input
raw_token = urllib.unquote(input)
print(raw_token)
# IV is the 24 first bytes of token in base64, after base64 decoding it needs 16 bytes for IV
IV = raw_token[:24]
IV = base64.b64decode(IV)
token = raw_token[24:]
token = token[1:]
token = base64.urlsafe_b64decode(token)

# Decryption
decryption_suite = AES.new(key, AES.MODE_CBC, IV)
jwt = decryption_suite.decrypt(token)

print("The decrypted JWT is: %s" % jwt) 
header, content, signature = jwt.split(".")
print("\nThe JWT header is: %s\n" % header)
print("The JWT content is: %s\n" % content)
print("The JWT signature is: %s\n" % signature)
print("The information inside JWT is as followed:\n")
pad = (len(header) % 4)
header = (base64.b64decode(header)) 
pad = (len(content) % 4)
print(pad)
content = content + (pad * "=")
content = (base64.b64decode(content))
content = content.split(",")
for item in content:
    print item
