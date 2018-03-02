# authors: Nick Hiemstra and Erik Douwes
# version: 0.2 
# date: 24-01-2018

from Crypto.Cipher import AES
import hmac
import base64
import jwt 
import sys
import urllib

# to use this class:
# import jwtCrypto
# jwt = jwtCrypto.jwtCrypto("key")
# jwt.decrypt(raw_token) # raw base64 encoded jwt from header
#
# jwt decryption is as follows:
#
# 1. jwt urrlib.unquote (sometimes .decode(utf8)
# 2. splits IV (first 24 bytes of base64 encoded jwt
# 3. base64 decode IV
# 4. base64 decode token (except first 24 bytes)
# 5. AES decrypt token
# 6. you'll get a three segment base64 string , seperated by dot)
# 7. splits the three segments (header, content, signature)
# 8. base64 decode those segment
# 9. everything is plain and readable


class jwtCrypto:

    def __init__(self, key):
        self.key = key
        
    def decrypt(self, input):
        raw_token = input
        raw_token = urllib.unquote(raw_token).decode('utf8') 
        IV = raw_token[:24]
        IV = base64.b64decode(IV)
        token = raw_token[24:]
        token = token[1:]
        token = base64.b64decode(token)

        # Decryption
        decryption_suite = AES.new(key, AES.MODE_CBC, IV)
        jwt = decryption_suite.decrypt(token)
        header, content, signature = jwt.split(".")
        self.header = base64.b64decode(header)
        pad = (len(content) % 4)
        self.content = content + (pad * "=")
        self.content = base64.b64decode(content)
