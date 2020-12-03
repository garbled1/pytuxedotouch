import asyncio
import time
import hmac
import hashlib
import logging
import httpx
import json
import ssl
from bs4 import BeautifulSoup
from base64 import b64decode
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from const import (
    HOME_URL,
    HTMLAPI_URL,
    HEADER_PRE,
    API_URL,
)

"""
This module will communicate with a Tuxedo Touch Wifi module from Honeywell.
This is only tested on the most recent firmware, previous ones did not have
as much "encryption".
"""


class TuxAESCipher:
    def __init__(self, key, iv):
        self.key = key
        self.iv = iv

    def encrypt(self, data):
        self.cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        encdata = self.cipher.encrypt(pad(data.encode('utf-8'),
                                          AES.block_size))
        return b64encode(encdata)

    def decrypt(self, data):
        raw = b64decode(data)
        self.cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        return unpad(self.cipher.decrypt(raw), AES.block_size)


class TuxedoTouchWiFi:
    def __init__(self, hostname, username, password):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.cjar = None
        self.api_key_enc = None
        self.api_iv_enc = None
        self.api_key_bytes = None
        self.api_iv_bytes = None

        # Debugging
        logging.basicConfig(level=logging.DEBUG)

        # The device uses an ancient DH key that is too small, and self signed
        ssl_context = httpx.create_ssl_context(verify=False)
        ssl_context.options ^= ssl.OP_NO_TLSv1_1
        ssl_context.set_ciphers('TLS13-AES-256-GCM-SHA384:TLS13-CHACHA20-POLY1305-SHA256:TLS13-AES-128-GCM-SHA256:ECDH+AESGCM:ECDH+CHACHA20:DH+AESGCM:DH+CHACHA20:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:RSA+AESGCM:RSA+AES:!aNULL:!eNULL:!MD5HIGH:!DH:!aNULL')
        self.client = httpx.AsyncClient(base_url=f'https://{self.hostname}',
                                        verify=ssl_context)

    def make_digest512(sekf, message, key):
        """ Digest message into sha512 hex."""
        key = bytes(key, 'UTF-8')
        message = bytes(message, 'UTF-8')

        digester = hmac.new(key, message, hashlib.sha512)
        return(digester.hexdigest())

    def make_digest1(self, message, key):
        """ Digest message into sha1 hex."""
        key = bytes(key, 'UTF-8')
        message = bytes(message, 'UTF-8')

        digester = hmac.new(key, message, hashlib.sha1)
        return(digester.hexdigest())

    async def initial_login(self):
        """ Login, get cookie."""
        r = await self.client.get(HOME_URL)
        cjar = r.cookies
        header = r.headers
        user = self.make_digest512(self.username, header['Random'])
        password = self.make_digest512(self.username + self.password,
                                       header['Random'])
        payload = {
            'log': user,
            'log1': password,
            'identity': header['RandomId'],
        }
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Connection': 'keep-alive',
        }

        rr = await self.client.post(HOME_URL, headers=headers, data=payload,
                                    cookies=cjar)
        self.cjar = rr.history[0].cookies

    async def get_enc_keys(self):
        """ Get the crazy 'encryption' keys from the device."""
        r = await self.client.post(HTMLAPI_URL, cookies=self.cjar)
        soup = BeautifulSoup(r.text, 'html.parser')
        readit = soup.find(id='readit')
        readit_val = readit.get('value')
        self.api_key_enc = readit_val[:64]
        self.api_iv_enc = readit_val[64:96]
        self.api_key_bytes = bytes.fromhex(self.api_key_enc)
        self.api_iv_bytes = bytes.fromhex(self.api_iv_enc)

    async def post_api(self, url, data):
        """ Handle a post."""
        if data is not None and len(data) > 0:
            d_to_send = TuxAESCipher(self.api_key_bytes, self.api_iv_bytes).encrypt(data)
            post_data = {
                'param': d_to_send,
                'len': len(d_to_send),
                'tstamp': int(time.time()),
            }

        headers = {
            'authtoken': self.make_digest1(HEADER_PRE + url, self.api_key_enc),
            'identity': self.api_iv_enc,
        }

        if data is not None and len(data) > 0:
            r = await self.client.post(API_URL + url, headers=headers,
                                       data=post_data, cookies=self.cjar)
        else:
            r = await self.client.post(API_URL + url, headers=headers,
                                       cookies=self.cjar)

        r_data = json.loads(r.text)
        return TuxAESCipher(self.api_key_bytes, self.api_iv_bytes).decrypt(r_data['Result']).decode('utf-8')

    async def GetSecurityStatus(self):
        """ Perform a GetSecurityStatus call, return json."""
        data = await self.post_api('/GetSecurityStatus', None)
        return json.loads(data)
