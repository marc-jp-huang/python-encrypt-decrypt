import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES

class AESCipher(object):

    def __init__(self, key): 
        self.bs = 32
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]

if __name__ == '__main__':
    o1 = AESCipher('your key')
    o2 = AESCipher('other key')
    encrypt_text1 = o1.encrypt('the text you want to encrypt')
    encrypt_text2 = o1.encrypt('the other text you want to encrypt')
    print encrypt_text1
    print encrypt_text2
    print o1.decrypt(encrypt_text1)
    try:
        #this one will failed, using wrong key
        print o2.decrypt(encrypt_text2)
    finally:
        print 'oops'
    print o1.decrypt(encrypt_text2)

