# -*- coding: utf-8 -*-
"""
Created on Thu May 04 13:04:37 2017

@author: Franjo
"""

from Crypto import Random
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
import os
from base64 import *


class AESCipher(object):
    def __init__(self,key=None,blockSize=16):
        self.bs = blockSize
        if key!=None:
            self.key = b64decode(key).encode('hex')
        else:
            self.key = key
        pass
    
    def pad (self,raw):
        raw =  raw + (self.bs - len(raw) % self.bs) * chr(self.bs - len(raw) % self.bs)
        return raw
    
    def unpad(self,data):
        return data[:-ord(data[len(data)-1:])]
    
    def generateKey(self):
        secret = os.urandom(self.bs)
        self.key = secret.encode('hex')
        
    def getKey(self):
        return b64encode(self.key.decode('hex'))
    
    def setKey(self,key):
        self.key=key.encode('hex')
        
    def encode(self,raw_data):
        raw_data = self.pad(raw_data)
        IV = Random.new().read( self.bs )
        cipher = AES.new( self.key.decode('hex'), AES.MODE_CBC, IV )
        return b64encode( IV + cipher.encrypt( raw_data ) ) 
        pass    
    
    def decode(self,encoded_data):
        data = b64decode( encoded_data ) 
        #raw_data = self.pad(raw_data)
        IV = data[:16]
        decipher = AES.new( self.key.decode('hex'), AES.MODE_CBC, IV )
        return  decipher.decrypt( data[16:] ) 
    
"""
SymmetricCipher=AESCipher()
#print SymmetricCipher.getKey()
SymmetricCipher.generateKey()
#print SymmetricCipher.getKey()

text='Ovim programom cu dobiti Omotnicu koju cu onda ubaciti u gui'

encoded =  SymmetricCipher.encode(text)
#print encoded

newKey = SymmetricCipher.getKey()
      
SymmetricDecipher= AESCipher(newKey)

decoded = SymmetricCipher.decode(encoded)

print decoded

print SymmetricDecipher.getKey()==newKey
print SymmetricDecipher.getKey()
print '-------'
print newKey

"""