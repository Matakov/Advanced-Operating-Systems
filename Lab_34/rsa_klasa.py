# -*- coding: utf-8 -*-
"""
Created on Thu May 04 14:02:39 2017

@author: Franjo
"""

from Crypto import Random
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
import base64
from Tkinter import *
from KSI import *
from tkFileDialog import askopenfilename
import os
import subprocess
import math
import hashlib
from mySHA import *
import Crypto
from Crypto.PublicKey import RSA
from Crypto import Random
import ast
from base64 import *
import struct
from aes_klasa import *
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA


class RSACipher(object):
    def __init__(self,modulous=None,publicExponent=None,privateExponent=None,size=1024):
        self.size=size
        if modulous==None and publicExponent==None:
            random_generator = Random.new().read
            self.key = RSA.generate(size, random_generator) #generate public and private keys
        elif privateExponent==None:
            Mod = b64decode(modulous)
            PE = b64decode(publicExponent)
            try:
                numberMod = long(Mod)
                numberPublic = long(PE)
            except ValueError:
                numberMod = long(Mod,16)
                numberPublic = long(PE,16)
            self.key = RSA.construct([numberMod,numberPublic])
        else:
            Mod = b64decode(modulous)
            PE = b64decode(publicExponent)
            SE = b64decode(privateExponent)
            try:
                numberMod = long(Mod)
                numberPublic = long(PE)
                numberPrivate = long(SE)
            except ValueError:
                numberMod = long(Mod,16)
                numberPublic = long(PE,16)
                numberPrivate = long(SE,16)
            self.key = RSA.construct([numberMod,numberPublic,numberPrivate])
        pass
    
    def pad (self,raw):
        raw =  raw + (self.bs - len(raw) % self.bs) * chr(self.bs - len(raw) % self.bs)
        return raw
    
    def unpad(self,data):
        return data[:-ord(data[len(data)-1:])]
        
    def generateKey(self):
        random_generator = Random.new().read
        self.key = RSA.generate(self.size, random_generator)
        
    def getPublicKey(self):
        return self.key.publickey()
    
    def getPrivateKey(self):
        if self.key.has_private:
            return self.key
        else:
            return None
    
    def setPublicKey(self,modulous,publicExponent):
        self.key = RSA.construct([long(b64decode(modulous)),long(b64decode(publicExponent))])
        
    def setPrivateKey(self,modulous,publicExponent,privateExponent):
        self.key = RSA.construct([long(b64decode(modulous)),long(b64decode(publicExponent)),long(b64decode(privateExponent))])
        
    def inttob64(self,n):                                                              
        """                                                                       
        Given an integer returns the base64 encoded version of it (no trailing ==)
        """
        parts = []                                                                
        while n:                                                                  
            parts.insert(0,n & 0xFF)                                             
            n >>= 32                                                              
        data = struct.pack('>' + 'L'*len(parts),*parts)                           
        s = base64.urlsafe_b64encode(data).rstrip('=')                            
        return s 
    
    def b64toint(self,s):                                                              
        """                                                                       
        Given a string with a base64 encoded value, return the integer representation
        of it                                                                     
        """                                                                       
        data = base64.urlsafe_b64decode(s + '==')                                 
        n = 0                                                                     
        while data:                                                               
            n <<= 32                                                              
            (toor,) = struct.unpack('>L',data[:4])                                
            n |= toor & 0xffffffff                                                
            data = data[4:]                                                       
        return n
        
        
    def getPublicExponent(self):
        #key = self.key.exportKey('DER')
        return b64encode(bytes(self.key.e))
        #return b64encode(''.join(Public))
        
        #return self.key.e
    
    def getModulus(self):
        #key = self.key.exportKey('DER')
        return b64encode(bytes(self.key.n))
        #return self.key.n
    
    def getPrivateExponent(self):
        #key = self.key.exportKey('DER')
        return b64encode(bytes(self.key.d))
        #return self.key.d
    
    def getE(self):
        return b64encode(hex(self.key.e))
    
    def getD(self):
        return b64encode(hex(self.key.d))
    
    def getN(self):
        return b64encode(hex(self.key.n))
    
    def encode(self,raw_data):
        return b64encode(self.key.encrypt(raw_data, 'x')[0])
        pass
    
    def decode(self,coded_data):
        return self.key.decrypt(b64decode(coded_data))
        pass
    
    def createEnvelope(self,data):
        SymmetricCipher=AESCipher()
        SymmetricCipher.generateKey()
        encoded =  SymmetricCipher.encode(data)
        symmetricKey = SymmetricCipher.getKey()
        codedSymKey = self.encode(symmetricKey)
        
        dic = {}
        dic['Key']=codedSymKey
        dic['Data']=encoded
        return dic
        pass
    
    def openEnvelope(self,codedSymKey,codedData):
        SymKey = self.decode(codedSymKey)
        #print SymKey
        #print len(bytearray(SymKey))
        SymmetricDecipher=AESCipher(SymKey)
        decodedData =SymmetricDecipher.decode(codedData)
        return decodedData
    
    def createSignature(self,data):
        #m = hashlib.sha1()
        #m.update(data)
        #hesh = m.hexdigest()
        h = SHA.new(data)
        #h = myOwnSha(data)
        #print h
        #sign = self.key.sign(hesh,data)
        signer = PKCS1_v1_5.new(self.key)
        signature = signer.sign(h)
        
        dic = {}
        dic['Signature']=b64encode(signature)
        dic['Data']=data
        return dic
        pass
    
    def verifySignature(self,signature,data):
        #print '----------------------'
        #print signature
        #print data
        #m = hashlib.sha1()
        #m.update(data)
        #hesh = m.hexdigest()
        #print hesh
        h = SHA.new(data)
        verifier = PKCS1_v1_5.new(self.key)
        #decodedHash = self.key.verify(hesh,signature)
        if verifier.verify(h, b64decode(signature)):
            return True
        else:
            return False
        pass
        
    def createSeal(self):
        pass 
    
    
Cipher=RSACipher()
Cipher2=RSACipher()


CipherForSignature=RSACipher(Cipher.getModulus(),Cipher.getPublicExponent())

CipherForEnvelope=RSACipher(Cipher2.getModulus(),Cipher2.getPublicExponent())
#print SymmetricCipher.getKey()
#SymmetricCipher.generateKey()
#print SymmetricCipher.getKey()

text='Ovim programom cu dobiti Omotnicu koju cu onda ubaciti u gui'
"""
#print SymmetricCipher.getModulus()
mod= SymmetricCipher.getModulus()
#print "------------------------------"
#print SymmetricCipher.getPrivateExponent()
private = SymmetricCipher.getPrivateExponent()
#print "------------------------------"
#print SymmetricCipher.getPublicExponent()
public = SymmetricCipher.getPublicExponent()
#print "----------------------------------------------------"
number = long(b64decode(private))
#print type(number)
#print number == SymmetricCipher.getD()

SymmetricCipher2 = RSACipher(mod,public,private)

codeIt = SymmetricCipher.encode(text)
print codeIt

plaintext = SymmetricCipher2.decode(codeIt)

print plaintext
"""
"""
signature = CipherForSignature.createSignature(text)
print signature
VerifySignature = Cipher.verifySignature(signature['Signature'],signature['Data'])

print VerifySignature
"""

Envelope = CipherForEnvelope.createEnvelope(text)
#print Envelope

SignedEnvelope = Cipher.createSignature(Envelope['Key']+Envelope['Data'])

#print SignedEnvelope

#VerifyEnvelope = Cipher2.openEnvelope(Envelope['Key'],Envelope['Data'])
#print VerifyEnvelope
#VerifySignature = CipherForSignature.verifySignature(SignedEnvelope['Signature'],Envelope['Key']+Envelope['Data'])
#print VerifySignature

"""
OPEN ENVELOPE
"""
"""
Envelope = CipherForEnvelope.createEnvelope(text)
#print Envelope

EnvelopeData = Cipher2.openEnvelope(Envelope['Key'],Envelope['Data'])
print EnvelopeData
"""
