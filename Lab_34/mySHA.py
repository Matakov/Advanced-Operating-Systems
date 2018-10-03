# -*- coding: utf-8 -*-
"""
Created on Sun Apr 30 09:44:27 2017

@author: Franjo
"""
import binascii
import sys

def chunkstring(string, length):
    return (string[0+i:length+i] for i in range(0, len(string), length))

def ROTL(x, n, w=32):
        return ((x << n) | (x >> w - n))

def prep(stream):
        M = []
        n_blocks = len(stream) // 64

        stream = bytearray(stream)

        for i in range(n_blocks):  # 64 Bytes per Block
            m = []

            for j in range(16):  # 16 Words per Block
                n = 0
                for k in range(4):  # 4 Bytes per Word
                    n <<= 8
                    n += stream[i*64 + j*4 + k]

                m.append(n)

            M.append(m[:])

        return M

div = lambda x,y: [ x[i:i+y] for i in range(0,len(x),y)] 

def prepit(stream):
    l = len(stream)
    my_str_as_bytes = bytearray(stream)
    lista=''
    Array=[]
    
    for (elem,n) in zip(my_str_as_bytes,range(len(my_str_as_bytes))):
        if n%4==0 and n!=0:
            Array.append(lista)
            lista=''
        lista+=str(bin(elem))[2:].rjust(8,'0')
        if n==len(my_str_as_bytes)-1:
            lista+='1'
            lista=lista.ljust(32,'0')
            Array.append(lista)

    listSize = len(Array)
    howMuch = (listSize%16)
    for i in range(howMuch-1):
        Array.append('0'*32)
    last=''
    last+=str(bin(l))[2:].rjust(32,'0')
    Array.append(last)
    BigArray = div(Array,16)
    return BigArray


def myOwnSha(msg):
    #Initialize variables:
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0
    
    MASK = 2**32-1
    #binMsg=turnToBinary(msg)
    binMsg=msg
    
    l = len(binMsg)  # Bytes
    hl = [int((hex(l*8)[2:]).rjust(16, '0')[i:i+2], 16) for i in range(0, 16, 2)]
    l0 = (56 - l) % 64
    #print l0
    #print 64-(l-56) % 64
    if not l0:
        l0 = 64
    binMsg += chr(0b10000000)
    binMsg += chr(0)*(l0-1)
    for a in hl:
        binMsg += chr(a)
    
    #lista = list(chunkstring(binMsg,512))
    lista=prep(binMsg)
    
    #lista = prepit(msg)
    for chunk in lista:
        #break chunk into sixteen 32-bit big-endian words w[i], 0 ≤ i ≤ 15
        w = chunk[:]
        for i in range(16,80):
            #print i
            xorLista = w[i-3] ^ w[i-8]  ^ w[i-14] ^ w[i-16]
            #print xorLista
            xorLista = ROTL(xorLista,1)
            #print bin(xorLista)
            w.append(xorLista % 2**32)
            #w[i] = xor(w[i-3],w[i-8])
            #w[i] = xor(w[i],w[i-14]) 
            #w[i] = xor(w[i],w[i-16])
            #w[i] = rotateLeft(int(w[i],2),1)
            
        #Initialize hash value for this chunk:
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4
        for i in range(80):
            if 0 <= i <= 19:
                f = ((b & c) ^ (~b & d))
                k = 0x5a827999
            elif 20 <= i <= 39:
                f = b^c^d
                k = 0x6ed9eba1
            elif 40 <= i <= 59:
                f = ((b & c) ^ (b & d) ^ (c & d)) 
                k = 0x8f1bbcdc
            elif 60 <= i <= 79:
                f = b ^ c ^ d
                k = 0xca62c1d6
            temp = (ROTL(a,5) + f + e + k + w[i]) % 2**32
            #print bin(temp)
            e = d
            d = c
            c = (ROTL(b,30)) % 2**32
            b = a
            a = temp
            #print (a, b, c, d, e)
        h0 = (h0 + a) % 2**32
        h1 = (h1 + b) % 2**32 
        h2 = (h2 + c) % 2**32
        h3 = (h3 + d) % 2**32
        h4 = (h4 + e) % 2**32
        
    hh = (h0 << 128) | (h1 << 96) | (h2 << 64) | (h3 << 32) | h4
    return hh


#line = 'dkasjn jsankasjnda\nsdkamdlsad\nsad\n'
#print (hex(myOwnSha(line))[2:-1])