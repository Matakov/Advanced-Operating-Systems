# -*- coding: utf-8 -*-
"""
Created on Sat Apr 22 00:30:46 2017

@author: Franjo
"""

from Crypto import Random
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from base64 import *
from Tkinter import *
from KSI import *
from tkFileDialog import askopenfilename
import os
import subprocess
import math
import hashlib
from mySHA import *
from rsa_klasa import *
from aes_klasa import *


def bin2hex(binStr):
    return binascii.hexlify(binStr)

def hex2bin(hexStr):
    return binascii.unhexlify(hexStr)


def write_data_d(name, value1, fp):
    ## Used for writing keys in the output file.
    try:
        fp.write(name+':\n')
        if type(value1) is list:
            for val in value1:
                value = str(val)
                print value
                if value[len(value)-1] == 'L':
                    value = value[:len(value)-1]
                #if len(value) % 2 != 0:
                #    value = value.zfill(len(value)+1)
                fp.write('    ' + value + '\n')
        fp.write('\n')
        return 1
    except:
        return 0


class Child_Window(Frame):
    
    
    def generateKey(self,filename,tip):
        if tip==1:
            BLOCK_SIZE = 16
            secret = os.urandom(BLOCK_SIZE)
            my_hex="".join([ch.encode("hex") for ch in secret])
            #my_hex = unicode(secret).decode('hex')
            #print my_hex
            self.key['Secret key']=[my_hex]
            #print self.labelKey.get()
            self.write_data(self.labelKey.get(),1)
        else:
            """
            OVO TREBA IZMJENITI NE RADI DOBRO!!!!!!!!!!!!!!
            """
            key = RSACipher()
            self.key['Modulus']=self.prepOutputData(key.getModulus())
            self.key['Private exponent']=self.prepOutputData(key.getPrivateExponent())
            self.key['Public exponent']=self.prepOutputData(key.getPublicExponent())
            self.key['Key length']=[hex(key.getN().bit_length())]
            
            
            
            
            """
            key = RSA.generate(2048)
            binPrivKey = key.exportKey('DER')
            binPubKey =  key.publickey().exportKey('DER')
            self.key['Modulus']=[]
            if len(hex(key.n))>60:
                turns=int(math.ceil(len(hex(key.n)[2:-1])/float(60)))
                for i in range(0,turns):
                    if i==0:
                        self.key['Modulus'].append(hex(key.n)[2:60])
                    elif i!=turns-1:
                        self.key['Modulus'].append(hex(key.n)[i*60:(i+1)*60])
                    else:
                        self.key['Modulus'].append(hex(key.n)[(turns-1)*60:-1])
            #self.key['Modulus']=[key.n]
            print self.key
            self.key['Public exponent']=[]
            if len(hex(key.e))>60:
                turns=int(math.ceil(len(hex(key.e)[2:-1])/float(60)))
                key.e=hex(key.e)[2:-1]
                for i in range(0,turns):
                    if i==0:
                        self.key['Public exponent'].append(key.e[0:60])
                    elif i!=turns-1:
                        self.key['Public exponent'].append(key.e[i*60:(i+1)*60])
                    else:
                        self.key['Public exponent'].append(key.e[(turns-1)*60:-1])
            else:
                self.key['Public exponent'].append(hex(key.e)[2:-1])
            #self.key['Public exponent']=[key.e]
            print self.key['Public exponent']
            self.key['Private exponent']=[]
            #self.key['Private exponent']=[key.d]
            if len(hex(key.d))>60:
                turns=int(math.ceil(len(hex(key.d)[2:-1])/float(60)))
                key.d=hex(key.d)[2:-1]
                for i in range(0,turns):
                    if i==0:
                        self.key['Private exponent'].append(key.d[2:60])
                    elif i!=turns-1:
                        self.key['Private exponent'].append(key.d[i*60:(i+1)*60])
                    else:
                        self.key['Private exponent'].append(key.d[(turns-1)*60:])
            print self.key['Private exponent']
            self.key['Key length']=[hex(key.n.bit_length())]
            #print self.key
            """
            self.write_data(self.labelKeyPublic.get(),3)
            self.write_data(self.labelKeyPrivate.get(),4)
            
            
    
    def doJob(self,event,Type):
        job = self.valueEnDec.get()
        if job==1:
            if Type=="SHA":
                self.output = self.hashSHA(Type)
            else:
                self.output = self.encode(Type)
        else:
            self.output = self.decode(Type)
            
        #print self.output
        pass
    
    def hashSHA(self,Type):
        m = hashlib.sha1()
        for dae in self.data['Data']:
                text = dae
                """
                while(len(text)%16!=0):
                    text=text+' '
                    """
                m.update(text)
        self.labelSHA.set(m.hexdigest())
        txt=''
        for dae in self.data['Data']:
            txt+=dae
        self.labelMySHA.set(hex(myOwnSha(txt))[2:-1])
        return m.hexdigest()
        pass
    
    def encode(self,Type):
        print Type
        if Type=="AES":
            IV = 16 * '\x00'           # Initialization vector: discussed later
            mode = AES.MODE_CBC
            encryptor = AES.new(self.key['Secret key'][0], mode, IV=IV)
            self.crypted = []
            for dae in self.data['Data']:
                text = dae
                while(len(text)%16!=0):
                    text=text+' '
                self.plain = text
                self.crypted.append(encryptor.encrypt(self.plain))
        else:
            n=''.join(self.key['Modulus'])
            e=''.join(self.key['Public exponent'])
            cryptKey = RSA.construct([long(n, 16),long(e, 16)])
            self.crypted = []
            for dae in self.data['Data']:
                text = dae
                while(len(text)%16!=0):
                    text=text+' '
                self.plain = text
                self.crypted.append(cryptKey.encrypt(self.plain, 'x')[0])
            pass
        print self.plain
        return self.crypted
        pass
    
    def decode(self,Type):
        if Type=="AES":
            IV = 16 * '\x00'           # Initialization vector: discussed later
            mode = AES.MODE_CBC
            decryptor = AES.new(self.key['Secret key'][0], mode, IV=IV)
            self.decrypted=[]
            if len(self.crypted)==0:
                ciphertext = self.data['Data']
            else:
                ciphertext= self.crypted
            
            for dae in ciphertext:
                text = dae
                while(len(text)%16!=0):
                    text=text+' '
                self.decrypted.append(decryptor.decrypt(text))
        else:
            n=''.join(self.key['Modulus'])
            d=''.join(self.key['Private exponent'])
            e=''.join(self.key['Public exponent'])
            decryptKey = RSA.construct([long(n, 16),long(e, 16),long(d, 16)])
            #print 'KRIPTIRANO------------------------------------------------------'
            #print self.crypted
            self.decrypted=[]
            if len(self.crypted)==0:
                ciphertext = self.data['Data']
            else:
                ciphertext= self.crypted
            
            for dae in ciphertext:
                text = dae
                while(len(text)%16!=0):
                    text=text+' '
                self.decrypted.append(decryptKey.decrypt(text))
            pass
        print self.decrypted
        return self.decrypted
        pass
    
    
    def create_window(self,event,filepath,dataType,CryptType,data):
        #self.parent.counter += 1
        #t = Toplevel(self)
        #t.wm_title("Window #%s" % self.parent.counter)
        
        process_one = subprocess.Popen(['notepad.exe', filepath])
        process_one.wait()
        #self.choose_file(dataType,CryptType,filepath)
        
        """
        pt={}
        if tip==1:
            pt=self.key
        elif tip==2:
            pt=self.data
        else:
            pt=self.crypted
        l = Label(t, text="%s" % (data))
        l.pack(side="top", fill="both", expand=True, padx=100, pady=100)
        """
        
    def read_data(self,filename):
        fp = open(filename, "rb")
        data=load(fp)
        print data
        fp.close()
        return data
        pass
    
    
    def write_data(self,filename,tip):
        #print filename
        fp = open(filename, "w")
        put_header("Header",fp)
        if tip==1:
            #print str(unicode(self.key['Secret key'][0]))
            write_data_d(name='Description',value1=["Secret key"],fp=fp)
            write_data_d(name='Method',value1=["AES"],fp=fp)
            write_data_d(name='Secret key',value1=self.key['Secret key'],fp=fp)
        elif tip==2:
            #put_data_s('Data',self.output,None,fp=fp)
            write_data_d(name='Description',value1=["Crypted data"],fp=fp)
            write_data_d(name='Method',value1=["AES"],fp=fp)
            write_data_d(name='Data',value1=self.crypted,fp=fp)
        elif tip==3:
            print self.key
            write_data_d(name='Description',value1=["Public key"],fp=fp)
            write_data_d(name='Method',value1=["RSA"],fp=fp)
            write_data_d(name='Key length',value1=[(self.key['Key length'][0])[2:]],fp=fp)
            write_data_d(name='Modulus',value1=self.key['Modulus'],fp=fp)
            write_data_d(name='Public exponent',value1=self.key['Public exponent'],fp=fp)
        elif tip==4:
            write_data_d(name='Description',value1=["Private key"],fp=fp)
            write_data_d(name='Method',value1=["RSA"],fp=fp)
            write_data_d(name='Key length',value1=[(self.key['Key length'][0])[2:]],fp=fp)
            write_data_d(name='Modulus',value1=self.key['Modulus'],fp=fp)
            write_data_d(name='Private exponent',value1=self.key['Private exponent'],fp=fp)
            write_data_d(name='Public exponent',value1=self.key['Public exponent'],fp=fp)
        elif tip==6:
            write_data_d(name='Description',value1=["Signature"],fp=fp)
            write_data_d(name='Method',value1=["SHA-1"],fp=fp)
            write_data_d(name='Signature',value1=[self.output],fp=fp)
            
        else:
            write_data_d(name='Description',value1=["Data"],fp=fp)
            write_data_d(name='Method',value1=["AES"],fp=fp)
            write_data_d(name='Data',value1=self.decrypted,fp=fp)
        
        put_footer("Footer",fp)
        fp.close()
        pass
    
    def choose_file(self,event,arg,tipCrip,filename=None):
        if filename==None:
            filename = askopenfilename()
        if arg==1:
            if(tipCrip=='AES'):
                self.labelKey.set(filename)
                self.key.update(self.read_data(filename))
            elif(tipCrip=='RSA'):
                self.labelKeyPublic.set(filename)
                self.key.update(self.read_data(filename))
            #self.label1.config(self.labelKey)
        elif arg==2:
            self.labelInput.set(filename)
            self.data=self.read_data(filename)
            #self.label2.config(self.labelInput)
        elif arg==3:
            self.labelOutput.set(filename)
            if (len(self.crypted)!=0):
                self.write_data(filename,2)
            else:
                if (tipCrip=='SHA'):
                    self.write_data(filename,6)
                else:
                    self.write_data(filename,5)
            #self.label3.config(self.labelOutput)
        elif arg==4:
            if(tipCrip=='RSA'):
                self.labelKeyPrivate.set(filename)
                self.key.update(self.read_data(filename))
        pass
    
    
    def create_window_AES(self):
        t = Toplevel(self)
        t.wm_title("Window AES")
        #DATA
        self.labelKey = StringVar()
        self.labelInput = StringVar()
        self.labelOutput = StringVar()
        self.labelKey.set('C:/Users/Franjo/Documents/FER/NOS/Lab34/aes_kljuc.txt')
        self.labelInput.set('C:/Users/Franjo/Documents/FER/NOS/Lab34/aes_ulaz.txt')
        self.labelOutput.set('C:/Users/Franjo/Documents/FER/NOS/Lab34/aes_izlaz.txt')
        t.l1 = Label(t, text="Kljuc:")
        #l.pack(side="top", fill="both", expand=True, padx=100, pady=100)
        t.l2 = Label(t, text="Ulazna datoteka:")
        t.l3 = Label(t, text="Izlazna datoteka:")
        t.label1 = Label(t, textvariable = self.labelKey)
        t.label2 = Label(t, textvariable = self.labelInput)
        t.label3 = Label(t, textvariable = self.labelOutput)
        self.valueEnDec = IntVar()
        self.valueEnDec.set(1)
        
        t.button1Odaberi = Button(t, text="Odaberi")
        t.button2Odaberi = Button(t, text="Odaberi")
        t.button3Odaberi = Button(t, text="Odaberi")
        t.button1Odaberi.bind("<ButtonPress-1>", lambda event,arg=1: self.choose_file(event, arg,'AES'))
        t.button2Odaberi.bind("<ButtonPress-1>", lambda event,arg=2: self.choose_file(event, arg,'AES'))
        t.button3Odaberi.bind("<ButtonPress-1>", lambda event,arg=3: self.choose_file(event, arg,'AES'))
        t.button1Pregledaj = Button(t, text="Pregledaj")
        t.button2Pregledaj = Button(t, text="Pregledaj")
        t.button3Pregledaj = Button(t, text="Pregledaj")
        t.button1Pregledaj.bind("<ButtonPress-1>", lambda event,arg1=self.labelKey.get(),arg2=1: self.create_window(event, arg1,arg2,'AES', self.key))
        t.button2Pregledaj.bind("<ButtonPress-1>", lambda event,arg1=self.labelInput.get(),arg2=2: self.create_window(event, arg1,arg2,'AES', self.data))
        t.button3Pregledaj.bind("<ButtonPress-1>", lambda event,arg1=self.labelOutput.get(),arg2=3: self.create_window(event, arg1,arg2,'AES', self.crypted))
        t.buttonGeneriraj = Button(t, text="Generiraj")
        t.buttonGeneriraj.bind("<ButtonPress-1>", lambda arg2=self.labelKey.get(),tip=1: self.generateKey(arg2,tip))
        t.buttonCodeDecode = Button(t, text="Obavi kriptiranje/dekriptiranje")
        t.buttonCodeDecode.bind("<ButtonPress-1>", lambda event,arg1="AES": self.doJob(event,arg1))
        t.l1.grid(row=1,column=1, padx=10, pady=10)
        t.l2.grid(row=2,column=1, padx=10, pady=10)
        t.l3.grid(row=3,column=1, padx=10, pady=10)
        t.label1.grid(row=1,column=2, padx=50, pady=10)
        t.label2.grid(row=2,column=2, padx=50, pady=10)
        t.label3.grid(row=3,column=2, padx=50, pady=10)
        t.button1Odaberi.grid(row=1,column=3, padx=10, pady=10)
        t.button2Odaberi.grid(row=2,column=3, padx=10, pady=10)
        t.button3Odaberi.grid(row=3,column=3, padx=10, pady=10)
        t.button1Pregledaj.grid(row=1,column=4, padx=10, pady=10)
        t.button2Pregledaj.grid(row=2,column=4, padx=10, pady=10)
        t.button3Pregledaj.grid(row=3,column=4, padx=10, pady=10)
        t.buttonGeneriraj.grid(row=1,column=5, padx=10, pady=10)
        t.buttonCodeDecode.grid(row=6,columnspan=5)
        

        Radiobutton(t, text="Kriptiranje", variable=self.valueEnDec, value=1).grid(row=4,column=1,columnspan=2,padx=50, pady=10)
        Radiobutton(t, text="Dekriptiranje", variable=self.valueEnDec, value=2).grid(row=4,column=3,columnspan=2,padx=50, pady=10)
        
    
    def create_window_RSA(self):
        t = Toplevel(self)
        t.wm_title("Window RSA")
        #DATA
        self.labelKeyPublic = StringVar()
        self.labelKeyPrivate = StringVar()
        self.labelInput = StringVar()
        self.labelOutput = StringVar()
        self.labelKeyPublic.set('C:/Users/Franjo/Documents/FER/NOS/Lab34/rsa_javni.txt')
        self.labelKeyPrivate.set('C:/Users/Franjo/Documents/FER/NOS/Lab34/rsa_privatni.txt')
        self.labelInput.set('C:/Users/Franjo/Documents/FER/NOS/Lab34/rsa_ulaz.txt')
        self.labelOutput.set('C:/Users/Franjo/Documents/FER/NOS/Lab34/rsa_izlaz.txt')
        t.l1 = Label(t, text="Javni kljuc:")
        #l.pack(side="top", fill="both", expand=True, padx=100, pady=100)
        t.l2 = Label(t, text="Ulazna datoteka:")
        t.l3 = Label(t, text="Izlazna datoteka:")
        t.l4 = Label(t, text="Privatni kljuc:")
        t.label1 = Label(t, textvariable = self.labelKeyPublic)
        t.label4 = Label(t, textvariable = self.labelKeyPrivate)
        t.label2 = Label(t, textvariable = self.labelInput)
        t.label3 = Label(t, textvariable = self.labelOutput)
        self.valueEnDec = IntVar()
        self.valueEnDec.set(1)
        
        t.button1Odaberi = Button(t, text="Odaberi")
        t.button2Odaberi = Button(t, text="Odaberi")
        t.button3Odaberi = Button(t, text="Odaberi")
        t.button4Odaberi = Button(t, text="Odaberi")
        t.button1Odaberi.bind("<ButtonPress-1>", lambda event,arg=1: self.choose_file( event,arg,'RSA'))
        t.button2Odaberi.bind("<ButtonPress-1>", lambda event,arg=2: self.choose_file( event,arg,'RSA'))
        t.button3Odaberi.bind("<ButtonPress-1>", lambda event,arg=3: self.choose_file( event,arg,'RSA'))
        t.button4Odaberi.bind("<ButtonPress-1>", lambda event,arg=4: self.choose_file( event,arg,'RSA'))
        t.button1Pregledaj = Button(t, text="Pregledaj")
        t.button2Pregledaj = Button(t, text="Pregledaj")
        t.button3Pregledaj = Button(t, text="Pregledaj")
        t.button4Pregledaj = Button(t, text="Pregledaj")
        t.button1Pregledaj.bind("<ButtonPress-1>", lambda event,arg1=self.labelKeyPublic.get(),arg2=1: self.create_window(event, arg1,arg2,'RSA', self.key))
        t.button2Pregledaj.bind("<ButtonPress-1>", lambda event,arg1=self.labelKeyPrivate.get(),arg2=2: self.create_window(event, arg1,arg2,'RSA', self.key))
        t.button3Pregledaj.bind("<ButtonPress-1>", lambda event,arg1=self.labelInput.get(),arg2=3: self.create_window(event, arg1,arg2,'RSA', self.data))
        t.button4Pregledaj.bind("<ButtonPress-1>", lambda event,arg1=self.labelOutput.get(),arg2=4: self.create_window(event, arg1,arg2,'RSA', self.crypted))
        t.buttonGeneriraj = Button(t, text="Generiraj")
        t.buttonGeneriraj.bind("<ButtonPress-1>", lambda arg2=self.labelKeyPublic.get(),tip=2: self.generateKey(arg2,tip))
        t.buttonCodeDecode = Button(t, text="Obavi kriptiranje/dekriptiranje")
        t.buttonCodeDecode.bind("<ButtonPress-1>", lambda event,arg1="RSA": self.doJob(event,arg1))
        t.l1.grid(row=1,column=1, padx=10, pady=10)
        t.l2.grid(row=3,column=1, padx=10, pady=10)
        t.l3.grid(row=4,column=1, padx=10, pady=10)
        t.l4.grid(row=2,column=1, padx=10, pady=10)
        t.label1.grid(row=1,column=2, padx=50, pady=10)
        t.label2.grid(row=3,column=2, padx=50, pady=10)
        t.label3.grid(row=4,column=2, padx=50, pady=10)
        t.label4.grid(row=2,column=2, padx=50, pady=10)
        t.button1Odaberi.grid(row=1,column=3, padx=10, pady=10)
        t.button2Odaberi.grid(row=3,column=3, padx=10, pady=10)
        t.button3Odaberi.grid(row=4,column=3, padx=10, pady=10)
        t.button4Odaberi.grid(row=2,column=3, padx=10, pady=10)
        t.button1Pregledaj.grid(row=1,column=4, padx=10, pady=10)
        t.button2Pregledaj.grid(row=3,column=4, padx=10, pady=10)
        t.button3Pregledaj.grid(row=4,column=4, padx=10, pady=10)
        t.button4Pregledaj.grid(row=2,column=4, padx=10, pady=10)
        t.buttonGeneriraj.grid(row=1,column=5, padx=10, pady=10)
        t.buttonCodeDecode.grid(row=7,columnspan=5)
        

        Radiobutton(t, text="Kriptiranje", variable=self.valueEnDec, value=1).grid(row=5,column=1,columnspan=2,padx=50, pady=10)
        Radiobutton(t, text="Dekriptiranje", variable=self.valueEnDec, value=2).grid(row=5,column=3,columnspan=2,padx=50, pady=10)
        
    
    def create_window_SHA(self):
        t = Toplevel(self)
        t.wm_title("Window SHA")
        #DATA
        self.labelInput = StringVar()
        self.labelOutput = StringVar()
        self.labelSHA = StringVar()
        self.labelMySHA = StringVar()
        self.labelInput.set('C:/Users/Franjo/Documents/FER/NOS/Lab34/aes_ulaz.txt')
        t.l1 = Label(t, text="Kljuc:")
        #l.pack(side="top", fill="both", expand=True, padx=100, pady=100)
        t.l2 = Label(t, text="Ulazna datoteka:")
        t.l3 = Label(t, text="Izlazna datoteka:")
        t.label2 = Label(t, textvariable = self.labelInput)
        t.label3 = Label(t, textvariable = self.labelSHA)
        t.label4 = Label(t, textvariable = self.labelMySHA)
        self.valueEnDec = IntVar()
        self.valueEnDec.set(1)
        
        t.button2Odaberi = Button(t, text="Odaberi")
        t.button3Odaberi = Button(t, text="Odaberi")
        t.button2Odaberi.bind("<ButtonPress-1>", lambda event,arg=2: self.choose_file(event, arg,'SHA'))
        t.button3Odaberi.bind("<ButtonPress-1>", lambda event,arg=3: self.choose_file(event, arg,'SHA'))
        t.button2Pregledaj = Button(t, text="Pregledaj")
        t.button3Pregledaj = Button(t, text="Pregledaj")
        t.button2Pregledaj.bind("<ButtonPress-1>", lambda event,arg1=self.labelInput.get(),arg2=2: self.create_window(event, arg1,arg2,'SHA', self.data))
        t.button3Pregledaj.bind("<ButtonPress-1>", lambda event,arg1=self.labelSHA.get(),arg2=3: self.create_window(event, arg1,arg2,'SHA', self.crypted))
        t.buttonCodeDecode = Button(t, text="Obavi sazimanje")
        t.buttonCodeDecode.bind("<ButtonPress-1>", lambda event,arg1="SHA": self.doJob(event,arg1))
        t.l2.grid(row=1,column=1, padx=10, pady=10)
        t.l3.grid(row=2,column=1, padx=10, pady=10)
        t.label2.grid(row=1,column=2, padx=50, pady=10)
        t.label3.grid(row=2,column=2, padx=50, pady=10)
        t.label4.grid(row=3,column=2, padx=50, pady=10)
        t.button2Odaberi.grid(row=1,column=3, padx=10, pady=10)
        t.button3Odaberi.grid(row=2,column=3, padx=10, pady=10)
        t.button2Pregledaj.grid(row=1,column=4, padx=10, pady=10)
        t.button3Pregledaj.grid(row=2,column=4, padx=10, pady=10)
        t.buttonCodeDecode.grid(row=4,columnspan=5)
    
    
    def load_file(self,event,arg,tipCrip,SenderRecipient=None,filename=None):
        if filename==None:
            filename = askopenfilename()
        #INPUT FILE
        if arg==1:
            self.labelInput.set(filename)
            self.data=self.read_data(filename)
            #print self.data
            #self.label1.config(self.labelKey)
        #PUBLIC KEY
        elif arg==2:
            if(SenderRecipient=='Recipient'):
                self.labelPublicKeyRecipient.set(filename)
                self.keyPublicRecipient.update(self.read_data(filename))
            elif(SenderRecipient=='Sender'):
                self.labelPublicKeySender.set(filename)
                self.keyPublicSender.update(self.read_data(filename))
            #self.label2.config(self.labelInput)
        #PRIVATE KEY
        elif arg==3:
            if(SenderRecipient=='Recipient'):
                self.labelPrivateKeyRecipient.set(filename)
                self.keyPrivateRecipient.update(self.read_data(filename))
            elif(SenderRecipient=='Sender'):
                self.labelPrivateKeySender.set(filename)
                self.keyPrivateSender.update(self.read_data(filename))
        elif arg==4:
            self.labelOmotnica.set(filename)
            pass
        elif arg==5:
            self.labelPotpis.set(filename)
            pass
        else:
            self.labelPecat.set(filename)
            self.Pecat=self.read_data(filename)
            pass
        pass
    
    
    """
    
    OVO TREBA DOBRO NAPISATI
    
    """
    def save_file(self,event,filename,tip):
        fp = open(filename, "wb")
        put_header("Header",fp)
        if tip=='Omotnica':
            #print str(unicode(self.key['Secret key'][0]))
            write_data_d(name='Description',value1=["Secret key"],fp=fp)
            write_data_d(name='Method',value1=["AES","RSA"],fp=fp)
            #OVO TREBA PROMIJENITI
            print self.keyPublicRecipient
            write_data_d(name='Key length',value1=[(self.keyPublicRecipient['Key length'][0])[:]],fp=fp)
            write_data_d(name='Envelope data',value1=self.Omotnica['Text'],fp=fp)
            write_data_d(name='Envelope crypt key',value1=self.Omotnica['Key'],fp=fp)
        elif tip=='Potpis':
            #put_data_s('Data',self.output,None,fp=fp)
            write_data_d(name='Description',value1=["Crypted data"],fp=fp)
            write_data_d(name='Method',value1=["SHA-1","RSA"],fp=fp)
            #OVO TREBA PROMIJENITI
            write_data_d(name='Key length',value1=[('A0',self.keyPrivateSender['Key length'][0])[2:]],fp=fp)
            write_data_d(name='Signature',value1=self.Potpis['Key'],fp=fp)
            write_data_d(name='Envelope data',value1=self.Potpis['Text'],fp=fp)
            #write_data_d(name='Data',value1=self.crypted,fp=fp)
            
        elif tip=='Pecat':
            #print self.key
            write_data_d(name='Description',value1=["Public key"],fp=fp)
            write_data_d(name='Method',value1=["AES","RSA","SHA-1"],fp=fp)
            write_data_d(name='Key length',value1=[(self.keyPublicRecipient['Key length'][0])[:],'A0'],fp=fp)
            write_data_d(name='Envelope data',value1=self.Pecat['Envelope data'],fp=fp)
            write_data_d(name='Envelope crypt key',value1=self.Pecat['Envelope crypt key'],fp=fp)
            write_data_d(name='Signature',value1=self.Pecat['Signature'],fp=fp)
        elif tip=='Otvori':
            write_data_d(name='Description',value1=["Message"],fp=fp)
            write_data_d(name='Data',value1=self.data['Data'],fp=fp)
            write_data_d(name='Signature',value1=self.data['Hash'],fp=fp)
        put_footer("Footer",fp)
        fp.close()
        pass
    
    def prepData(self,Input):
        return b64decode(''.join(Input))
        pass
    
    def prepOutputData(self,Input):
        Input = b64encode(Input)
        outputList=[]
        turns=int(math.ceil(len(Input)/float(60)))
        for i in range(0,turns):
            if i==0:
                outputList.append(Input[0:60])
            elif i!=turns-1:
                outputList.append(Input[i*60:(i+1)*60])
            else:
                outputList.append(Input[(turns-1)*60:])
        return outputList
        pass
    
    
    def DigitalnaOmotnica(self,event,arg):
        #ako je 1 napravi omotnicu
        if arg==1:
            #n=''.join(self.keyPublicRecipient['Modulus'])
            #e=''.join(self.keyPublicRecipient['Public exponent'])
            n=self.prepData(self.keyPublicRecipient['Modulus'])
            e=self.prepData(self.keyPublicRecipient['Public exponent'])
            #print type(n)
            text = ''.join(self.data['Data'])   
            Cipher=RSACipher(n,e)
            Envelope = Cipher.createEnvelope(text)
            #print cryptedText
            #cryptedKey="".join([ch.encode("hex") for ch in cryptedKey])
            #chunks, chunk_size = len(cryptedKey), len(cryptedKey)/2
            self.Omotnica['Key']=self.prepOutputData(Envelope['Key'])
            self.Omotnica['Text']=self.prepOutputData(Envelope['Data'])
            pass
        else:
            #n=''.join(self.keyPrivateRecipient['Modulus'])
            #d=''.join(self.keyPrivateRecipient['Private exponent'])
            #e=''.join(self.keyPrivateRecipient['Public exponent'])
            n=self.prepData(self.keyPrivateRecipient['Modulus'])
            d=self.prepData(self.keyPrivateRecipient['Private exponent'])
            e=self.prepData(self.keyPrivateRecipient['Public exponent'])
            Decipher = RSACipher(n,e,d)
            Envelope = {}
            Envelope['Key']=self.prepData(self.data['Envelope crypt key'])
            Envelope['Data']=self.prepData(self.data['Envelope data'])
            EnvelopeData = Decipher.openEnvelope(Envelope['Key'],Envelope['Data'])
            
            print EnvelopeData
            self.data['Data'] = EnvelopeData
            pass
        
        #inace otkljucaj
        pass
    
    def DigitalniPotpis(self,event,arg):
         m = hashlib.sha1()
         if arg==1:
             #print self.keyPrivateSender
             #n=''.join(self.keyPrivateSender['Modulus'])
             #e=''.join(self.keyPrivateSender['Public exponent'])
             #d=''.join(self.keyPrivateSender['Private exponent'])
             n=self.prepData(self.keyPrivateSender['Modulus'])
             e=self.prepData(self.keyPrivateSender['Public exponent'])
             d=self.prepData(self.keyPrivateSender['Private exponent'])
             #print e
             Cipher=RSACipher(n,e,d)
             text = ''.join(self.data['Data'])
             signature = Cipher.createSignature(text)
             
             #print cryptedHash
             #print cryptedText
             self.Potpis['Key']=self.prepOutputData(signature['Signature'])
             self.Potpis['Text']=self.prepOutputData(signature['Data'])
             #print self.Potpis['Text']
             pass
         else:
             n=''.join(self.keyPublicSender['Modulus'])
             #d=''.join(self.keyPrivateSender['Private exponent'])
             e=''.join(self.keyPublicSender['Public exponent'])
             
             n=self.prepData(self.keyPublicSender['Modulus'])
             #d=''.join(self.keyPrivateSender['Private exponent'])
             e=self.prepData(self.keyPublicSender['Public exponent'])
             
             CipherForSignature=RSACipher(n,e)
             """
             MORAS SREDITI DOBAVLJANJE POTPISA
             """
             signature = self.prepData(self.data['Signature'])
             #key = self.prepData(self.data['Envelope crypt key'])
             data = self.prepData(self.data['Envelope data'])
             VerifySignature = CipherForSignature.verifySignature(signature,data)
             decryptedKey=[]
             #decryptedKey.append(decryptKey.decrypt(text))
             
             print VerifySignature
             pass
         pass
    
    
    def missingPadding(self,data):
        missing_padding = len(data) % 4
        if missing_padding != 0:
            data += b'='* (4 - missing_padding)
        return data
    
    def DigitalniPecat(self,event,arg):
         m = hashlib.sha1()
         if arg==1:
             #print self.keyPublicRecipient
             #print self.keyPrivateSender
             nP=self.prepData(self.keyPublicRecipient['Modulus'])
             eP=self.prepData(self.keyPublicRecipient['Public exponent'])
             nS=self.prepData(self.keyPrivateSender['Modulus'])
             dS=self.prepData(self.keyPrivateSender['Private exponent'])
             eS=self.prepData(self.keyPrivateSender['Public exponent'])
             
             #nP=''.join(self.keyPublicRecipient['Modulus'])
             #eP=''.join(self.keyPublicRecipient['Public exponent'])
             #nS=''.join(self.keyPrivateSender['Modulus'])
             #dS=''.join(self.keyPrivateSender['Private exponent'])
             #eS=''.join(self.keyPrivateSender['Public exponent'])
             
             
             print self.data['Data']
             text = ''.join(self.data['Data'])
             
             CipherForEnvelope=RSACipher(nP,eP)
             Envelope = CipherForEnvelope.createEnvelope(text)
             
             CipherForSignature=RSACipher(nS,eS,dS)
             #SignedEnvelope = CipherForSignature.createSignature(Envelope['Key']+Envelope['Data'])
             m.update(Envelope['Key']+Envelope['Data'])
             hashOut = m.hexdigest()
             print type(hashOut)
             myhashOut = myOwnSha(Envelope['Key']+Envelope['Data'])
             print hashOut
             #print hex(myhashOut)[2:-1]
             codedHash = CipherForSignature.encode(hashOut)
             #print codedHash
             signature=CipherForSignature.key.sign(myhashOut,32)
             print signature
             print signature[0]
             self.Pecat['Envelope data']=self.prepOutputData(Envelope['Data'])
             self.Pecat['Envelope crypt key']=self.prepOutputData(Envelope['Key'])
             #self.Pecat['Signature']=self.prepOutputData(SignedEnvelope['Signature'])
             self.Pecat['Signature']=self.prepOutputData(hex(signature[0]))
             #print b64decode(codedHash)
             #print "CODED HASH:",codedHash
             """
             
             SREDITI PECAT!!!
             
             """
             pass
         else:
            #nP=''.join(self.keyPrivateRecipient['Modulus'])
            #dP=''.join(self.keyPrivateRecipient['Private exponent'])
            #eP=''.join(self.keyPrivateRecipient['Public exponent'])
            #nS=''.join(self.keyPublicSender['Modulus'])
            #eS=''.join(self.keyPublicSender['Public exponent'])
            nP=self.prepData(self.keyPrivateRecipient['Modulus'])
            dP=self.prepData(self.keyPrivateRecipient['Private exponent'])
            eP=self.prepData(self.keyPrivateRecipient['Public exponent'])
            nS=self.prepData(self.keyPublicSender['Modulus'])
            eS=self.prepData(self.keyPublicSender['Public exponent'])
            
            #print b64decode(nP)
            #print b64decode(dP)
            #print b64decode(eP)
            #print b64decode(nS)
            #print b64decode(eS)
            
            DecypherForEnvelope=RSACipher(nP,eP,dP)
            DecypherForSignature=RSACipher(nS,eS)
            
            signature =  self.prepData(self.data['Signature'])
            data =  self.prepData(self.data['Envelope data'])
            key = self.prepData( self.data['Envelope crypt key'])
            print signature
            
            EnvelopeData = DecypherForEnvelope.openEnvelope(key,data)
            #VerifySignature = DecypherForSignature.verifySignature(signature,key+data)
            getHash=myOwnSha(key+data)
            m.update(key+data)
            hashOut = m.hexdigest()
            #hex(getHash)[2:-1]
            #valid = DecypherForSignature.key.verify(hex(getHash)[2:-1],(long(signature,16),))
            valid = DecypherForSignature.key.verify(hashOut,(long(signature,16),))
            #openHash = DecypherForEnvelope.decode(b64encode(signature))
            #print openHash
            #print type(openHash)
            #print long(openHash,16)
            #print hex(getHash)[2:-1]
            print hashOut
            #print b64decode(self.missingPadding(openHash))
            print valid
            if (valid):
                print EnvelopeData
            self.data['Data']=self.prepOutputData(EnvelopeData)
            self.data['Hash']=self.prepOutputData(EnvelopeData)
            
            pass
         pass
    
    
     
    def create_window_digitalnaOmotnica(self):
        t = Toplevel(self)
        t.wm_title("Window Digitalna Omotnica")
        #DATA
        self.labelInput = StringVar()
        self.labelPublicKeyRecipient = StringVar()
        self.labelOmotnica = StringVar()
        self.labelInput.set('C:/Users/Franjo/Documents/FER/NOS/Lab34/ulaz.txt')
        self.labelPublicKeyRecipient.set('C:/Users/Franjo/Documents/FER/NOS/Lab34/javni_kljuc_primatelj.txt')
        self.labelOmotnica.set('C:/Users/Franjo/Documents/FER/Diplomski/Napredni operacijski sustavi/Labosi/Lab34/omotnica.txt')
        t.l1 = Label(t, text="Ulazna datoteka:")
        #l.pack(side="top", fill="both", expand=True, padx=100, pady=100)
        t.l2 = Label(t, text="Javni kljuc primatelja:")
        t.l3 = Label(t, text="Digitalna omotnica:")
        t.label1 = Label(t, textvariable = self.labelInput)
        t.label2 = Label(t, textvariable = self.labelPublicKeyRecipient)
        t.label3 = Label(t, textvariable = self.labelOmotnica)
                
        t.button1Odaberi = Button(t, text="Odaberi")
        t.button2Odaberi = Button(t, text="Odaberi")
        t.button3Odaberi = Button(t, text="Odaberi")
        t.button1Odaberi.bind("<ButtonPress-1>", lambda event,arg=1: self.load_file(event, arg,'Digitalna Omotnica'))
        t.button2Odaberi.bind("<ButtonPress-1>", lambda event,arg=2,arg2='Recipient': self.load_file(event, arg,'Digitalna Omotnica',arg2))
        t.button3Odaberi.bind("<ButtonPress-1>", lambda event,arg=4: self.load_file(event, arg,'Digitalna Omotnica'))
        t.button1Pregledaj = Button(t, text="Pregledaj")
        t.button2Pregledaj = Button(t, text="Pregledaj")
        t.button3Pregledaj = Button(t, text="Spremi")
        t.button1Pregledaj.bind("<ButtonPress-1>", lambda event,arg1=self.labelInput.get(),arg2=1: self.create_window(event, arg1,arg2,'Digitalna Omotnica', self.key))
        t.button2Pregledaj.bind("<ButtonPress-1>", lambda event,arg1=self.labelPublicKeyRecipient.get(),arg2=2: self.create_window(event, arg1,arg2,'Digitalna Omotnica', self.data))
        #t.button3Pregledaj.bind("<ButtonPress-1>", lambda event,arg1=self.labelOmotnica.get(),arg2=3: self.create_window(event, arg1,arg2,'Digitalna Omotnica', self.crypted))
        t.button3Pregledaj.bind("<ButtonPress-1>", lambda event,arg1=self.labelOmotnica.get(): self.save_file(event, arg1,'Omotnica'))
        t.buttonGeneriraj = Button(t, text="Generiraj digitalnu omotnicu")
        t.buttonGeneriraj.bind("<ButtonPress-1>", lambda event,arg1=1: self.DigitalnaOmotnica(event,arg1))
        t.l1.grid(row=1,column=1, padx=10, pady=10)
        t.l2.grid(row=2,column=1, padx=10, pady=10)
        t.l3.grid(row=3,column=1, padx=10, pady=10)
        t.label1.grid(row=1,column=2, padx=50, pady=10)
        t.label2.grid(row=2,column=2, padx=50, pady=10)
        t.label3.grid(row=3,column=2, padx=50, pady=10)
        t.button1Odaberi.grid(row=1,column=3, padx=10, pady=10)
        t.button2Odaberi.grid(row=2,column=3, padx=10, pady=10)
        t.button3Odaberi.grid(row=3,column=3, padx=10, pady=10)
        t.button1Pregledaj.grid(row=1,column=4, padx=10, pady=10)
        t.button2Pregledaj.grid(row=2,column=4, padx=10, pady=10)
        t.button3Pregledaj.grid(row=3,column=4, padx=10, pady=10)
        t.buttonGeneriraj.grid(row=4,columnspan=5)
        
        self.labelPrivateKeyRecipient = StringVar()
        self.labelOutput = StringVar()
        self.labelPrivateKeyRecipient.set('C:/Users/Franjo/Documents/FER/NOS/Lab34/privatni_kljuc_primatelj.txt')
        self.labelOutput.set('C:/Users/Franjo/Documents/FER/NOS/Lab34/poruka.txt')
        t.l4 = Label(t, text="Tajni kljuc primatelja:")
        t.l5 = Label(t, text="Izlazna datoteka:")
        t.label4 = Label(t, textvariable = self.labelPrivateKeyRecipient)
        t.label5 = Label(t, textvariable = self.labelOutput)
        t.l4.grid(row=5,column=1, padx=10, pady=10)
        t.l5.grid(row=6,column=1, padx=10, pady=10)
        t.label4.grid(row=5,column=2, padx=50, pady=10)
        t.label5.grid(row=6,column=2, padx=50, pady=10)
        t.button5Odaberi = Button(t, text="Odaberi")
        t.button6Odaberi = Button(t, text="Odaberi")
        t.button5Odaberi.bind("<ButtonPress-1>", lambda event,arg=3,arg2='Recipient': self.load_file(event, arg,'Digitalna Omotnica',arg2))
        t.button6Odaberi.bind("<ButtonPress-1>", lambda event,arg=4: self.load_file(event, arg,'Digitalna Omotnica'))
        t.button5Odaberi.grid(row=5,column=3, padx=10, pady=10)
        t.button6Odaberi.grid(row=6,column=3, padx=10, pady=10)
        t.button5Pregledaj = Button(t, text="Pregledaj")
        t.button6Pregledaj = Button(t, text="Pregledaj")
        t.button5Pregledaj.bind("<ButtonPress-1>", lambda event,arg1=self.labelInput.get(),arg2=1: self.create_window(event, arg1,arg2,'AES', self.key))
        t.button6Pregledaj.bind("<ButtonPress-1>", lambda event,arg1=self.labelPrivateKeyRecipient.get(),arg2=2: self.create_window(event, arg1,arg2,'AES', self.data))
        t.button5Pregledaj.grid(row=5,column=4, padx=10, pady=10)
        t.button6Pregledaj.grid(row=6,column=4, padx=10, pady=10)
        t.buttonOtvori = Button(t, text="Otvori digitalnu omotnicu")
        t.buttonOtvori.bind("<ButtonPress-1>", lambda event,arg1=2: self.DigitalnaOmotnica(event,arg1))
        t.buttonOtvori.grid(row=7,columnspan=5)
        
        pass
        
    def create_window_digitalniPotpis(self):
        t = Toplevel(self)
        t.wm_title("Window Digitalni Potpis")
        #DATA
        self.labelInput = StringVar()
        self.labelPrivateKeySender = StringVar()
        self.labelPotpis = StringVar()
        self.labelInput.set('C:/Users/Franjo/Documents/FER/NOS/Lab34/ulaz.txt')
        self.labelPrivateKeySender.set('C:/Users/Franjo/Documents/FER/NOS/Lab34/tajni_kljuc_posiljatelja.txt')
        self.labelPotpis.set('C:/Users/Franjo/Documents/FER/Diplomski/Napredni operacijski sustavi/Labosi/Lab34/potpis.txt')
        t.l1 = Label(t, text="Ulazna datoteka:")
        #l.pack(side="top", fill="both", expand=True, padx=100, pady=100)
        t.l2 = Label(t, text="Tajni kljuc primatelja:")
        t.l3 = Label(t, text="Digitalni potpis:")
        t.label1 = Label(t, textvariable = self.labelInput)
        t.label2 = Label(t, textvariable = self.labelPrivateKeySender)
        t.label3 = Label(t, textvariable = self.labelPotpis)
                
        t.button1Odaberi = Button(t, text="Odaberi")
        t.button2Odaberi = Button(t, text="Odaberi")
        t.button3Odaberi = Button(t, text="Odaberi")
        t.button1Odaberi.bind("<ButtonPress-1>", lambda event,arg=1: self.load_file(event, arg,'Digitalni potpis'))
        t.button2Odaberi.bind("<ButtonPress-1>", lambda event,arg=3,arg2='Sender': self.load_file(event, arg,'Digitalni potpis',arg2))
        t.button3Odaberi.bind("<ButtonPress-1>", lambda event,arg=5: self.load_file(event, arg,'Digitalni potpis'))
        t.button1Pregledaj = Button(t, text="Pregledaj")
        t.button2Pregledaj = Button(t, text="Pregledaj")
        t.button3Pregledaj = Button(t, text="Spremi")
        t.button1Pregledaj.bind("<ButtonPress-1>", lambda event,arg1=self.labelInput.get(),arg2=1: self.create_window(event, arg1,arg2,'Digitalni potpis', self.key))
        t.button2Pregledaj.bind("<ButtonPress-1>", lambda event,arg1=self.labelPrivateKeySender.get(),arg2=2: self.create_window(event, arg1,arg2,'Digitalni potpis', self.data))
        #t.button3Pregledaj.bind("<ButtonPress-1>", lambda event,arg1=self.labelPotpis.get(),arg2=3: self.create_window(event, arg1,arg2,'Digitalni potpis', self.crypted))
        t.button3Pregledaj.bind("<ButtonPress-1>", lambda event,arg1=self.labelPotpis.get(): self.save_file(event, arg1,'Potpis'))
        t.buttonGeneriraj = Button(t, text="Generiraj digitalni potpis")
        t.buttonGeneriraj.bind("<ButtonPress-1>", lambda event,arg1=1: self.DigitalniPotpis(event,arg1))
        t.l1.grid(row=1,column=1, padx=10, pady=10)
        t.l2.grid(row=2,column=1, padx=10, pady=10)
        t.l3.grid(row=3,column=1, padx=10, pady=10)
        t.label1.grid(row=1,column=2, padx=50, pady=10)
        t.label2.grid(row=2,column=2, padx=50, pady=10)
        t.label3.grid(row=3,column=2, padx=50, pady=10)
        t.button1Odaberi.grid(row=1,column=3, padx=10, pady=10)
        t.button2Odaberi.grid(row=2,column=3, padx=10, pady=10)
        t.button3Odaberi.grid(row=3,column=3, padx=10, pady=10)
        t.button1Pregledaj.grid(row=1,column=4, padx=10, pady=10)
        t.button2Pregledaj.grid(row=2,column=4, padx=10, pady=10)
        t.button3Pregledaj.grid(row=3,column=4, padx=10, pady=10)
        t.buttonGeneriraj.grid(row=4,columnspan=5)
        
        self.labelPublicKeySender = StringVar()
        self.labelPublicKeySender.set('C:/Users/Franjo/Documents/FER/NOS/Lab34/javni_kljuc_posiljatelja.txt')
        t.l4 = Label(t, text="Javni kljuc postljatelja:")
        t.label4 = Label(t, textvariable = self.labelPublicKeySender)
        t.l4.grid(row=5,column=1, padx=10, pady=10)
        t.label4.grid(row=5,column=2, padx=50, pady=10)
        t.button4Odaberi = Button(t, text="Odaberi")
        t.button4Odaberi.bind("<ButtonPress-1>", lambda event,arg=2,arg2='Sender': self.load_file(event, arg,'Digitalni potpis',arg2))
        t.button4Pregledaj = Button(t, text="Pregledaj")
        t.button4Pregledaj.bind("<ButtonPress-1>", lambda event,arg1=self.labelPublicKeySender.get(),arg2=1: self.create_window(event, arg1,arg2,'Digitalni potpis', self.key))
        
        t.buttonOtvori = Button(t, text="Provjeri digitalni potpis")
        t.buttonOtvori.bind("<ButtonPress-1>", lambda event,arg1=2: self.DigitalniPotpis(event,arg1))
        t.button4Odaberi.grid(row=5,column=3, padx=10, pady=10)
        t.button4Pregledaj.grid(row=5,column=4, padx=10, pady=10)
        t.buttonOtvori.grid(row=6,columnspan=5)
        pass
    
    def create_window_digitalniPecat(self):
        t = Toplevel(self)
        t.wm_title("Window Digitalni Pecat")
        #DATA
        self.labelInput = StringVar()
        self.labelPublicKeyRecipient = StringVar()
        self.labelPrivateKeySender = StringVar()
        self.labelPecat = StringVar()
        self.labelInput.set('C:/Users/Franjo/Documents/FER/NOS/Lab34/ulaz.txt')
        self.labelPublicKeyRecipient.set('C:/Users/Franjo/Documents/FER/NOS/Lab34/javni_kljuc_primatelja.txt')
        self.labelPrivateKeySender.set('C:/Users/Franjo/Documents/FER/NOS/Lab34/tajni_kljuc_posiljatelja.txt')
        self.labelPecat.set('C:/Users/Franjo/Documents/FER/Diplomski/Napredni operacijski sustavi/Labosi/Lab34/pecat.txt')
        t.l1 = Label(t, text="Ulazna datoteka:")
        #l.pack(side="top", fill="both", expand=True, padx=100, pady=100)
        t.l2 = Label(t, text="Javni kljuc primatelja:")
        t.l3 = Label(t, text="Tajni kljuc posiljatelja:")
        t.l4 = Label(t, text="Digitalni pecat:")
        t.label1 = Label(t, textvariable = self.labelInput)
        t.label2 = Label(t, textvariable = self.labelPublicKeyRecipient)
        t.label3 = Label(t, textvariable = self.labelPrivateKeySender)
        t.label4 = Label(t, textvariable = self.labelPecat)
                
        t.button1Odaberi = Button(t, text="Odaberi")
        t.button2Odaberi = Button(t, text="Odaberi")
        t.button3Odaberi = Button(t, text="Odaberi")
        t.button4Odaberi = Button(t, text="Odaberi")
        t.button1Odaberi.bind("<ButtonPress-1>", lambda event,arg=1: self.load_file(event, arg,'Digitalni pecat'))
        t.button2Odaberi.bind("<ButtonPress-1>", lambda event,arg=2,arg2='Recipient': self.load_file(event, arg,'Digitalni pecat',arg2))
        t.button3Odaberi.bind("<ButtonPress-1>", lambda event,arg=3,arg2='Sender': self.load_file(event, arg,'Digitalni pecat',arg2))
        t.button4Odaberi.bind("<ButtonPress-1>", lambda event,arg=6: self.load_file(event, arg,'Digitalni pecat'))
        t.button1Pregledaj = Button(t, text="Pregledaj")
        t.button2Pregledaj = Button(t, text="Pregledaj")
        t.button3Pregledaj = Button(t, text="Pregledaj")
        t.button4Pregledaj = Button(t, text="Spremi")
        t.button1Pregledaj.bind("<ButtonPress-1>", lambda event,arg1=self.labelInput.get(),arg2=1: self.create_window(event, arg1,arg2,'Digitalni pecat', self.key))
        t.button2Pregledaj.bind("<ButtonPress-1>", lambda event,arg1=self.labelPublicKeyRecipient.get(),arg2=2: self.create_window(event, arg1,arg2,'Digitalni pecat', self.data))
        t.button3Pregledaj.bind("<ButtonPress-1>", lambda event,arg1=self.labelPrivateKeySender.get(),arg2=3: self.create_window(event, arg1,arg2,'Digitalni pecat', self.crypted))
        #t.button4Pregledaj.bind("<ButtonPress-1>", lambda event,arg1=self.labelPecat.get(),arg2=3: self.create_window(event, arg1,arg2,'Digitalni pecat', self.crypted))
        t.button4Pregledaj.bind("<ButtonPress-1>", lambda event,arg1=self.labelPecat.get(): self.save_file(event, arg1,'Pecat'))
        t.buttonGeneriraj = Button(t, text="Generiraj digitalni pecat")
        t.buttonGeneriraj.bind("<ButtonPress-1>", lambda event,arg1=1: self.DigitalniPecat(event,arg1))
        t.l1.grid(row=1,column=1, padx=10, pady=10)
        t.l2.grid(row=2,column=1, padx=10, pady=10)
        t.l3.grid(row=3,column=1, padx=10, pady=10)
        t.l4.grid(row=4,column=1, padx=10, pady=10)
        t.label1.grid(row=1,column=2, padx=50, pady=10)
        t.label2.grid(row=2,column=2, padx=50, pady=10)
        t.label3.grid(row=3,column=2, padx=50, pady=10)
        t.label4.grid(row=4,column=2, padx=50, pady=10)
        t.button1Odaberi.grid(row=1,column=3, padx=10, pady=10)
        t.button2Odaberi.grid(row=2,column=3, padx=10, pady=10)
        t.button3Odaberi.grid(row=3,column=3, padx=10, pady=10)
        t.button4Odaberi.grid(row=4,column=3, padx=10, pady=10)
        t.button1Pregledaj.grid(row=1,column=4, padx=10, pady=10)
        t.button2Pregledaj.grid(row=2,column=4, padx=10, pady=10)
        t.button3Pregledaj.grid(row=3,column=4, padx=10, pady=10)
        t.button4Pregledaj.grid(row=4,column=4, padx=10, pady=10)
        t.buttonGeneriraj.grid(row=5,columnspan=5)
        
        self.labelPublicKeySender = StringVar()
        self.labelPrivateKeyRecipient = StringVar()
        self.labelOutput = StringVar()
        self.labelPublicKeySender.set('C:/Users/Franjo/Documents/FER/NOS/Lab34/javni_kljuc_posiljatelja.txt')
        self.labelPrivateKeyRecipient.set('C:/Users/Franjo/Documents/FER/NOS/Lab34/tajni_kljuc_primatelja.txt')
        self.labelOutput.set('C:/Users/Franjo/Documents/FER/NOS/Lab34/aes_izlaz.txt')
        t.l5 = Label(t, text="Javni kljuc posiljatelja:")
        t.l6 = Label(t, text="Tajni kljuc primatelja:")
        t.l7 = Label(t, text="Izlazna datoteka:")
        t.label5 = Label(t, textvariable = self.labelPublicKeySender)
        t.label6 = Label(t, textvariable = self.labelPrivateKeyRecipient)
        t.label7 = Label(t, textvariable = self.labelOutput)
        t.l5.grid(row=6,column=1, padx=10, pady=10)
        t.l6.grid(row=7,column=1, padx=10, pady=10)
        t.l7.grid(row=8,column=1, padx=10, pady=10)
        t.label5.grid(row=6,column=2, padx=50, pady=10)
        t.label6.grid(row=7,column=2, padx=50, pady=10)
        t.label7.grid(row=8,column=2, padx=50, pady=10)
        t.button5Odaberi = Button(t, text="Odaberi")
        t.button6Odaberi = Button(t, text="Odaberi")
        t.button7Odaberi = Button(t, text="Odaberi")
        t.button5Odaberi.bind("<ButtonPress-1>", lambda event,arg=2,arg2='Sender': self.load_file(event, arg,'Digitalni pecat',arg2))
        t.button6Odaberi.bind("<ButtonPress-1>", lambda event,arg=3,arg2='Recipient': self.load_file(event, arg,'Digitalni pecat',arg2))
        t.button7Odaberi.bind("<ButtonPress-1>", lambda event,arg=6: self.load_file(event, arg,'Digitalni pecat'))
        t.button5Odaberi.grid(row=6,column=3, padx=10, pady=10)
        t.button6Odaberi.grid(row=7,column=3, padx=10, pady=10)
        t.button7Odaberi.grid(row=8,column=3, padx=10, pady=10)
        t.button5Pregledaj = Button(t, text="Pregledaj")
        t.button6Pregledaj = Button(t, text="Pregledaj")
        t.button7Pregledaj = Button(t, text="Pregledaj")
        t.button5Pregledaj.bind("<ButtonPress-1>", lambda event,arg1=self.labelPublicKeySender.get(),arg2=1: self.create_window(event, arg1,arg2,'Digitalni pecat', self.key))
        t.button6Pregledaj.bind("<ButtonPress-1>", lambda event,arg1=self.labelPublicKeyRecipient.get(),arg2=2: self.create_window(event, arg1,arg2,'Digitalni pecat', self.data))
        #t.button7Pregledaj.bind("<ButtonPress-1>", lambda event,arg1=self.labelOutput.get(),arg2=2: self.create_window(event, arg1,arg2,'Digitalni pecat', self.data))
        t.button7Pregledaj.bind("<ButtonPress-1>", lambda event,arg1=self.labelOutput.get(): self.save_file(event, arg1,'Pecat'))
        t.button5Pregledaj.grid(row=6,column=4, padx=10, pady=10)
        t.button6Pregledaj.grid(row=7,column=4, padx=10, pady=10)
        t.button7Pregledaj.grid(row=8,column=4, padx=10, pady=10)
        t.buttonOtvori = Button(t, text="Otvori digitalnu omotnicu")
        t.buttonOtvori.bind("<ButtonPress-1>", lambda event,arg1=2: self.DigitalniPecat(event,arg1))
        t.buttonOtvori.grid(row=9,columnspan=5)
        pass
        
    
    
    def say_hi(self):
        print "hi there, everyone!"
    
    
    def __init__(self, master=None,arg=1):
        Frame.__init__(self,master)
        self.parent=master
        self.pack()
        self.data={}
        self.key={}
        self.keyPublic={}
        self.keyPublicSender={}
        self.keyPublicRecipient={}
        self.keyPrivate={}
        self.keyPrivateSender={}
        self.keyPrivateRecipient={}
        self.Omotnica={}
        self.Potpis={}
        self.Pecat={}
        self.crypted=''
        self.plain=''
        self.output=''
        if arg==1:
            self.create_window_AES()
        elif arg==2:
            self.create_window_RSA()
            pass
        elif arg==3:
            self.create_window_SHA()
            pass
        elif arg==4:
            self.create_window_digitalnaOmotnica()
            pass
        elif arg==5:
            self.create_window_digitalniPotpis()
            pass
        else:
            self.create_window_digitalniPecat()
            pass
    pass



class Application(Frame):
    counter = 0
    
    def say_hi(self):
        print "hi there, everyone!"
    
    
    def create_window(self,parent,arg):
        print parent
        print arg
        dialog = Child_Window(self, arg )
        pass
    
    
    def new_data(self, data):
        self.data=data
    
    
    def createWidgets(self):

        self.hi_there = Button(self)
        self.hi_there["text"] = "Hello",
        self.hi_there["command"] = self.say_hi

        
        
        self.AES = Button(self)
        self.AES["text"] = "AES"
        self.AES["fg"]   = "blue"
        #self.AES["command"] =  self.create_window
        self.AES.bind("<ButtonPress-1>", lambda event,arg=1: self.create_window(self, arg))
        
        self.RSA = Button(self)
        self.RSA["text"] = "RSA"
        self.RSA["fg"]   = "blue"
        #self.RSA["command"] =  self.create_window
        self.RSA.bind("<ButtonPress-1>", lambda event,arg=2: self.create_window(self, arg))
        
        self.SHA = Button(self)
        self.SHA["text"] = "SHA"
        self.SHA["fg"]   = "blue"
        self.SHA.bind("<ButtonPress-1>", lambda event,arg=3: self.create_window(self, arg))
        #self.SHA["command"] =  self.create_window
        
        #self.button = Button(self, text="Create new window", command=self.create_window)
        #self.button.bind("<ButtonPress-1>", lambda event,arg=0: self.create_window(event, arg))
        
        self.digitalnaOmotnica = Button(self)
        self.digitalnaOmotnica["text"] = "Digitalna Omotnica"
        self.digitalnaOmotnica["fg"]   = "red"
        self.digitalnaOmotnica.bind("<ButtonPress-1>", lambda event,arg=4: self.create_window(self, arg))
        
        
        self.digitalniPotpis = Button(self)
        self.digitalniPotpis["text"] = "Digitalni Potpis"
        self.digitalniPotpis["fg"]   = "red"
        self.digitalniPotpis.bind("<ButtonPress-1>", lambda event,arg=5: self.create_window(self, arg))
        
        
        self.digitalniPecat = Button(self)
        self.digitalniPecat["text"] = "Digitalni Pecat"
        self.digitalniPecat["fg"]   = "red"
        self.digitalniPecat.bind("<ButtonPress-1>", lambda event,arg=6: self.create_window(self, arg))
        
        
        #self.button.pack()
        self.AES.pack()
        self.RSA.pack()
        self.SHA.pack()
        #self.hi_there.pack()
        self.digitalnaOmotnica.pack()
        self.digitalniPotpis.pack()
        self.digitalniPecat.pack()
        

    def __init__(self, master=None):
        Frame.__init__(self, master)
        self.pack()
        self.createWidgets()
        self.data={}
        

root = Tk()
app = Application(master=root)
app.mainloop()