
"""
Created on Sun Sep 30 11:51:48 2018

@author: snehamuppala
"""
#import following libraries
from hashlib import md5
from base64 import b64decode
from base64 import b64encode
from Crypto import Random
from Crypto.Cipher import AES
import time

# Padding for the input data
BLOCK_SIZE = 16  # Bytes
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * \
                chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]
print("AES in the CBC mode")

class AESCBC:
    
    #generating 128 bit key
    def __init__(self, key):
        start_time = time.time()
        self.key = md5(key.encode('utf8')).hexdigest()
        print "Time taken to generate key %s seconds " % (time.time() - start_time)
        #print(self.key)
    #encryption
    def encrypt(self, raw):
        #padding
        raw = pad(raw)
        #initialization Vector
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return b64encode(iv + cipher.encrypt(raw))
    #Decryption
    def decrypt(self, enc):
        enc = b64decode(enc)
        #initialization Vector
        iv = enc[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        #unpadding
        return unpad(cipher.decrypt(enc[16:])).decode('utf8')
    
    
 #Function to check for correctness   
def compare(Plaintext, Decrypted):
    
        if(Plaintext==Decrypted):
            print("Success:original data is equal to decrypted data")
        else:
            print("Failure:original data is not equal to decrypted data ") 
        
#Files of 1kb and 1mb
File_1kb="/Users/snehamuppala/Desktop/computer_security/hw3/1kb.txt"
File_1mb="/Users/snehamuppala/Desktop/computer_security/hw3/1mb.txt"
#Files of 1kb and 1mb- to store encrypted data
File_1kb_Encrypted="/Users/snehamuppala/Desktop/computer_security/hw3/1kb_Encrypted_cbc.txt"
File_1mb_Encrypted="/Users/snehamuppala/Desktop/computer_security/hw3/1mb_Encrypted_cbc.txt"
#Files of 1kb and 1mb- to store Decrypted data
File_1kb_Decrypted="/Users/snehamuppala/Desktop/computer_security/hw3/1kb_Decrypted_cbc.txt"
File_1mb_Decrypted="/Users/snehamuppala/Desktop/computer_security/hw3/1mb_Decrypted_cbc.txt"

#reading files-plaintext
infile_1kb= open(File_1kb)
infile_1mb= open(File_1mb)
data_1kb=infile_1kb.read()
data_1mb=infile_1mb.read()


#encrypting and Decrypting 1kb and 1mb file
print(" ")
print("***********Encrption of 1kb File***********")
start_time = time.time()
Ciphertext_1kb=AESCBC(key).encrypt(data_1kb) 
print "Time taken to Encrypt File 1KB= %s seconds " % (time.time() - start_time)
total_time=(time.time() - start_time)
bytes_speed=(total_time)/len(data_1kb)
print ("Speed per byte to Encrypt File 1KB seconds :"+str(bytes_speed))


print(" ")
print("*************Encrption of 1MB File************")
start_time = time.time()
Ciphertext_1mb=AESCBC(key).encrypt(data_1mb)   
print "Time taken to Encrypt File 1MB= %s seconds" % (time.time() - start_time)
total_time=(time.time() - start_time)
bytes_speed=(total_time)/len(data_1mb)
print ("Speed per byte to Encrypt File 1MB seconds:"+str(bytes_speed))

outfile_1kb = open(File_1kb_Encrypted, 'wb')
outfile_1mb = open(File_1mb_Encrypted, 'wb')
#writing into files
outfile_1kb.write(Ciphertext_1kb)
outfile_1mb.write(Ciphertext_1mb)


cipher_1kb= open(File_1kb_Encrypted)
cipher_1mb= open(File_1mb_Encrypted)
cipher_1KB=cipher_1kb.read()
cipher_1MB=cipher_1mb.read()


print(" ")
print("***********Decrption of 1kb File***********")
start_time = time.time()
Decrypted_1kb=AESCBC(key).decrypt(Ciphertext_1kb)
print "Time taken to Decrypt File 1KB= %s seconds " % (time.time() - start_time)
total_time=(time.time() - start_time)
bytes_speed=(total_time)/len(Ciphertext_1kb)
print ("Speed per byte to Decrypt File 1KB in seconds :"+str(bytes_speed))

print(" ")
print("***********Decrption of 1mb File***********")
start_time = time.time()
Decrypted_1mb=AESCBC(key).decrypt(Ciphertext_1mb)
print "Time taken to Decrypt File 1MB= %s seconds " % (time.time() - start_time)
total_time=(time.time() - start_time)
bytes_speed=(total_time)/len(Ciphertext_1mb)
print ("Speed per byte to Decrypt File 1MB in seconds :"+str(bytes_speed))



outfile_1kb_DEC = open(File_1kb_Decrypted, 'wb')
outfile_1mb_DEC = open(File_1mb_Decrypted, 'wb')

outfile_1kb_DEC.write(Decrypted_1kb)
outfile_1mb_DEC.write(Decrypted_1mb)
print(" ")
print("checking for correctness:")
print("File-1kb:")
compare(data_1kb, Decrypted_1kb)
print("File-1mb:")
compare(data_1mb, Decrypted_1mb)

