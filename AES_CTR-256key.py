#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
Created on Sun Sep 30 15:15:58 2018

@author: snehamuppala
"""
#import following libraries
import binascii
import os
from Crypto.Cipher import AES
from Crypto.Util import Counter
import time
print("AES in the CTR mode -256 bit key")
def int_of_string(s):
    return int(binascii.hexlify(iv), 16)
def encrypt_message(key, plaintext):
    #initialization Vector
    iv = Random.get_random_bytes(16)
    ctr = Counter.new(128, initial_value=int_of_string(iv))
    
    aes = AES.new(key, AES.MODE_CTR, counter=ctr)
    return iv + aes.encrypt(plaintext)
def decrypt_message(key, ciphertext):
    iv = ciphertext[:16]
    ctr = Counter.new(128, initial_value=int_of_string(iv))
    aes = AES.new(key, AES.MODE_CTR, counter=ctr)
    return aes.decrypt(ciphertext[16:])
#Function to check for correctness 
def compare(plaintext, decrypt):
    
    if(plaintext==decrypt):
        print("Success:original data is equal to decrypted data ")
    else:
        print("Failure: original data is not equal to decrypted data ")
        
        
 #Files of 1kb and 1mb       
File_1kb="/Users/snehamuppala/Desktop/computer_security/hw3/1kb.txt"
File_1mb="/Users/snehamuppala/Desktop/computer_security/hw3/1mb.txt"
#Files of 1kb and 1mb- to store encrypted data
File_1kb_Encrypted="/Users/snehamuppala/Desktop/computer_security/hw3/1kb_Encrypted_ctr.txt"
File_1mb_Encrypted="/Users/snehamuppala/Desktop/computer_security/hw3/1mb_Encrypted_ctr.txt"
#Files of 1kb and 1mb- to store Decrypted data
File_1kb_Decrypted="/Users/snehamuppala/Desktop/computer_security/hw3/1kb_Decrypted_ctr.txt"
File_1mb_Decrypted="/Users/snehamuppala/Desktop/computer_security/hw3/1mb_Decrypted_ctr.txt"
print(" ")
#key generating 256 bit
start_time = time.time()
key = Random.get_random_bytes(32)
print "Time taken to generate key 256 bit:  %s seconds" % (time.time() - start_time)

#reading files-plaintext
infile_1kb= open(File_1kb)
infile_1mb= open(File_1mb)

plaintext_1kb=infile_1kb.read()
plaintext_1mb=infile_1mb.read()
#encrypting and Decrypting 1kb and 1mb file
print(" ")
print("***********Encrption of 1kb File***********")
start_time = time.time()
ciphertext_1kb=encrypt_message(key,plaintext_1kb)
print "Time taken to Encrypt File 1KB= %s seconds " % (time.time() - start_time)
total_time=(time.time() - start_time)
bytes_speed=(total_time)/len(plaintext_1kb)
print ("Speed per byte to Encrypt File 1KB :"+str(bytes_speed))


print(" ")
print("***********Encrption of 1mb File***********")
start_time = time.time()
ciphertext_1mb=encrypt_message(key,plaintext_1mb)
print "Time taken to Encrypt File 1KB= %s seconds " % (time.time() - start_time)
total_time=(time.time() - start_time)
bytes_speed=(total_time)/len(plaintext_1mb)
print ("Speed per byte to Encrypt File 1KB :"+str(bytes_speed))


outfile_1kb = open(File_1kb_Encrypted, 'wb')

outfile_1mb = open(File_1mb_Encrypted, 'wb')


#writing into files
outfile_1kb.write(ciphertext_1kb)
outfile_1mb.write(ciphertext_1mb)


cipher_1kb= open(File_1kb_Encrypted)
cipher_1mb= open(File_1mb_Encrypted)
cipher_1KB=cipher_1kb.read()
cipher_1MB=cipher_1mb.read()
print(" ")
print("***********Decrption of 1kb File***********")
start_time = time.time()
Decrypted_1kb=decrypt_message(key,ciphertext_1kb)
print "Time taken to Decrypt File 1KB= %s seconds" % (time.time() - start_time)
total_time=(time.time() - start_time)
bytes_speed=(total_time)/len(cipher_1KB)
print ("Speed per byte to Decrypt File 1KB :"+str(bytes_speed))
print(" ")
print("***********Decrption of 1mb File***********")
start_time = time.time()
Decrypted_1mb=decrypt_message(key,ciphertext_1mb)
print "Time taken to Decrypt File 1MB= %s seconds " % (time.time() - start_time)
total_time=(time.time() - start_time)
bytes_speed=(total_time)/len(cipher_1MB)
print ("Speed per byte to Decrypt File 1MB :"+str(bytes_speed))




#writing into files
outfile_1kb_DEC = open(File_1kb_Decrypted, 'wb')
outfile_1mb_DEC = open(File_1mb_Decrypted, 'wb')
outfile_1kb_DEC.write(Decrypted_1kb)
outfile_1mb_DEC.write(Decrypted_1mb)

print(" ")

print("checking for correctness:")
print("File-1kb:")
compare(plaintext_1kb, Decrypted_1kb)
print("File-1mb:")
compare(plaintext_1mb, Decrypted_1mb)



