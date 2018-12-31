#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
Created on Sun Sep 30 18:58:28 2018

@author: snehamuppala
"""

#import following libraries
from Crypto.PublicKey import RSA
import base64
from Crypto.Cipher import PKCS1_OAEP
import zlib
import time

print("2048-bit and 3072 bit RSA key, encrypt and decrypt of files above with PKCS #1 v2 OAEP")
#key generating - 2048 bits
start_time = time.time()
new_key_2048 = RSA.generate(2048, e=65537)
print "Time taken to generate key-2048 bits %s seconds" % (time.time() - start_time)
#The private key in PEM format
private_key_2048 = new_key_2048.exportKey("PEM")

#The public key in PEM Format
public_key_2048 = new_key_2048.publickey().exportKey("PEM")
#write private_key
fd = open("/Users/snehamuppala/Desktop/computer_security/private_key_2048.pem", "wb")
fd.write(private_key_2048)
fd.close()

#write public_key
fd = open("/Users/snehamuppala/Desktop/computer_security/public_key_2048.pem", "wb")
fd.write(public_key_2048)
fd.close()



#key generating - 3072 bits
start_time = time.time()
new_key_3072 = RSA.generate(3072, e=65537)
print "Time taken to generate key-3072 bits %s seconds " % (time.time() - start_time)
#The private key in PEM format
private_key_3072 = new_key_3072.exportKey("PEM")

#The public key in PEM Format
public_key_3072= new_key_3072.publickey().exportKey("PEM")
#write private_key
fd = open("/Users/snehamuppala/Desktop/computer_security/private_key_3072.pem", "wb")
fd.write(private_key_3072)
fd.close()

#write public_key
fd = open("/Users/snehamuppala/Desktop/computer_security/public_key_3072.pem", "wb")
fd.write(public_key_3072)
fd.close()





def encrypt(Plaintext, public_key,chunk_size):
    #Import the Public Key and use for encryption using PKCS1_OAEP
    rsa_key = RSA.importKey(public_key)
    rsa_key = PKCS1_OAEP.new(rsa_key)
    
    msgg = zlib.compress(Plaintext)

    offset = 0
    end_loop = False
    encrypted =  ""

    while not end_loop:
        #The chunk
        chunk = msgg[offset:offset + chunk_size]

        #If the data chunk is less then the chunk size, then we need to add
        #padding with " ". This indicates the we reached the end of the file
        #so we end loop here
        if len(chunk) % chunk_size != 0:
            end_loop = True
            chunk += " " * (chunk_size - len(chunk))

        #Append the encrypted chunk to the overall encrypted file
        encrypted += rsa_key.encrypt(chunk)

        #Increase the offset by chunk size
        offset += chunk_size

    #Base 64 encode the encrypted file
    return base64.b64encode(encrypted)



def decrypt(encrypted, private_key,chunk_size):

    #Import the Private Key and use for decryption using PKCS1_OAEP
    rsakey = RSA.importKey(private_key)
    rsakey = PKCS1_OAEP.new(rsakey)

    #Base 64 decode the data
    encrypted_blob = base64.b64decode(encrypted)
    

  
    offset = 0
    decrypted = ""

    #keep loop going as long as we have chunks to decrypt
    while offset < len(encrypted_blob):
        #The chunk
        chunk = encrypted_blob[offset: offset + chunk_size]
        #print(chunk)
        
        #Append the decrypted chunk to the overall decrypted file
        decrypted += rsakey.decrypt(chunk)
        

        #Increase the offset by chunk size
        offset += chunk_size
        
    #return the decompressed decrypted data
    return zlib.decompress(decrypted)

def compare(Plaintext, Decrypted):
    
        if(Plaintext==Decrypted):
            print("Success:original data is equal to decrypted data")
        else:
            print("Failure:original data is not equal to decrypted data ") 


#message = 'To be encrypted'
File_1kb="/Users/snehamuppala/Desktop/computer_security/hw3/1kb.txt"
File_1mb="/Users/snehamuppala/Desktop/computer_security/hw3/1mb.txt"

infile_1kb = open(File_1kb)
Plaintext_1kb=infile_1kb.read()
infile_1mb = open(File_1kb)
Plaintext_1mb=infile_1mb.read()
#2048-bit RSA key, encrypt and decrypt of files above with PKCS #1 v2 OAEP
#A 2048-bit key can encrypt up to (2048/8) – 42 = 256 – 42 = 214 bytes.
#Encryption chunk size=214,Decryption chunk size=256 in bytes
print(" ")
print("*Encryption and Decryption of 1kb and 1mb files--2048-bit RSA key-PKCS #1 v2 OAEP*")
      
      
start_time = time.time()      
encrypted_2048_1kb = encrypt(Plaintext_1kb, public_key_2048,214)
print "Time taken to Encrypt File 1KB= %s seconds" % (time.time() - start_time)
total_time=(time.time() - start_time)
bytes_speed=(total_time)/len(Plaintext_1kb)
print ("Speed per byte to Encrypt File 1KB :"+str(bytes_speed))




start_time = time.time()
decrypted_2048_1kb=decrypt(encrypted_2048_1kb,private_key_2048,256)
print "Time taken to Decrypt File 1KB= %s seconds" % (time.time() - start_time)
total_time=(time.time() - start_time)
bytes_speed=(total_time)/len(encrypted_2048_1kb)
print ("Speed per byte to Decrypt File 1KB :"+str(bytes_speed))



start_time = time.time()
encrypted_2048_1mb = encrypt(Plaintext_1mb, public_key_2048,214)
print "Time taken to Encrypt File 1MB= %s seconds" % (time.time() - start_time)
total_time=(time.time() - start_time)
bytes_speed=(total_time)/len(Plaintext_1mb)
print ("Speed per byte to Encrypt File 1MB :"+str(bytes_speed))



start_time = time.time()
decrypted_2048_1mb=decrypt(encrypted_2048_1mb,private_key_2048,256)
print "Time taken to Decrypt File 1MB= %s seconds" % (time.time() - start_time)
total_time=(time.time() - start_time)
bytes_speed=(total_time)/len(encrypted_2048_1mb)
print ("Speed per byte to Decrypt File 1MB :"+str(bytes_speed))

print("checking for correctness-2048 bit key")
print("File-1kb:")
compare(Plaintext_1kb,decrypted_2048_1kb)
print("File-1mb:")
compare(Plaintext_1mb,decrypted_2048_1mb)

#3072-bit RSA key, encrypt and decrypt of files above with PKCS #1 v2 OAEP
#A3072-bit key can encrypt up to (3072/8) – 42 = 384 – 42 = 342 bytes.
#Encryption chunk size=342,Decryption chunk size=384 in bytes
print(" ")
print("*Encryption and Decryption of 1kb and 1mb files--3072-bit RSA key-PKCS #1 v2 OAEP*")
start_time = time.time()      
encrypted_3072_1kb = encrypt(Plaintext_1kb, public_key_3072,342)
print "Time taken to Encrypt File 1KB= %s seconds" % (time.time() - start_time)
total_time=(time.time() - start_time)
bytes_speed=(total_time)/len(Plaintext_1kb)
print ("Speed per byte to Encrypt File 1KB :"+str(bytes_speed))



start_time = time.time()
decrypted_3072_1kb=decrypt(encrypted_3072_1kb,private_key_3072,384)
print "Time taken to Decrypt File 1KB= %s seconds" % (time.time() - start_time)
total_time=(time.time() - start_time)
bytes_speed=(total_time)/len(encrypted_3072_1kb)
print ("Speed per byte to Decrypt File 1KB :"+str(bytes_speed))


start_time = time.time()
encrypted_3072_1mb = encrypt(Plaintext_1mb, public_key_3072,342)
print "Time taken to Encrypt File 1MB= %s seconds" % (time.time() - start_time)
total_time=(time.time() - start_time)
bytes_speed=(total_time)/len(Plaintext_1mb)
print ("Speed per byte to Encrypt File 1MB :"+str(bytes_speed))


start_time = time.time()
decrypted_3072_1mb=decrypt(encrypted_3072_1mb,private_key_3072,384)
print "Time taken to Decrypt File 1MB= %s seconds" % (time.time() - start_time)
total_time=(time.time() - start_time)
bytes_speed=(total_time)/len(encrypted_3072_1mb)
print ("Speed per byte to Decrypt File 1MB :"+str(bytes_speed))





print("checking for correctness-3072 bit key")
print("File-1kb:")
compare(Plaintext_1kb,decrypted_3072_1kb)
print("File-1mb:")
compare(Plaintext_1mb,decrypted_3072_1mb)








