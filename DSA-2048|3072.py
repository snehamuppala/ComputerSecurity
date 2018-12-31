#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
Created on Mon Oct  1 11:31:20 2018

@author: snehamuppala
"""
#import following libraries
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa
import time
print(" ")
print("********2048 bit DSA**********")
start_time = time.time()
private_key = dsa.generate_private_key(key_size=2048,backend=default_backend())
print "Time taken to generate key 2048 bit  %s seconds" % (time.time() - start_time)


#Files of 1kb and 1mb
File_1kb="/Users/snehamuppala/Desktop/computer_security/hw3/1kb.txt"
File_1mb="/Users/snehamuppala/Desktop/computer_security/hw3/1mb.txt"
infile_1kb = open(File_1kb)
infile_1mb = open(File_1mb)

data_1kb=infile_1kb.read()
data_1mb=infile_1mb.read()

public_key = private_key.public_key()
print(" ")
print("*************Signature-1kb****************")
start_time = time.time()
#computing signature
signature_1kb = private_key.sign(data_1kb,hashes.SHA256())
print "Time taken to produce signature  %s seconds" % (time.time() - start_time)
total_time=(time.time() - start_time)
bytes_speed=(total_time)/len(File_1kb)
print ("Speed per byte to Produce :"+str(bytes_speed))
start_time = time.time()
#verifying the signature and hash
public_key.verify(signature_1kb,data_1kb,hashes.SHA256())
print "Time taken to verify signature  %s seconds" % (time.time() - start_time)

total_time=(time.time() - start_time)
bytes_speed=(total_time)/len(File_1kb)
print ("Speed per byte to Verify :"+str(bytes_speed))
#computing signature
print(" ")
#computing signature
print("*************Signature-1mb****************")
start_time = time.time()
signature_1mb = private_key.sign(data_1mb,hashes.SHA256())
print "Time taken to produce signature  %s seconds" % (time.time() - start_time)
total_time=(time.time() - start_time)
bytes_speed=(total_time)/len(File_1kb)
print ("Speed per byte to Produce :"+str(bytes_speed))
#verifying the signature and hash
start_time = time.time()
public_key.verify(signature_1mb,data_1mb,hashes.SHA256())
print "Time taken to verfy signature  %s seconds" % (time.time() - start_time)

total_time=(time.time() - start_time)
bytes_speed=(total_time)/len(File_1mb)
print ("Speed per byte to  Verify :"+str(bytes_speed))