#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
Created on Sun Sep 30 17:44:04 2018

@author: snehamuppala
"""

import sys
import hashlib


# BUF_SIZE is totally arbitrary, change for your app!
BUF_SIZE = 65536  # lets read stuff in 64kb chunks!

md5 = hashlib.md5()
sha1 = hashlib.sha1()
sha256 = hashlib.sha256()
sha512 = hashlib.sha512()
#SHA3_256 = hashlib.SHA3_256()
msg="/Users/snehamuppala/Desktop/computer_security/Sec_hw1_final.rtf"
infile = open(msg)
msgg=infile.read()
with open(msg, 'rb') as f:
    while True:
        data = f.read(BUF_SIZE)
        if not data:
            break
        md5.update(data)
        sha1.update(data)
        sha256.update(data)

print("MD5: {0}".format(md5.hexdigest()))
print("SHA1: {0}".format(sha1.hexdigest()))
print("SHA256: {0}".format(sha256.hexdigest()))
print("SHA512: {0}".format(sha512.hexdigest()))
#print("SHA3_256: {0}".format(SHA3_256.hexdigest()))
#SHA-256, SHA-512, and SHA3- 256.

