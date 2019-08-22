# ComputerSecurity


1. Encryption and Decryption per byte speed for 1mb is less compared to 1kb as it
takes time to initialise. Hashing per byte speed for 1mb files is also less compared
to hashing per byte speed of 1kb. For RSA, per byte speed of 1kb is less compared
to 1mb. Also in DSA, speed to produce and verify hash speed for 1kb is less than
1mb. Encryption for 1kb for AES is faster followed by RSA and SHA.
2. RSA is asymmetric encryption so, decryption takes longer time than encryption.
Also, decryption is slower than encryption, because the decryption exponent is
huge (whereas the encryption exponent is typically small. AES-CTR performance
is better in encryption and decryption compared to AES-CBC, because AES-CTR
is encode parallelizable and AES-CBC is Sequential. CTR does not require padding
but CBC does.
3. AES uses more rounds for larger keys, 10 for 128-bit keys, 14 for 256-bit keys.
So, key generation using 256 bit key in AES-CTR takes more time compared to
29
128 bit key generation. In RSA, 3072-bit key generation takes more time than
2048 key. As the key size increases, encryption and decryption takes more time,
because the key generation involves more rounds for larger keys. In DSA, 3072-bit
key generation takes more time than 2048 key. As the key size increases, encryption
and decryption takes more time, because the key generation involves more rounds
for larger keys.
4. SHA-512 performance is better compared to SHA-256 and. Especially when
the data is large. SHA3-256 and SHA-512 performance equally better. SHA-256
is recommended because it uses 32-byte hash values which is difficult to break.
SHA3-256 performance is better when the data size is less.
5. AES is symmetric cryptography that is it uses same key for both encryption and
decryption. RSA is asymmetric cryptography that is it uses a key to encrypt data
and then uses a different key for decryption. Public key is used for encryption
and private key for Decryption. Private key size is significantly large compared to
public key so, decryption takes more time. SHA is a hash algorithm that is one
way encryption. So it gives no way for decryption. AES performance is better
compared to RSA above because AES uses same key and key size is small.


![alt text](https://github.com/snehamuppala/ComputerSecurity/blob/master/Results.png)

Mode	              Time taken 1kb-seconds	Time taken 1mb-seconds	Per-byte speed-1kb-seconds	Per-byte speed-1mb-seconds
AES CBC Encryption-128	0.000840187	          0.010915995	              8.73E-07	                  1.10E-08
AES CBC Decryption-128	0.000412941	          0.012589931	              3.27E-07	                  9.40E-09
AES CTR Encryption-128	0.000532866	          0.006421089	              5.63E-07	                  6.35E-09
AES CTR Decryption-128	0.000320196	          0.008362055	              3.98E-07	                  8.48E-09
AES CTR Encryption-256	0.000244141	          0.007882118	              2.84E-07	                  7.87E-09
AES CTR Decryption-256	0.000360012	          0.009276152	              3.94E-07	                  9.17E-09
SHA-256	                0.001834079	          0.031045479             	1.79E-06	                  2.96E-08
SHA-512	                0.001473902	          0.035921175	              1.44E-06	                  3.51E-05
SHA3-256	              9.42E-04	            0.06364735	              9.20E-07	                  6.22E-05
RSA-2048-PKCS #1 v2 
OAEP-Encryption	        0.003369093	          0.006925106	              3.32E-06	                  6.84E-06
RSA-2048-PKCS #1 v2
OAEP-Decryption	        0.035111904	          0.038622141	              3.44E-05	                  3.78E-05
RSA-3072-PKCS #1 v2
OAEP-encryption	        0.005994081	          0.007658958	              5.91E-06	                  8.01E-06
RSA-3072-PKCS #1 v2
OAEP-Decryption	        0.067039967	          0.072906017	              6.59E-05	                  7.16E-05
DSA-2048-Produce	      0.001657009	          0.003993034	              3.03E-05	                  7.21E-05
DSA-2048-Verify	        0.000611782	          0.003181934	              1.18E-05	                  5.69E-05
DSA-3072-Produce	      0.001294136	          0.00297904	              2.40E-05	                  5.33E-05
DSA-3072-Verify	        0.001030922	          0.003202915	              2.10E-05	                  5.77E-05


KEY SIZE	AES-CBC 	AES-CTR 	RSA-PKCS-OAEP	  DSA
key 128	1.00E-05	﻿0.00049090385437		
key 256		        0.000595093		
key 2048			                0.431459904	0.49296093
key 3072			                1.758993864	0.598431826
