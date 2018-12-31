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
