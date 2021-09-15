# wuyou-crypto-go
crypto tools for Fabric, as a plugin project written in Golang.

It contains some cryptography tools, such as:
* SM2: key generation, encrypt/decrypt, sign/verify (like RSA)
* SM3: calculate digest of a message (like SHA256)
* SM4: key generation, encrypt/decrypt (like AES)
* Paillier: key generation, addCiphertext/subCiphertext, addPlaintext/MulPlaintext/DivPlaintext

This project is inspired by some great projects, thanks them.

# references:
* https://github.com/tjfoc/gmsm
* https://github.com/srderson/paillier
