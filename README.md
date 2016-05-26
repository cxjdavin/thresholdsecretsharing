# About
Here are 3 (k,n)-threshold secret sharing implementations due to:

1. Blakley, G. R. (1899, December). Safeguarding cryptographic keys. In *afips* (p. 313). IEEE.

2. Shamir, A. (1979). How to share a secret. *Communications of the ACM*, 22(11), 612-613.

3. Asmuth, C., & Bloom, J. (1983). A modular approach to key safeguarding. *IEEE transactions on information theory, 30(2)*, 208-210.

All 3 schemes support encryption and decryption files using [AES-256](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) via [PyCrypto](http://pythonhosted.org/pycrypto/). AES is a symmetric-key algorithm (i.e. encryption key = decryption key). The secret **S** to be shared is not the original file, but the 256-bit AES key.

**Encryption mode**

* Read a given input file (plaintext)
* Encrypt it using AES-256 with a randomly generated 256-bit key
* Store encrypted file (ciphertext)
* Split the key into **n** parts with threshold set to **k**
* Store keys to be given out

**Decryption mode**

* Read in encrypted file (ciphertext)
* Read in the given t keys
* Attempt to combine the keys into the original 256-bit key
* Decrypt ciphertext with combined key using AES-256
* Store decrypted file (plaintext)

Obviously, decryption will succeed if and only if at least **k** valid keys are provided.

```
Sample execution:

>>> python3 main.py -scheme Blakley -encrypt -infile lenna.png -outfile cipher.png -keysfile keys.txt -n 7 -k 5

Split keys to 7 different parties
Some time passes...
Gather some keys and put in keys.txt

>>> python3 main.py -scheme Blakley -decrypt -infile cipher.png -outfile lenna_restored.png -keysfile keys.txt

Successful if and only if keys.txt contain >= 5 valid keys

>>> diff lenna.png lenna_restored.png

Files are identical!
```

# Blog post
To learn more, read the blog post here: http://davinchoo.com/2016/05/26/threshold-secret-sharing-schemes/
