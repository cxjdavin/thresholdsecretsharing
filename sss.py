import sys
from functools import reduce
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto import Random # A cryptographically strong version of Python's standard "random" module

# Implementation notes:
# Since AES uses block length of 16 bytes, we use "ctr = Counter.new(128)"
# Since counter is a stateful function, we need 2 objects - one for encoding, one for decoding
class SSS:
    '''
    Base class for Secret Sharing Schemes (SSS) that implements (k,n)-threshold sharing.
    Encryption: Use AES-256 to encode infile and save into outfile, then split AES key into n keys
    Decryption: Combine k keys into AES key and decrypt outfile
    Other SSS classes extend from this and implement their methods of splitting the AES key and combining keys

    Conventions:
    S = secret = AES key
    After splitting up a "key", we get "keys"/"shares"/"shadows"
    '''

    def __init__(self):
        '''
        Initialises a huge prime p for modulo (if needed), where S < p.
        Since S is 32 bytes, p has to be > 256 bits.
        Source: http://primes.utm.edu/lists/2small/200bit.html
        Verification: http://www.wolframalpha.com/input/?i=is+2%5E257+-+93+prime
        '''

        # You can randomly generate this if you wish to
        self.p = 2**257 - 93

    def split_key(self, key, n, k):
        '''
        Split up AES key into different shares.
        Implementation left up to different schemes that extend this class
        '''
        pass

    def combine_keys(self, keys):
        '''
        Combines shares into a AES key.
        Will only succeed if >= k valid shares are provided
        Implementation left up to different schemes that extend this class
        '''
        pass

    def encrypt(self, infile, outfile, keysfile, n, k):
        '''
        Encrypts infile to outfile via AES-256 and stores "broken up" key in keysfile

        1) Reads in plaintext from infile
        2) Create AES-256 encoder with 32 random bytes as key
        3) Encrypt plaintext
        4) Store ciphertext in outfile
        5) Split key into via split_key function (Output depends on n and k)
        6) Store keys/shares in keysfile
        '''

        # Read from infile
        with open(infile, 'rb') as f:
            plain = f.read()

        # Create AES-256 encoder with 32 random bytes as key
        key = Random.new().read(32)
        encoder = AES.new(key, AES.MODE_CTR, counter = Counter.new(128))

        # Encrypt plaintext
        cipher = encoder.encrypt(plain)
        
        # Write to outfile
        with open(outfile, 'wb') as f:
            f.write(cipher)

        # Generate n keys
        keys = self.split_key(key, n, k)

        # Store n keys
        with open(keysfile, 'w') as f:
            for key in keys:
                f.write("{}\n".format(key))

    def decrypt(self, infile, outfile, keysfile):
        '''
        Reads in keys/shares from keysfiles and parse them as a list of keys/shares
        '''

        # Read from keysfile
        with open(keysfile, 'r') as f:
            keys = f.read().splitlines()
        keys = [[int(num) for num in key[1:-1].replace(' ', '').split(',')] for key in keys]
        self.decrypt_with_keys(infile, outfile, keys)

    def decrypt_with_keys(self, infile, outfile, keys):
        '''
        Decrypts infile to outfile via AES-256 with keys

        1) Reads in ciphertext from infile
        2) Combine keys/shares into a AES-256 key
        3) Create AES-256 decoder with combined key
        4) Decrypt ciphertext
        5) Store plaintext in outfile
        '''

        # Read from infile
        with open(infile, 'rb') as f:
            cipher = f.read()

        try:
            # Combine given keys. May throw exception if < k valid keys are given
            key = self.combine_keys(keys)

            # Create AES-256 decoder with key
            decoder = AES.new(key, AES.MODE_CTR, counter = Counter.new(128))

            # Decrypt ciphertext
            plain = decoder.decrypt(cipher)
        except Exception as e:
            plain = str.encode(e.args[0])
        finally:
            # Write to outfile
            with open(outfile, 'wb') as f:
                f.write(plain)

####################
# HELPER FUNCTIONS #
####################

def prod(lst):
    '''
    Returns the product of all values in the list
    '''
    return reduce(lambda x, y: x * y, lst)

# Source: https://en.wikibooks.org/wiki/Algorithm_Implementation/Mathematics/Extended_Euclidean_algorithm
def xgcd(b, n):
    '''
    Extended gcd (Iterative form)
    '''
    x0, x1, y0, y1 = 1, 0, 0, 1
    while n != 0:
        q, b, n = b // n, n, b % n
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return  b, x0, y0

# Source: https://en.wikibooks.org/wiki/Algorithm_Implementation/Mathematics/Extended_Euclidean_algorithm
def mulinv(b, n):
    '''
    Returns the modulo inverse of b in mod n
    i.e. x = mulinv(b) mod n, (x * b) % n == 1
    '''
    g, x, _ = xgcd(b, n)
    if g == 1:
        return x % n

# Source: https://en.wikipedia.org/wiki/Lagrange_polynomial
def basis(x, k, j, p):
    '''
    Computes the basis for Lagrange interpolating polynomial based on the formula
    '''
    terms = [(0-x[m])*mulinv(x[j] - x[m], p) for m in range(k) if m != j]
    return prod(terms) % p