import sys
from sss import *
from Crypto.Random import random # A cryptographically strong version of Python's standard "random" module

class ShamirSSS(SSS):
    '''
    Shamir Secret Sharing Scheme
    Paper: Shamir, A. (1979). How to share a secret. Communications of the ACM, 22(11), 612-613.

    Key idea:
    Pick a random (k-1) degree polynomial: q(x) = a_0 + a_1 * x + a2 * x^2 + ... + a_(k-1) * x^(k-1)
    Secret stored in q(0) = a_0 = S
    
    n keys = q(i) for i = 1, 2, ... , n
    >= k keys can reconstruct q(x)
    < k keys insufficient to reconstruct q(x)

    Conventions:
    Constant term in interpolating polynomial q(0) is the secret/key S
    Reconstruction via Lagrange interpolation
    '''

    def __init__(self):
        super().__init__()

    def split_key(self, key, n, k):
        '''
        Generates coefficient vector a with a[0] = S
        Sample polynomial q(i) at i = 1, 2, ... , n
        
        Key i = [i, q(i)]
        '''

        # Generate coefficient vector a
        a = [int.from_bytes(key, byteorder = sys.byteorder)]
        for i in range(k-1):
            a.append(random.randint(0, 2**256))

        # Polynomial q(x) = a_0 + a_1 * x + a2 * x^2 + ... + a_(k-1) * x^(k-1) (mod p)
        # Generate q(1), q(2), ... , q(n) (mod p)
        keys = []
        for i in range(1, n+1):
            x = [i ** j for j in range(k)]
            keys.append([i, sum(a[j] * x[j] % self.p for j in range(k)) % self.p])

        # Return keys
        return keys

    def combine_keys(self, keys):
        '''
        Extract x and y = q(x) from keys
        Apply Lagrange interpolation to compute q(0) = S
        
        Key = q(0)
        '''

        # keys[i][0] = x value
        # keys[i][1] = q(x) value
        k = len(keys)
        x = [keys[i][0] for i in range(k)]
        y = [keys[i][1] for i in range(k)]

        # Find q(0) by directly applying definition of Lagrange interpolation formula
        # Secret S = AES key = q(0)
        #
        # Implementation notes:
        # Take modulo (2 ** 256) because insufficent/invalid keys may result in S > 256 bits
        # If S > 256 bits, then it will crash in the conversion to 32 byte representation
        S = int(sum(y[j] * basis(x, k, j, self.p) % self.p for j in range(k)) % self.p) % (2 ** 256)
        key = S.to_bytes(32, byteorder = sys.byteorder)

        # Return key
        return key