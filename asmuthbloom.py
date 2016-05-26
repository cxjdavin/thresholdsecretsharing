import sys, math
from sss import *
from Crypto.Random import random # A cryptographically strong version of Python's standard "random" module

class AsmuthBloomSSS(SSS):
    '''
    AsmuthBloom Secret Sharing Scheme
    Paper: Asmuth, C., & Bloom, J. (1983). A modular approach to key safeguarding. IEEE transactions on information theory, 30(2), 208-210.

    Key idea:
    Pick n pairwise coprime integers m1, .. , mn
    Pick m0 such that gcd(m0, mi) = 1 for i = 1, ... , n
    Required condition: Product of smallest k primes > m0 * Product of largest (k-1) primes
    
    Let secret S = x
    Let M = Product of smallest k primes
    Pick random A such that 0 <= x + A * m0 <= M

    n keys = x + A * m0 (mod mi) for i = 1, 2, ... , n
    >= k keys can solve for x via Chinese Remainder Theorem (CRT) mod product of given mi's. Then, secret = unique CRT solution mod m0
    < k keys cannot yield unique solution via CRT

    Conventions:
    Solution to Chinese Remainder Theorem is the secret/key S
    We split the 256 bit AES key into 32 chunks of 8-bit/1-byte, then encode each of them
    This is because it is really hard to find a set of pairwise coprime integers that satisfy the required conditions.

    For now,
    1) Maximum allowable n is 10. i.e. At most split into 10 shares
    2) Choice of mi's are smallest n primes out of the list of 91st to 100th primes.
    3) m0 is fixed at 2^8 = 256
    '''

    def __init__(self):
        '''
        The 91st to 100th primes are used as a set of pairwise coprime integers.
        Fix m0 = 2^8 = 256.
        '''

        super().__init__()
        self.primes = [467, 479, 487, 491, 499, 503, 509, 521, 523, 541]
        self.m0 = 256

    def split_key(self, key, n, k):
        '''
        Split AES key into 32 chunks then encode each chunk using smallest n primes
        Let y = x + A * m0

        Key i = [mi, y for chunk 1, ... , y for chunk 32]
        '''

        assert (n <= 10), "For now, AsmuthBloomSSS only works with n <= 10."

        # Split into 256 bit AES key into 32 chunks of 8-bit/1-byte
        chunks = [c for c in key]
        
        # Grab the smallest n primes as mi's
        m = self.primes[:n]

        # Compute M as the product of smallest k mi's
        M = prod(m[:k])

        # Check correctness condition
        assert (self.m0 * prod(m[-k+1:]) < prod(m[:k]))

        keys = [[mi] for mi in m]
        for c in chunks:
            # Generate random A such that 0 <= c + A * m0 < M
            A = random.randrange(0, math.floor((M - c) / self.m0))
            y = c + A * self.m0
            assert(y < M)

            # Generate shares for each 8-bit chunk
            shares = [y % mi for mi in m]
            for i in range(n):
                keys[i].append(shares[i])

        # Return keys
        return keys

    def combine_keys(self, keys):
        '''
        Extract mi's and y chunks, then apply Chinese Remainder Theorem (CRT) to each chunk individually
        Combine all 32 chunks back into a single 256 bit AES key
        
        Key = Merged CRT solutions to all 32 chunks
        '''

        # keys[i][0] = mi
        # keys[i][1..32] = y mod mi (32 different y chunks)
        k = len(keys)

        # m = [m1, m2, ... , mk]
        # chunks = [[y1, y2, ... , yk], ... , [y1, y2, ... , yk]]
        # Each [y1, y2, ... , yk] represent a 8-bit chunk of the original 256-bit AES key
        m = [keys[i][0] for i in range(k)]
        chunks = [[keys[i][j] for i in range(k)] for j in range(1,33)]

        # Compute M, mi
        # M = product of all mi
        # zi = M / mi
        # bi * (M / mi) = 1 (mod mi), i.e. bi = mulinv(zi, mi)
        # S = (y1 * z1 * b1 + y2 * z2 * b2 + ... + yk * zk * bk) % M % m0
        #
        # Implementation notes:
        # z = [int(M / mi) for mi in m]: Fails because of division precision error
        M = prod([mi for mi in m])
        z = [prod([m[i] for i in range(k) if i != j]) for j in range(k)]
        b = [mulinv(z[i], m[i]) for i in range(k)]
        S_chunks = [int(sum(y[i] * z[i] * b[i] % M for i in range(k)) % M % self.m0) for y in chunks]
        
        # Secret S = AES key = Merged Chinese Remainder Theorem solutions of all 32 chunks
        S = sum(S_chunks[i] * (256 ** i) for i in range(32))
        key = S.to_bytes(32, byteorder = sys.byteorder)

        # Return key
        return key