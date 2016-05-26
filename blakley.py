import sys, scipy.linalg
import numpy as np
from sss import *
from Crypto.Random import random # A cryptographically strong version of Python's standard "random" module

class BlakleySSS(SSS):
    '''
    Blakley Secret Sharing Scheme
    Paper: Blakley, G. R. (1899, December). Safeguarding cryptographic keys. In afips (p. 313). IEEE.
    Paper: Hei, X., Du, X., & Song, B. (2012, June). Two matrices for Blakley's secret sharing scheme. In Communications (ICC), 2012 IEEE International Conference on (pp. 810-814). IEEE.

    Key idea:
    Secret stored in k-vector X

    n keys = n hyperplane equations
    >= k hyperplanes will intersect at point X
    < k hyperplanes will intersect in a higher dimensional object, e.g. line, hence cannot recover X

    Conventions:
    First coordinate is the secret/key S
    Pascal Matrix is used as per suggestion in the second cited paper
    '''

    def __init__(self):
        super().__init__()

    def split_key(self, key, n, k):
        '''
        Generates k-vector X and corresponding Pascal Matrix A
        Then, compute y vector: Ax = y
        
        Key i = [i-th row of Pascal Matrix, y[i]]
        '''

        # Generate x vector
        x = [int.from_bytes(key, byteorder = sys.byteorder)]
        for i in range(k-1):
            x.append(random.randint(0, 2**256))
        x = np.array(x)

        # Generate Pascal Matrix
        A = np.ones((n, k)).astype(int)
        for r in range(1, n):
            for c in range(1, k):
                A[r,c] = A[r,c-1] + A[r-1,c]

        # Generate y vector, where Ax = y
        y = np.dot(A, x)

        # Split keys
        keys = [A[i].tolist() + [y[i]] for i in range(n)]

        # Return keys
        return keys

    def combine_keys(self, keys):
        '''
        Generate partial, square Pascal Matrix B from first k keys
        Extract first k y values
        Solve for x in Bx = y
        
        Key = x[0]
        '''

        k = len(keys[0])-1
        if k > len(keys):
            raise Exception("Insufficient keys provided for decryption. Please ensure the first {} keys are valid.".format(k))

        # Generate matrix and y vector from keys, filter for first k keys
        B = np.matrix([keys[i][:-1] for i in range(k)])[:k]
        y = np.array([keys[i][-1] for i in range(k)])[:k]

        if np.linalg.matrix_rank(B) != k:
            raise Exception("Keys provided are not linearly independent. Please ensure the first {} keys are valid.".format(k))

        # Solve simultaneous equation: Bx = y
        #
        # Implementation notes:
        # Problem 1:    Currently, no math packages can solve linear system of equations with arbitrary length numbers
        #               But, y is made up of values that are up to 256 bits long
        # Workaround:   Since elements in B is invertible, find B^-1 (invB)
        #               Use scipy since numpy doesn't have in-built inv function
        # Problem 2:    invB may contain fractions
        # Workaround 2: Since elements in B are integers, det(B) is an integer.
        #               Using invB = adj(B)/det(B) definition, defer division by det(B) till after multiplying with y
        invB = scipy.linalg.inv(B)
        detB = round(scipy.linalg.det(B))

        # Secret S = AES key = invA[0] * y (since we only care about x[0])
        #
        # Implementation notes:
        # type(round(detB * invB[0][0]))        -> float64
        # type(int(round(detB * invB[0][0])))   -> native Python int
        # type(round(detB))                     -> native Python int
        # Need to use // instead of / to maintain numerical precision
        S = sum(int(round(detB * invB[0][i])) * y[i] for i in range(k)) // round(detB)
        key = S.to_bytes(32, byteorder = sys.byteorder)

        # Return key
        return key