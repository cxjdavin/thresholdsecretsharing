import subprocess
from itertools import chain, combinations
from blakley import *
from shamir import *
from asmuthbloom import *

# Modified from: http://stackoverflow.com/questions/18826571/python-powerset-of-a-given-set-with-generators
def powerset_generator(i):
    for subset in chain.from_iterable(combinations(i, r) for r in range(len(i)+1)):
        yield list(subset)

# Test setting setup
test_input = "lenna.png" # Source: https://upload.wikimedia.org/wikipedia/en/2/24/Lenna.png
cipherfile = "cipher.png"
keysfile = "keys.txt"
test_output = "lenna_restored.png"
schemes = [["Blakley", BlakleySSS()], ["Shamir", ShamirSSS()], ["AsmuthBloom", AsmuthBloomSSS()]]

# Iterate over all schemes, 1 <= n <= 10, 2 <= k <= n
for scheme_name, sss in schemes:
    for n in range(1,11):
        for k in range(2, n+1):
            print("Scheme: {}, n: {}, k: {}".format(scheme_name, n, k))
            sss.encrypt(test_input, cipherfile, keysfile, n, k)

            # Read in keys
            with open(keysfile, 'r') as f:
                keys = f.read().splitlines()
            keys = [[int(num) for num in key[1:-1].replace(' ', '').split(',')] for key in keys]
            
            # Generate all possible subset of keys
            powerset = powerset_generator(keys)
            for subset in powerset:
                if len(subset) >= 2:
                    sss.decrypt_with_keys(cipherfile, test_output, subset)

                    # Check that decryption works if and only if number of keys >= k
                    cmd = "diff {} {}".format(test_input, test_output)
                    sp = subprocess.Popen(cmd, stdout = subprocess.PIPE, shell=True)
                    if len(subset) >= k:
                        assert len(list(sp.stdout)) == 0
                    else:
                        assert len(list(sp.stdout)) != 0

print("All testing done!")