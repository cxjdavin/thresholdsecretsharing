import argparse
from blakley import *
from shamir import *
from asmuthbloom import *

####################
# Argument Parsing #
####################

parser = argparse.ArgumentParser()
parser.add_argument("-scheme", help = "Select SSS scheme: 'Blakley', 'Shamir' or 'AsmuthBloom'")
parser.add_argument("-encrypt", help = "Enable encrypt mode", action = "store_true")
parser.add_argument("-decrypt", help = "Enable decrypt mode", action = "store_true")
parser.add_argument("-infile", help = "Name of input file. For encryption, infile should hold plaintext. For decryption, infile should hold ciphertext.")
parser.add_argument("-outfile", help = "Name of output file. For encryption, ciphertext will be written here. For decryption, plaintext will be written here.")
parser.add_argument("-keysfile", help = "Name of keys file. For encryption, n keys will be stored here. Decryption will only work if at least k valid keys are provided here.")
parser.add_argument("-n", help = "Total number of secret keys generated during encryption", type = int)
parser.add_argument("-k", help = "Decryption threshold: At least k out of n keys will be needed to decrypt", type = int)
args = parser.parse_args()
print("Arguments: {}".format(args))

#################################
# Execute Secret Sharing Scheme #
#################################
'''
Sample execution:

>>> python3 main.py -scheme Blakley -encrypt -infile lenna.png -outfile cipher.png -keysfile keys.txt -n 7 -k 5

Split keys to 7 different parties
Some time passes...
Gather some keys and put in keys.txt

>>> python3 main.py -scheme Blakley -decrypt -infile cipher.png -outfile lenna_restored.png -keysfile keys.txt

Successful if and only if keys.txt contain >= 5 valid keys

>>> diff lenna.png lenna_restored.png

Files are identical!
'''

if args.scheme == 'Blakley' or args.scheme == 'Shamir' or args.scheme == 'AsmuthBloom':
    # Select secret sharing scheme
    if args.scheme == 'Blakley':
        sss = BlakleySSS()
    elif args.scheme == 'Shamir':
        sss = ShamirSSS()
    elif args.scheme == 'AsmuthBloom':
        sss = AsmuthBloomSSS()

    # Select mode
    if args.encrypt and args.decrypt:
        print("Invalid use mode: Cannot pick both encryption and decryption at the same time.")
    elif not args.encrypt and not args.decrypt:
        print("Invalid use mode: Please pick either the encryption or decryption mode.")
    elif args.encrypt:
        # Use AES-256 to encode infile and save into outfile, then split AES key into n keys
        print("Encrypting...")
        sss.encrypt(args.infile, args.outfile, args.keysfile, args.n, args.k)
        print("Done!")
    else:
        print("Decrypting...")
        # Combine k keys into AES key and decrypt outfile
        sss.decrypt(args.infile, args.outfile, args.keysfile)
        print("Done!")
else:
    print("Please select a Secret Sharing Scheme: 'Blakley', 'Shamir' or 'AsmuthBloom'")