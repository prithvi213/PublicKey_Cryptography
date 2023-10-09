## Public Key Cryptography

In this lab we learnt about cryptography, the RSA algorithm, and ways which we can deliver messages to the recipient secretly. Learning these algorithms required me to deeply understand some math functions: gcd, pow_mod, mod_inverse, is_prime, and make_prime.

## Building
To build the 'keygen' program:

make keygen

To build the 'encrypt' program:

make encrypt

To build the 'decrypt' program:

make decrypt

## Running

To run the 'keygen' program:

./keygen -[hvb:i:n:d:s:]

-h = Displays program options
-v = Enables verbose printing
-b = Inputted number of min bits
-i = Number of iterations
-n = Specifies public key file
-d = Specifies private key file
-s = Specifies random seed

To run the 'encrypt' program:

./encrypt -[hvn:i:o:]

-h = Displays program options
-v = Enables verbose printing
-n = Specifies file containing public key
-i = Specifies input file to encrypt
-o = Specifies output file to encrypt

To run the 'decrypt' program:

./decrypt -[hvi:o:n:]

-h = Displays program options
-v = Enables verbose printing
-n = Specifies private key file
-i = Specifies input file to decrypt
-o = Specifies output file to decrypt

## Cleaning

To clean the folder:

make clean

## Formatting

To format all the files:

make format

## Scan Build

To run a scan-build:

scan-build make
