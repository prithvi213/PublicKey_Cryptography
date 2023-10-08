#include <stdio.h>
#include <gmp.h>
#include <stdlib.h>
#include <time.h>
#include <assert.h>
#include <math.h>

#include "numtheory.h"
#include "randstate.h"
#include "rsa.h"

// Creates parts of a public key: p and q are large primes of size bits/2, n = p
void rsa_make_pub(mpz_t p, mpz_t q, mpz_t n, mpz_t e, uint64_t nbits, uint64_t iters) {

    // First, split the bits for p and q
    time_t tim;
    srand((unsigned) time(&tim));
    uint64_t pbits = (rand() % ((3 * nbits / 4) - (nbits / 4)) + 1) + (nbits / 4);
    uint64_t qbits = nbits - pbits;

    // Creates p and q using make_prime
    make_prime(p, pbits, iters);
    make_prime(q, qbits, iters);

    mpz_mul(n, p, q);
    mpz_t mul_bits;
    mpz_init(mul_bits);
    mpz_set_ui(mul_bits, mpz_sizeinbase(n, 2));

    // While p == q -> reproduces prime number
    while (mpz_cmp(p, q) == 0 || mpz_cmp_ui(mul_bits, nbits) < 0) {
        make_prime(q, qbits, iters);
        mpz_mul(n, p, q);
        mpz_set_ui(mul_bits, mpz_sizeinbase(n, 2));
    }

    // Checks if p and q are not equal to 0
    assert(p != 0);
    assert(q != 0);

    // Generates the totient
    mpz_t pminus1, qminus1, totient;
    mpz_inits(pminus1, qminus1, totient, NULL);
    mpz_sub_ui(pminus1, p, 1);
    mpz_sub_ui(qminus1, q, 1);
    mpz_mul(totient, pminus1, qminus1);
    assert(mpz_sizeinbase(n, 2) == nbits);

    uint64_t random_seed;
    mpz_t random_mpz, gcdout;
    mpz_inits(random_mpz, gcdout, NULL);

    srand((unsigned) time(&tim));
    random_seed = rand() + 1;

    gmp_randstate_t tmp_state;
    gmp_randinit_mt(tmp_state);
    gmp_randseed_ui(tmp_state, random_seed);

    do {
        mpz_urandomm(random_mpz, tmp_state, totient);
        mpz_add_ui(random_mpz, random_mpz, 1);
        gcd(gcdout, totient, random_mpz);
        mpz_set(e, random_mpz);
    } while (mpz_cmp_ui(gcdout, 1) != 0);

    // Free up memory allocated in gmp types
    gmp_randclear(tmp_state);
    mpz_clears(mul_bits, pminus1, qminus1, random_mpz, gcdout, totient, NULL);
}

// Writes out public key components into a file
void rsa_write_pub(mpz_t n, mpz_t e, mpz_t s, char username[], FILE *pbfile) {
    // Write n, e, and s in hex format and username also with
    gmp_fprintf(pbfile, "%Zx\n%Zx\n%Zx\n%s\n", n, e, s, username);
    return;
}

// Function makes the private key
// It calculates the totient and then uses mod_inverse to make private key
void rsa_make_priv(mpz_t d, mpz_t e, mpz_t p, mpz_t q) {
    mpz_t pminus1, qminus1, n;
    mpz_inits(pminus1, qminus1, n, NULL);
    mpz_sub_ui(pminus1, p, 1);
    mpz_sub_ui(qminus1, q, 1);
    mpz_mul(n, pminus1, qminus1);
    mod_inverse(d, e, n);
    mpz_clears(pminus1, qminus1, n, NULL);
    return;
}

// Given the totient and priv key -> write the file
void rsa_write_priv(mpz_t n, mpz_t d, FILE *pvfile) {
    gmp_fprintf(pvfile, "%Zx\n%Zx\n", n, d);
    return;
}

// Signature of key is done by using pow_mod
void rsa_sign(mpz_t s, mpz_t m, mpz_t d, mpz_t n) {
    pow_mod(s, m, d, n);
    return;
}

// Key verification is done by checking if m is equal to s^e mod(n)
bool rsa_verify(mpz_t m, mpz_t s, mpz_t e, mpz_t n) {
    mpz_t tmp_m;
    mpz_init(tmp_m);
    pow_mod(tmp_m, s, e, n);

    if (mpz_cmp(m, tmp_m) == 0) {
        mpz_clear(tmp_m);
        return true;
    }

    mpz_clear(tmp_m);
    return false;
}

// Reads a public key hexstring
void rsa_read_pub(mpz_t n, mpz_t e, mpz_t s, char username[], FILE *pbfile) {
    gmp_fscanf(pbfile, "%Zx\n%Zx\n%Zx\n%s\n", n, e, s, username);
    return;
}

// Reads a private key hexstring
void rsa_read_priv(mpz_t n, mpz_t d, FILE *pvfile) {
    gmp_fscanf(pvfile, "%Zx\n%Zx\n", n, d);
    return;
}

// RSA encrypt performs a basic pow mod operation
void rsa_encrypt(mpz_t c, mpz_t m, mpz_t e, mpz_t n) {
    pow_mod(c, m, e, n);
    return;
}

// Encrypts a file
void rsa_encrypt_file(FILE *infile, FILE *outfile, mpz_t n, mpz_t e) {
    // Set a variable for number of bytes k
    // k = (log2(n) - 1) / 8 bytes
    // Initialize mpz m
    mpz_t m, c;
    mpz_inits(m, c, NULL);
    size_t k = (mpz_sizeinbase(n, 2) - 1) / 8;

    // Dynamically allocate array
    uint8_t *block = (uint8_t *) calloc(k, sizeof(uint8_t));

    // Set zeroth byte of block to 0xFF
    block[0] = 0xFF;

    uint64_t j = 0, total_bytes = 0;

    // While the end of the file hasn't been reached:
    // Read max/k - 1 bytes from infile in a single read
    while (feof(infile) == 0) {
        j = fread(block + 1, sizeof(uint8_t), k - 1, infile);
        total_bytes += j;
        mpz_import(m, j + 1, 1, sizeof(uint8_t), 1, 0, block);
        rsa_encrypt(c, m, e, n);
        gmp_fprintf(outfile, "%Zx\n", c);
    }

    // Frees memory from mpz variables
    mpz_clears(m, c, NULL);
    free(block);
}

// RSA decrypt performs a basic pow mod operation
void rsa_decrypt(mpz_t m, mpz_t c, mpz_t d, mpz_t n) {
    pow_mod(m, c, d, n);
    return;
}

// Decrypts a file
void rsa_decrypt_file(FILE *infile, FILE *outfile, mpz_t n, mpz_t d) {
    // Initialize mpzs
    mpz_t m, c;
    mpz_inits(m, c, NULL);

    // Calculate block size k: k = log2(n) - 1 / 8
    size_t k = (mpz_sizeinbase(n, 2) - 1) / 8, ptr;

    // Create dynamic array
    uint8_t *block = (uint8_t *) calloc(k, sizeof(uint8_t));

    // Scans until EOF is reached
    while (feof(infile) == 0) {
        gmp_fscanf(infile, "%Zx\n", c);
        rsa_decrypt(m, c, d, n);
        mpz_export(block, &ptr, 1, sizeof(uint8_t), 1, 0, m);
        fwrite(block + 1, sizeof(uint8_t), ptr - 1, outfile);
    }

    // Frees up allocated memory
    mpz_clears(m, c, NULL);
    free(block);
}
