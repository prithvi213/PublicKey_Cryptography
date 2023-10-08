#include <gmp.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>

#include "rsa.h"
#include "randstate.h"
#include "numtheory.h"
#include "sys/stat.h"

gmp_randstate_t state;

#define OPTIONS "hvb:i:n:d:s:"

int main(int argc, char **argv) {
    int opt = 0;
    bool print_usage = false, print_verbose = false;
    uint32_t min_bits = 256, num_iters = 50, random_seed = time(NULL);
    char *pbfile = "rsa.pub", *pvfile = "rsa.priv";

    while ((opt = getopt(argc, argv, OPTIONS)) != -1) {
        switch (opt) {
        case 'h': print_usage = true; break;
        case 'v': print_verbose = true; break;
        case 'b': min_bits = atoi(optarg); break;
        case 'i': num_iters = atoi(optarg); break;
        case 's': random_seed = atoi(optarg); break;
        case 'n': pbfile = optarg; break;
        case 'd': pvfile = optarg; break;
        default: print_usage = true; break;
        }
    }

    // Checks print_usage option
    if (print_usage) {
        printf("SYNOPSIS\n");
        printf("   Generates an RSA public/private key pair.\n\n");
        printf("USAGE\n");
        printf("   ./keygen [-hv] [-b bits] -n pbfile -d pvfile\n\n");
        printf("OPTIONS\n");
        printf("   -h              Display program help and usage.\n");
        printf("   -v              Display verbose program output.\n");
        printf("   -b bits         Minimum bits needed for public key n (default: 256).\n");
        printf("   -i confidence   Miller-Rabin iterations for testing primes (default: 50).\n");
        printf("   -n pbfile       Public key file (default: rsa.pub).\n");
        printf("   -d pvfile       Private key file (default: rsa.priv).\n");
        printf("   -s seed         Random seed for testing.\n");
    }

    FILE *pubFile = NULL, *privFile = NULL;

    // Opens the public key file
    if (pbfile != NULL) {
        pubFile = fopen(pbfile, "w");

        if (pubFile == NULL) {
            fprintf(stderr, "Failed to open %s for write\n", pbfile);
            exit(1);
        }
    }

    // Opens the private key file
    if (pvfile != NULL) {
        privFile = fopen(pvfile, "w");

        if (privFile == NULL) {
            fprintf(stderr, "Failed to open %s for write\n", pbfile);
            exit(1);
        }
    }

    // Use fchmod() and fileno() to set private key permissions
    // Permissions for priv key are set to just user read and write
    int fd = fileno(privFile);
    fchmod(fd, S_IRUSR | S_IWUSR);

    // Use specified random seed
    // Randomly initializes random seed
    randstate_init(random_seed);

    // Generating the key
    mpz_t p, q, n, e;
    mpz_inits(p, q, n, e, NULL);
    rsa_make_pub(p, q, n, e, min_bits, num_iters);

    // Make the private key
    mpz_t d;
    mpz_init(d);
    rsa_make_priv(d, e, p, q);

    // Gets the user name using getenv
    char *username = getenv("USER");
    if (username == NULL) {
        fprintf(stderr, "Error: couldn't find USER env variable to retrieve user name\n");
        exit(1);
    }

    // Converts user name into an mpz_t and gets signature of username
    mpz_t s, m;
    mpz_inits(s, m, NULL);
    mpz_set_str(m, username, 62);
    rsa_sign(s, m, d, n);

    // Writes out public key
    rsa_write_pub(n, e, s, username, pubFile);

    // Writes out private key
    rsa_write_priv(n, d, privFile);

    // Checks if verbose was enabled to not
    // Prints out essential components which include the signature and both primes
    // It also prints out the modulus and exponent as well as the private key
    if (print_verbose && !print_usage) {
        gmp_printf("user = %Zx\n", m);
        gmp_printf("s (%zu bits) = %Zu\n", mpz_sizeinbase(s, 2), s);
        gmp_printf("p (%zu bits) = %Zu\n", mpz_sizeinbase(p, 2), p);
        gmp_printf("q (%zu bits) = %Zu\n", mpz_sizeinbase(q, 2), q);
        gmp_printf("n (%zu bits) = %Zu\n", mpz_sizeinbase(n, 2), n);
        gmp_printf("e (%zu bits) = %Zu\n", mpz_sizeinbase(e, 2), e);
        gmp_printf("d (%zu bits) = %Zu\n", mpz_sizeinbase(d, 2), d);
    }

    // Closes public and private files and clears random state
    mpz_clears(p, q, n, e, s, m, d, NULL);

    if (pubFile != NULL) {
        fclose(pubFile);
    }

    if (privFile != NULL) {
        fclose(privFile);
    }
}
