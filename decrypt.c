#include "rsa.h"
#include "randstate.h"
#include "numtheory.h"

#include <stdbool.h>
#include <stdio.h>
#include <gmp.h>
#include <unistd.h>
#include <stdlib.h>

#define OPTIONS "hvi:o:n:"

int main(int argc, char **argv) {
    int opt = 0;
    bool print_usage = false, print_verbose = false;
    char *infile_name = NULL, *outfile_name = NULL, *priv_keyfile = "rsa.priv";
    FILE *iFile = stdin, *oFile = stdout, *pvfile = NULL;

    // Parsing command-line options
    while ((opt = getopt(argc, argv, OPTIONS)) != -1) {
        switch (opt) {
        case 'h': print_usage = true; break;
        case 'v': print_verbose = true; break;
        case 'i': infile_name = optarg; break;
        case 'o': outfile_name = optarg; break;
        case 'n': priv_keyfile = optarg; break;
        default: print_usage = true; break;
        }
    }

    // Print usage command-line option
    if (print_usage) {
        printf("SYNOPSIS\n");
        printf("   Decrypts data using RSA encryption.\n");
        printf("   Encrypted data is encrypted by the encrypt program.\n\n");
        printf("USAGE\n");
        printf("   ./decrypt [-hv] [-i infile] [-o outfile] -n privkey\n\n");
        printf("OPTIONS\n");
        printf("   -h              Display program help and usage.\n");
        printf("   -v              Display verbose program output.\n");
        printf("   -i infile       Input file of data to encrypt (default: stdin).\n");
        printf("   -o outfile      Output file for encrypted data (default: stdout).\n");
        printf("   -n pvfile       Private key file (default: rsa.priv).\n");
    }

    // Opens private key file
    if (priv_keyfile != NULL) {
        pvfile = fopen(priv_keyfile, "r");

        if (pvfile == NULL) {
            fprintf(stderr, "Unable to open private keyfile.\n");
            exit(1);
        }
    }

    // Open input file if filename isn't NULL
    if (infile_name != NULL) {
        iFile = fopen(infile_name, "r");

        if (iFile == NULL) {
            fprintf(stderr, "Failed to open infile.\n");
            exit(1);
        }
    }

    // Writes encrypted message to outfile
    if (outfile_name != NULL) {
        oFile = fopen(outfile_name, "w");
    }

    // Reading from private key file
    mpz_t n, d;
    mpz_inits(n, d, NULL);
    rsa_read_priv(n, d, pvfile);

    // Print verbose command-line option
    if (print_verbose && !print_usage) {
        gmp_printf("n (%zu bits) = %Zu\n", mpz_sizeinbase(n, 2), n);
        gmp_printf("d (%zu bits) = %Zu\n", mpz_sizeinbase(d, 2), d);
    }

    // Decrypts the file
    rsa_decrypt_file(iFile, oFile, n, d);

    // Close the iFile and oFile
    // Clear memory in mpz variables
    mpz_clears(n, d, NULL);

    if (iFile != NULL) {
        fclose(iFile);
    }

    if (oFile != NULL) {
        fclose(oFile);
    }
}
