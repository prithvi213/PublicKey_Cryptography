#include "numtheory.h"
#include "randstate.h"
#include "rsa.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <gmp.h>

#define OPTIONS "hvn:i:o:"

int main(int argc, char **argv) {
    int opt = 0;
    bool print_usage = false, print_verbose = false;
    char *infile_name = NULL, *outfile_name = NULL, *pb_keyfile = "rsa.pub";
    FILE *iFile = stdin, *oFile = stdout, *pbfile = NULL;

    // Parsing command-line options
    while ((opt = getopt(argc, argv, OPTIONS)) != -1) {
        switch (opt) {
        case 'h': print_usage = true; break;
        case 'v': print_verbose = true; break;
        case 'i': infile_name = optarg; break;
        case 'o': outfile_name = optarg; break;
        case 'n': pb_keyfile = optarg; break;
        default: print_usage = true; break;
        }
    }

    // If command-line option requires printing out usage
    // It will print the usage
    if (print_usage) {
        printf("SYNOPSIS\n");
        printf("   Encrypts data using RSA encryption.\n");
        printf("   Encrypted data is decrypted by the decrypt program.\n\n");
        printf("USAGE\n");
        printf("   ./encrypt [-hv] [-i infile] [-o outfile] -n pubkey\n\n");
        printf("OPTIONS\n");
        printf("   -h              Display program help and usage.\n");
        printf("   -v              Display verbose program output.\n");
        printf("   -i infile       Input file of data to encrypt (default: stdin).\n");
        printf("   -o outfile      Output file for encrypted data (default: stdout).\n");
        printf("   -n pbfile       Public key file (default: rsa.pub).\n");
    }

    // Opens the public key file
    if (pb_keyfile != NULL) {
        pbfile = fopen(pb_keyfile, "r");

        if (pbfile == NULL) {
            fprintf(stderr, "Unable to open public keyfile.\n");
            exit(1);
        }
    }

    // Open input file if the filename isn't NULL
    if (infile_name != NULL) {
        iFile = fopen(infile_name, "r");

        if (iFile == NULL) {
            fprintf(stderr, "Unable to open infile.\n");
            exit(1);
        }
    }

    // Writes encrypted message to output file
    if (outfile_name != NULL) {
        oFile = fopen(outfile_name, "w");
    }

    // Reading from the public key file
    mpz_t n, e, s;
    char *username = getenv("USER");
    mpz_inits(n, e, s, NULL);
    rsa_read_pub(n, e, s, username, pbfile);

    // Verbose option check...
    if (print_verbose && !print_usage) {
        gmp_printf("user = %s\n", username);
        gmp_printf("s (%zu bits) = %Zu\n", mpz_sizeinbase(s, 2), s);
        gmp_printf("n (%zu bits) = %Zu\n", mpz_sizeinbase(n, 2), n);
        gmp_printf("e (%zu bits) = %Zu\n", mpz_sizeinbase(e, 2), e);
    }

    // Converts user name into an mpz_t and gets signature of username
    // Also verifies the signature
    mpz_t m;
    mpz_inits(m, NULL);
    mpz_set_str(m, username, 62);

    // If the sigature wasn't verified, it will throw an error
    if (!rsa_verify(m, s, e, n)) {
        fprintf(stderr, "Signature couldn't be verified.\n");
        exit(1);
    }

    // Call to rsa encrypt file
    rsa_encrypt_file(iFile, oFile, n, e);

    // Closing the pbfile, iFile and oFile
    // Clears memory from mpz variables
    mpz_clears(m, n, e, s, NULL);

    if (pbfile != NULL) {
        fclose(pbfile);
    }

    if (iFile != NULL) {
        fclose(iFile);
    }

    if (oFile != NULL) {
        fclose(oFile);
    }
}
