#include "randstate.h"
#include "numtheory.h"
#include "rsa.h"

#include <assert.h>
#include <stdio.h>
#include <gmp.h>
#include <time.h>
#include <math.h>
#include <stdlib.h>

// Inspired by Professor Long
// Used assignment pdf pseudocode
void gcd(mpz_t d, mpz_t a, mpz_t b) {
    mpz_t temp, temp_a, temp_b;
    mpz_inits(temp, temp_a, temp_b, NULL);
    mpz_set(temp_a, a);
    mpz_set(temp_b, b);

    while (mpz_cmp_ui(temp_b, 0) != 0) {
        mpz_set(temp, temp_b);
        mpz_mod(temp_b, temp_a, temp_b);
        mpz_set(temp_a, temp);
    }

    mpz_set(d, temp_a);
    mpz_clears(temp, temp_a, temp_b, NULL);
}

// Inspired by Professor Long
// Used assignment pdf pseudocode
void pow_mod(mpz_t o, mpz_t a, mpz_t d, mpz_t n) {
    mpz_t v, p, temp_mul, temp_d, temp_p, two_val;
    mpz_inits(v, p, temp_mul, temp_d, temp_p, two_val, NULL);
    mpz_set_ui(two_val, 2);
    mpz_set_ui(v, 1);
    mpz_set(p, a);
    mpz_set(temp_d, d);

    mpz_mod(p, p, n);

    // If p is 0 -> set o to p
    if (mpz_cmp_ui(p, 0) == 0) {
        mpz_set(o, p);
        mpz_clears(v, p, temp_mul, temp_d, temp_p, two_val, NULL);
        return;
    }

    // While temp_d > 0, perform an is_odd check on temp_d
    while (mpz_cmp_ui(temp_d, 0) > 0) {
        if (mpz_odd_p(temp_d) != 0) {
            mpz_mul(temp_mul, v, p);
            mpz_mod(v, temp_mul, n);
        }

        mpz_mul(temp_p, p, p);
        mpz_mod(p, temp_p, n);
        mpz_fdiv_q(temp_d, temp_d, two_val);
    }

    // Deallocates memory
    mpz_set(o, v);
    mpz_clears(v, p, temp_mul, temp_d, temp_p, two_val, NULL);
}

// Inspired by Professor Long
// Used assignment pseudocode
// Also used various GMP library functions
bool is_prime(mpz_t n, uint64_t iters) {

    // Corner cases, n is odd or is less than 2
    if (mpz_cmp_ui(n, 2) < 0 || (mpz_cmp_ui(n, 2) != 0 && mpz_even_p(n) != 0)) {
        return false;
    }

    // Another corner case: if n < 4
    if (mpz_cmp_ui(n, 4) < 0) {
        return true;
    }

    // Write n - 1 as 2^s * r
    mpz_t r, s, y, n_minus_1;
    mpz_inits(r, s, y, n_minus_1, NULL);
    mpz_sub_ui(r, n, 1);
    mpz_sub_ui(n_minus_1, n, 1);
    mpz_set_ui(s, 0);

    while (mpz_even_p(r) != 0) {
        mpz_add_ui(s, s, 1);
        mpz_fdiv_q_ui(r, r, 2);
    }

    mpz_t random_mpz, mpz_two, n_minus_3;
    mpz_inits(random_mpz, mpz_two, n_minus_3, NULL);
    mpz_set_ui(mpz_two, 2);
    mpz_sub_ui(n_minus_3, n, 3);

    time_t tim;
    srand((unsigned) time(&tim));
    uint64_t random_seed = 0;
    gmp_randstate_t tmp_state;
    gmp_randinit_mt(tmp_state);

    for (uint64_t i = 1; i < iters; i++) {
        random_seed = rand() + 1;
        gmp_randseed_ui(tmp_state, random_seed);
        mpz_urandomm(random_mpz, tmp_state, n_minus_3);
        mpz_add(random_mpz, random_mpz, mpz_two);
        pow_mod(y, random_mpz, r, n);

        if (mpz_cmp_ui(y, 1) != 0 && mpz_cmp(y, n_minus_1) != 0) {
            for (unsigned long int j = 1; j < mpz_get_ui(s); j++) {
                pow_mod(y, y, mpz_two, n);

                if (mpz_cmp(y, n_minus_1) == 0) {
                    break;
                }

                if (mpz_cmp_ui(y, 1) == 0) {
                    mpz_clears(r, s, y, n_minus_1, random_mpz, mpz_two, n_minus_3, NULL);
                    return false;
                }
            }

            if (mpz_cmp(y, n_minus_1) != 0) {
                mpz_clears(r, s, y, n_minus_1, random_mpz, mpz_two, n_minus_3, NULL);
                return false;
            }
        }
    }

    // Frees all memory
    mpz_clears(r, s, y, n_minus_1, mpz_two, random_mpz, n_minus_3, NULL);
    gmp_randclear(tmp_state);
    return true;
}

// Inspired by TA Eric
// Generates prime numbers from is_prime
void make_prime(mpz_t p, uint64_t bits, uint64_t iters) {
    mpz_t tmp_p;
    mpz_init(tmp_p);

    srand((unsigned) time(NULL));
    uint64_t random_seed = rand() + 1;
    gmp_randstate_t tmp_state;
    gmp_randinit_mt(tmp_state);
    gmp_randseed_ui(tmp_state, random_seed);

    do {
        mpz_ui_pow_ui(tmp_p, 2, bits - 1);
        mpz_urandomm(p, tmp_state, tmp_p);
        mpz_add(p, p, tmp_p);
    } while (is_prime(p, iters) == false);

    mpz_clear(tmp_p);
    gmp_randclear(tmp_state);
}

// Inspired pseudocode by Professor Long
// Used pseucode from assignment pdf
void mod_inverse(mpz_t i, mpz_t a, mpz_t n) {
    mpz_t r, rp, t, tp, q, tmp_r, tmp_t, tmp_mul, tmp_sub;
    mpz_inits(r, rp, t, tp, q, tmp_r, tmp_t, tmp_mul, tmp_sub, NULL);
    mpz_set(r, n);
    mpz_set(rp, a);
    mpz_set_si(t, 0);
    mpz_set_si(tp, 1);

    // While rp != 0
    while (mpz_cmp_ui(rp, 0) != 0) {
        mpz_fdiv_q(q, r, rp);
        mpz_set(tmp_r, r);
        mpz_set(r, rp);
        mpz_mul(tmp_mul, q, rp);
        mpz_sub(tmp_sub, tmp_r, tmp_mul);
        mpz_set(rp, tmp_sub);
        mpz_set(tmp_t, t);
        mpz_set(t, tp);
        mpz_mul(tmp_mul, q, tp);
        mpz_sub(tmp_sub, tmp_t, tmp_mul);
        mpz_set(tp, tmp_sub);
    }

    // If r > 1 -> return no inverse by setting i to 0
    if (mpz_cmp_si(r, 1) > 0) {
        mpz_set_si(i, 0);
        mpz_clears(r, rp, t, tp, q, tmp_r, tmp_t, tmp_mul, tmp_sub, NULL);
        return;
    }

    // If t < 0 -> set i to t + n
    if (mpz_cmp_si(t, 0) < 0) {
        mpz_add(t, t, n);
        mpz_set(i, t);
        mpz_clears(r, rp, t, tp, q, tmp_r, tmp_t, tmp_mul, tmp_sub, NULL);
        return;
    }

    // If memory hasn't be deallocated yet, deallocate memory
    mpz_set(i, t);
    mpz_clears(r, rp, t, tp, q, tmp_r, tmp_t, tmp_mul, tmp_sub, NULL);
    return;
}
