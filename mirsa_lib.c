// File: mirsa_lib.c
//
// Description: mirsa_lib.c is the module implemented to assist in key generation, encryption, and decryption.
//
// @author Ryan LaRue rml5169
// @date 10/27/2020
//
// // // // // // // // // // // // // // // // // // // // // // // // // //

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <math.h>
#include "mirsa_lib.h"

/// Verbose output flag
static bool VERBOSE = 0;

/// inverse computes the multiplicative inverse for a given a and n value 
///
/// @param n unsigned integer for a
/// @param a unsigned integer used 
/// @return an unsigned integer for the multiplicative inverse
static uint64_t inverse(uint64_t a, uint64_t n) {
    int64_t t = 0, newt = 1;
    uint64_t r = n, newr = a, quotient;
    
    while (newr != 0) {
        quotient = r / newr;
        if (VERBOSE) printf("Quotient: %lu\n", quotient);
        int64_t tempt = t, tempr = r;
        t = newt;
        newt = tempt - quotient * newt;
        r = newr;
        newr = tempr - quotient * newr;
        if (VERBOSE) {
           printf("T: %ld\n", t);
            printf("New T: %ld\n", newt);
            printf("R:: %lu\n", r);
            printf("New R: %lu\n", newr);
            printf("\n");
        }
    }

    if (r > 1) return NULL;
    if (t < 0) t = t + n;
    return t;
}

/// write_binaries writes the public, private, and nonce values to the specified <user>.pvt and 
/// <user>.pub binary files.
///
/// @param priv_key unsigned integer for the private key value
/// @param pub_key unsigned integer for the public key value
/// @param nonce unsigned integer for the nonce value
/// @param user c-string for the file prefix name
static void write_binaries(uint64_t priv_key, uint64_t pub_key, uint64_t nonce, const char * user) {
    assert(user != NULL);
    FILE *fp;
    int space_needed = strlen(user) + 5;
    char * file_name = (char *)malloc(sizeof(char) * space_needed);

    // Writes private key file
    strcpy(file_name, user);
    strcat(file_name, ".pvt");
    fp = fopen(file_name, "wb");
    assert(fp != NULL); 
    fwrite(&priv_key, sizeof(uint64_t), 1, fp);
    fwrite(&nonce, sizeof(uint64_t), 1, fp);
    fclose(fp);

    // Writes public key file
    strcpy(file_name, user);
    strcat(file_name, ".pub");
    fp = fopen(file_name, "wb");
    assert(fp != NULL);
    fwrite(&pub_key, sizeof(uint64_t), 1, fp);
    fwrite(&nonce, sizeof(uint64_t), 1, fp);
    fclose(fp);
    free(file_name);
}

///
/// Calculates public, private, and nonce values and writes them to binaries.
///        
bool mr_make_keys(uint64_t p, uint64_t q, const char * user) {
    
    assert(user != NULL);

    if (VERBOSE) {
        printf("P: %lu\n", p);
        printf("Q: %lu\n", q);
    }
    uint64_t n = p * q;
    // Check overflow, return false if no valid keyset
    if (__builtin_umull_overflow(p, q, &n)) {
        fprintf(stderr, "error: mr_make_keys: overflow. no keyset for <%lu, %lu>.\n", p, q);
        return false;
    } 
    uint64_t phi = (p - 1) * (q - 1);
    uint64_t e, d;
    for (e = 3; e <= 9; e++) {
        d = inverse(e, phi);
        if (VERBOSE) {
            printf("E: %lu\n", e);
            printf("D: %lu\n", d);
        }
        if (d != NULL) {
            if (VERBOSE) {
                printf("Pub Key:%lu, Priv Key:%lu\n", e, d);
            }
            write_binaries(d, e, n, user);
            return true;
        }
    }

   // Report failure and terminate
   fprintf(stderr, "no keyset for <%lu, %lu>\n", p, q);
   exit(EXIT_FAILURE);
}

///
/// Sets the VERBOSE flag to the passed value
///
bool mr_verbose(bool value) {
    bool old_verbose = VERBOSE;
    VERBOSE = value;
    return old_verbose;
}

///
/// Reads the key and nonce from the specified 
///
key_t * mr_read_keyfile(const char * file_name) {
    FILE * fp;
    key_t *key_struct = malloc(sizeof(key_t));
    fp = fopen(file_name, "rb");
    assert(fp != NULL);
    fread(&key_struct->key, sizeof(uint64_t), 1, fp);
    fread(&key_struct->nonce, sizeof(uint64_t), 1, fp);
    fclose(fp);
    return key_struct;
}

/// modpow is a static helper function designed to iteratively compute requisite 
/// powers of x and then iteratively multiply the powers together (using mod z). 
///
/// @param x unsigned long int whose requisite powers must be calculated
/// @param y unsigned long int used to validate the multiplication of x values
/// @param z unsigned long int used as part of the modular division operations
/// @return The unsigned long int value calculated through the modpow algorithm
static uint64_t modpow(uint64_t x, uint64_t y, uint64_t z) {
    int index = ceil(log2(y)) + 1; 
    uint64_t mods[index];
    mods[0] = x;
    int i;
    for (i = 1; i < index -1; i++) {
        mods[i] = (mods[i-1] * mods[i-1])% z;
    }   

    uint64_t val = 1;
    for (i = index -1; i >= 0; i--) {
        uint64_t current = pow(2, i);
        if (current <= y){
            if (VERBOSE) {
                printf("i: %d\n", i);
                printf("Current: %ld\n", current);
            }
            val = (val * mods[i]) % z;
            y -= current;
        }
    }
    if (VERBOSE) {
        printf("Val: %ld\n", val);
    }
    return val;
}




///
/// Encrypts the message encoded in p using the pubkey
///
uint64_t mr_encrypt(uint64_t p, const key_t * pubkey) {
    return modpow(p, pubkey->key, pubkey->nonce);
}

///
/// Decrypts the encrypted cipher c using the pvtkey
///
uint64_t mr_decrypt(uint64_t c, const key_t * pvtkey) {
    return modpow(c, pvtkey->key, pvtkey->nonce);
}

///
/// Converts a string to an unsigned long int code
///
uint64_t mr_encode(const char * st) {
    int hex_step = 0, loop_step = 0;
    char hex_st[9]; //2 * max number of chars + 1 for '\0'
    while (st[loop_step] != '\0') {
        sprintf(&hex_st[hex_step], "%02X", st[loop_step]);
        hex_step += 2;
        loop_step++;
    }
    hex_st[hex_step++] = '\0';

    uint64_t hex_int = strtoul(hex_st, NULL, 16);
    if (VERBOSE) {
        printf("Input String: %s\n", st);
        printf("Hex String: %s\n", hex_st);
        printf("Encoded String: %lu\n", hex_int);
    }
    return hex_int;
}

///
/// Converts an unsinged code to a string
///
char * mr_decode(uint64_t code) {
    int num_digits = snprintf(NULL, 0, "%lu", code);  
    char hex_st[num_digits + 1];
    char * decoded_st = (char *)malloc(sizeof(char) * 5);
    snprintf(hex_st, num_digits + 1,"%02lX", code);
    int i, decoded_index = 0;
    for (i = 0; i < num_digits - 1; i+=2) {
        char sub_st[2] = {hex_st[i], hex_st[i+1]};
        decoded_st[decoded_index] = strtoul(sub_st, NULL, 16);
        decoded_index++;
    }  
    //decoded_st[4] = '\0';
    
    if (VERBOSE) {
        printf("Number of Digits: %d\n", num_digits);
        printf("Input Integer: %lu\n", code);
        printf("Hex String: %s\n", hex_st);
        printf("Decoded String: %s\n", decoded_st);
    }
   
    return decoded_st;
}



