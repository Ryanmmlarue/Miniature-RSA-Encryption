// 
// File: mirsa_genkeys.c
//
// Description: mirsa_genkeys read generates and writes binary files containing public and 
// private encryption keys from a random list of primes
//
// @author Ryan LaRue rml5169
// @date 10/26/2020
//
// // // // // // // // // // // // // // // // // // // // // // // // // //

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include "mirsa_lib.h"

// The maximum buffer length of input
#define BUFFER_LENGTH 1024


/// verify_int verifies that a given argument is an integer value
///
/// @param optarg c string to be converted to an integer
/// @return true if optarg is an integer, false otherwise
bool verify_int(char * optarg) {
    int i;
    for (i = 0; i < (int)strlen(optarg); i++) {
        if (!isdigit(optarg[i]) && optarg[i] != '\n') return false;
    }
    return true;
}

/// read_primes_file populates an array of unsigned long integers based on a given file
///
/// @param primes pointer to array of unsigned long integers
/// @param file_name C string of the name of the Primes file
/// @return the number of primes read
uint64_t read_primes_file(uint64_t ** primes, char *file_name) {
    FILE * fp;
    char buffer[BUFFER_LENGTH];
    //Check if file is invalid
    if ((fp = fopen(file_name, "r")) == NULL) {
        fprintf(stderr, "error: missing primes file.\n");
        exit(EXIT_FAILURE);
    }
    fgets(buffer, BUFFER_LENGTH, fp);
    // Check if number of primes is invalid
    if (verify_int(buffer) == false) {
        fprintf(stderr, "error: primes file has invalid count.\n");
        exit(EXIT_FAILURE);
    }
    uint64_t num_primes = strtoul(buffer, NULL, 10);
    
    (*primes) = (uint64_t *)malloc(sizeof(uint64_t) * num_primes);
   
    int i = 0;
    while (fgets(buffer, BUFFER_LENGTH, fp)) {
        char * token;
        token = strtok(buffer, " \t\n");
        while (token != NULL) {
            (*primes)[i] = strtoul(token, NULL, 10);
            i++;
            token = strtok(NULL, " \t\n");
        }
    }
    fclose(fp);
    return num_primes;
}

/// verify_args checks the given flags and assigns appropriate values for various flags 
/// used to generate keys.
///
/// @param argc integer value for length of argv
/// @param *argv an array of c-string command line args
/// @param *verbose a pointer to a boolean flag for verbose output
/// @param *seed_number a pointer an integer value for the random seed
/// @param a pointer to a c-string for the name of the .pub and .pvt file name
void verify_args(int argc, char *argv[], bool *verbose, time_t *seed_number, char ** base_name) {
    int opt;
    while ((opt = getopt(argc, argv, "hvk:s:")) != -1) {
        switch (opt) {
            case 'h':
                fprintf(stderr, "\nusage: mirsa_genkeys [-hv] [-k keyname] [-s seed]\n");
                exit(EXIT_SUCCESS);
                break;
            case 'v':
                *verbose = true;
                break;
            case 'k':
                *base_name = optarg;
                break;
            case 's':
                if (verify_int(optarg)) {
                    *seed_number = strtoul(optarg, NULL, 10);
                } else {
                   fprintf(stderr, "error: invalid seed value '%s'\n", optarg);
                   fprintf(stderr, "usage: mirsa_getkeys [-hv] [-k keyname] [-s seed]\n");
                    exit(EXIT_FAILURE);
                }
                break;
            case '?':
                // Fall through since getopt will automatically report missing argument
            default:
                fprintf(stderr, "usage: mirsa_getkeys [-hv] [-k keyname] [-s seed]\n");
                exit(EXIT_FAILURE);
        }
    }
    if (argc > optind) {
        fprintf(stderr, "error: extra argument: '%s'\n", argv[optind]);
        fprintf(stderr, "usage: mirsa_getkeys [-hv] [-k key] [-s seed]\n");
        exit(EXIT_FAILURE);
    }
}

/// Reads in flags, assigns them to their appropriate values, and generates  .pub and
/// .pvt binary files containing key, nonce pairs.
///
/// @param argc integer number of arguments
/// @param argv array of c-string of arguments
/// @return EXIT_SUCCESS on success, EXIT_FAILURE otherwise
int main(int argc, char * argv[]) {
    bool verbose = false;
    time_t seed_number = time(0);
    char* base_name = getlogin();
    verify_args(argc, argv, &verbose, &seed_number, &base_name); 
    mr_verbose(verbose);
    srand(seed_number);
    uint64_t *primes = NULL, num_primes;
    num_primes = read_primes_file(&primes,"Primes.txt");
    uint64_t p = primes[rand() % num_primes], q = primes[rand() % num_primes];
   
    int count = 0;
    while (mr_make_keys(p, q, base_name) == false) {
        if (count == 3) {
            fprintf(stderr, "error: mr_make_keys: failed to generate keyset.\n");
            exit(EXIT_FAILURE);
        } else {
            // Pick a new q if an overflow occurs 
            q = primes[rand() % num_primes];
            count++;
        }
    }
    free(primes);
    exit(EXIT_SUCCESS);
}


