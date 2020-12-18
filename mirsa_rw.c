// File: mirsa_rw.c
//
// Description: mirsa_rw.c is the module implemented to read and write to cipherfile streams.
//
// @author Ryan LaRue rml5169
// @date 11/09/2020
//
// // // // // // // // // // // // // // // // // // // // // // // // // //

#include "mirsa_lib.h"
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

/* The maximum buffer length to be read from a file*/
#define BUFFER_SIZE 1024
#define CHUNK_SIZE 4

///
/// print_usage is a static helper function designed to print out the 
/// general error message
///
static void print_usage() {
    fprintf(stderr, "\nusage:\n");
    fprintf(stderr, "Reader use: mirsa_rw [-vh] [-k keyname] -r ");
    fprintf(stderr, "cipherfile [plainfile]\n");
    fprintf(stderr, "            If plainfile is not provided, ");
    fprintf(stderr, "then reader output is to stdout.\n");
    fprintf(stderr, "Writer use: mirsa_rw [-vh] [-k keyname] -w ");
    fprintf(stderr, "cipherfile [plainfile]\n");
    fprintf(stderr, "            If plainfile is not provided, ");
    fprintf(stderr, "then writer input is from stdin.\n");
    fprintf(stderr, "The -v flag turns on verbose output.\n");
}

/// write_cipher is a static helper function designed to read a plaintext
/// string from either stdin or a specified file and write the equivelant  
/// encrypted string in a specified cipherfile
///
/// @param base_name - string name of the base name of the public key file
/// @param cipherfile - strng name of the cipherfile
/// @param plainfile - string name of the plainfile or NULL
static void write_cipher(char *base_name, char *cipherfile, char *plainfile) {
    // Appends the .pub file type to the base name
    char *pub_file = (char *)malloc(sizeof(char) * (strlen(base_name) + 5));
    strcpy(pub_file, base_name);
    strcat(pub_file, ".pub");
    key_t *pub_key = mr_read_keyfile(pub_file);
    
    char buffer[BUFFER_SIZE];
    size_t bytes_read;
    // If the plainfile is null, read from stdin
    if (plainfile == NULL) {
        bytes_read = fread(buffer, sizeof(char), BUFFER_SIZE, stdin);
    } else  {
        FILE *fp;
        fp = fopen(plainfile, "r");
        if (fp == NULL) {
            perror("error");
            exit(EXIT_FAILURE);
        }
        bytes_read = fread(buffer, sizeof(char), BUFFER_SIZE, fp);
        fclose(fp); 
    }

    FILE *cipherfp;
    cipherfp = fopen(cipherfile, "wb");
    if (cipherfp == NULL) {
        perror("error");
        exit(EXIT_FAILURE);
    }
    
    //TODO: Padding for less than chunk size and final 
    size_t i;
    char sub[5] = {'\0', '\0', '\0', '\0', '\0'};
    // Handles when less than 4 bytes read
    if (bytes_read < CHUNK_SIZE) {
        strncpy(sub, buffer, bytes_read);
        size_t j;
        for (j = bytes_read - 1; j < CHUNK_SIZE; j++) {
            sub[j] = '\0';
        }
        uint64_t encoded = mr_encode(sub);
        uint64_t encrypted = mr_encrypt(encoded, pub_key);
        fwrite(&encrypted, sizeof(uint64_t), 1, cipherfp);
    } else {
        // Splits into 4-byte chunks and writes to cipher file
        for (i = 0; i < bytes_read; i+=CHUNK_SIZE){
            strncpy(sub, buffer+i, CHUNK_SIZE);
            if (bytes_read % CHUNK_SIZE != 0 && i == (bytes_read - bytes_read % CHUNK_SIZE)) {
                size_t j;
                for (j = i; j < i + CHUNK_SIZE - bytes_read % CHUNK_SIZE; j++) {
                    sub[j] = '\0';
                }
            } else {
                strncpy(sub, buffer+i, CHUNK_SIZE);
            }
            uint64_t encoded = mr_encode(sub);
            uint64_t encrypted = mr_encrypt(encoded, pub_key); 
            fwrite(&encrypted, sizeof(uint64_t), 1, cipherfp); 
        }
    }

    fclose(cipherfp);
    free(pub_key);
    free(pub_file);
}

/// read_cipher is a static helper function designed to read the cipherfile, 
/// decode and decrypt the file, and output the plaintext equivelant to either
/// stdout or a specified file
///
/// @param base_name - string name of the base name of the public key file
/// @param cipherfile - strng name of the cipherfile
/// @param plainfile - string name of the plainfile or NULL
static void read_cipher(char *base_name, char *cipherfile, char *plainfile) {
    // Appends the .pvt file type to the base name
    char *priv_file = (char *)malloc(sizeof(char) *( strlen(base_name) + 5));
    strcpy(priv_file, base_name);
    strcat(priv_file, ".pvt");
    key_t *priv_key = mr_read_keyfile(priv_file);

    FILE *fp;
    fp = fopen(cipherfile, "rb");
    if (fp == NULL) {
        perror("error");
        fclose(fp);
        exit(EXIT_FAILURE);
    }
    
    uint64_t value;
    FILE *plainfp;
    if (plainfile != NULL) {
        plainfp = fopen(plainfile, "w");
    }

    while (fread(&value, sizeof(uint64_t), 1, fp)) {
        uint64_t decrypted = mr_decrypt(value, priv_key);
        char *decoded = mr_decode(decrypted);
        if (plainfile != NULL) {
            fwrite(decoded, 1, CHUNK_SIZE, plainfp);
        } else {
            printf("%s", decoded);
        }
        free(decoded);
    }

    if (plainfile != NULL) { 
        fclose(plainfp);
    }
    free(priv_key);
    free(priv_file);
    fclose(fp);
} 

/// main processes command line input flags, then calls the appropriate read/write 
/// functions.
///
/// @param argc - integer number of command line arguments
/// @param argv - array of command line argument strings 
/// @return EXIT_SUCCESS on success, EXIT_FAILURE otherwise
int main(int argc, char *argv[]) {
    int opt;
    bool verbose = false;
    char *base_name = getlogin();
    char rw = '\0';
    char *cipherfile, *plainfile = NULL;
    if (argc == 1) {
        fprintf(stderr, "error: missing file argument");
        print_usage();
        exit(EXIT_FAILURE);
    }
    while ((opt = getopt(argc, argv, "hvk:r:w:")) != -1 ) {
        switch(opt) {
            case 'h':
                print_usage();
                exit(EXIT_SUCCESS);
                break;
            case 'v':
                verbose = true;
                break;
            case 'k':
                base_name = optarg;
                break;
            case 'r':  
            case 'w':
                rw = opt;
                cipherfile = optarg;
                break;
            case '?':
                fprintf(stderr,"error: unknown flag\n");
            default:
                print_usage(); 
        }
    }

    if (optind < argc) {
        plainfile = argv[optind];
    } 
        
    mr_verbose(verbose);
    if (verbose) {
        printf("Base Name: %s\n", base_name);
        printf("Read/Write: %c\nCipher File: %s\n", rw, cipherfile);
        printf("Plain File: %s\n", plainfile);
    }
    if (rw == 'w') {
        write_cipher(base_name, cipherfile, plainfile);
    } else if (rw == 'r') {
        read_cipher(base_name, cipherfile, plainfile);
    }
     
    exit(EXIT_SUCCESS);
}
