/*
 * DiscountTeddyBear
 * Date 3/10/2025
 * Key Generator
 * 
 * Description:
 * This program generates random cypher keys for AES Encryption
 * and the public and private cypher keys for RAS Encryption.
 * 
 * Notes:
 * If you do not have OpenSSL installed, run the following command:
 * sudo apt-get install libssl-dev
 * 
 * Compile program with the following command:
 * gcc Key_Generator.c -o Key_Generator -lssl -lcrypto
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>

//Generates public and private keys for RSA encryption/decryption and stores it in .pem files
void generate_RSA_keys() {
    // Key length for RSA
    int bits = 2048;
    unsigned long e = RSA_F4;  // Common exponent value (65537)

    // Generate RSA Key Pair
    RSA *rsa = RSA_new();
    BIGNUM *bn = BN_new();

    if (!BN_set_word(bn, e)) {
        fprintf(stderr, "Error setting exponent value.\n");
        exit(1);
    }

    if (!RSA_generate_key_ex(rsa, bits, bn, NULL)) {
        fprintf(stderr, "Error generating RSA keys.\n");
        exit(1);
    }

    // Save Public Key
    FILE *public_key_file = fopen("public_key.pem", "wb");
    if (!PEM_write_RSAPublicKey(public_key_file, rsa)) {
        fprintf(stderr, "Error saving public key.\n");
        exit(1);
    }
    fclose(public_key_file);

    // Save Private Key
    FILE *private_key_file = fopen("private_key.pem", "wb");
    if (!PEM_write_RSAPrivateKey(private_key_file, rsa, NULL, NULL, 0, NULL, NULL)) {
        fprintf(stderr, "Error saving private key.\n");
        exit(1);
    }
    fclose(private_key_file);

    printf("RSA key pair generated and saved to 'public_key.pem' and 'private_key.pem'.\n");

    // Free resources
    RSA_free(rsa);
    BN_free(bn);
}

//Generates cypher key for AES encryption/decryption and stores it in a file
void generate_AES_key() {
    // 256-bit AES key (32 bytes)
    unsigned char key[32];

    // Generate random 256-bit AES key
    if (RAND_bytes(key, sizeof(key)) != 1) {
        fprintf(stderr, "Error generating AES key.\n");
        exit(1);
    }

    // Open file to write the received data
    FILE *fp = fopen("AES_key.txt", "wb");
    if (fp == NULL) {
        printf("Failed to open file\n");
        exit(1);
    }
    
    for (int i = 0; i < 32; i++) {
        fprintf(fp, "%02x", key[i]);
    }

    printf("AES key generated and saved to 'AES_key.txt'.\n");

}

int main(int argc, char *argv[]) {
    char RSA_or_AES[100];

    if(argc == 2){
        strcpy(RSA_or_AES, argv[1]);
    }
    else{
        printf("Incorrect number of argument\nUsage: ./Key_Generator [RSA/AES]\n");
        return 1;
    }

    if(strcmp(RSA_or_AES, "RSA") == 0){
        generate_RSA_keys();
    }
    else if(strcmp(RSA_or_AES, "AES") == 0){
        generate_AES_key();
    }
    else{
        printf("Must use either 'RSA' or 'AES' as argument\nUsage: ./Key_Generator [RSA/AES]\n");
        return 1;
    }

    
    return 0;
}