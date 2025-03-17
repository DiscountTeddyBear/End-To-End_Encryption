/*
 * DiscountTeddyBear
 * Date 3/11/2025
 * RSA Encryption
 * 
 * Description:
 * This encrypts and decrypts data using RSA encryption.
 * 
 * Notes:
 * If you do not have OpenSSL installed, run the following command:
 * sudo apt-get install libssl-dev
 * 
 * Compile program with the following command:
 * gcc RSA_Encryption.c -o RSA_Encryption -lssl -lcrypto
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>

#define BUFFER_SIZE 256
#define KEY_LENGTH 2048

// Function to load the public key from PEM format
RSA* load_public_key(char *public_key_filename) {
    FILE *public_key_file = fopen(public_key_filename, "rb");
    if (!public_key_file) {
        printf("Unable to open public key file: %s\n", public_key_filename);
        perror("fopen");
        exit(1);
    }
    RSA *public_key = PEM_read_RSAPublicKey(public_key_file, NULL, NULL, NULL);
    fclose(public_key_file);
    if (!public_key) {
        printf("Unable to read public key from file: %s\n", public_key_filename);
        perror("PEM_read_RSAPublicKey");
        exit(1);
    }
    return public_key;
}

// Function to load the private key from PEM format
RSA* load_private_key(char *private_key_filename) {
    FILE *private_key_file = fopen(private_key_filename, "rb");
    if (!private_key_file) {
        printf("Unable to open private key file: %s\n", private_key_filename);
        perror("fopen");
        exit(1);
    }
    RSA *private_key = PEM_read_RSAPrivateKey(private_key_file, NULL, NULL, NULL);
    fclose(private_key_file);
    if (!private_key) {
        printf("Unable to read private key from file: %s\n", private_key_filename);
        perror("PEM_read_RSAPrivateKey");
        exit(1);
    }
    return private_key;
}

// Encryption using the public key
int encrypt_with_public_key(RSA *public_key,unsigned char *message, unsigned char *encrypted) {
    int result = RSA_public_encrypt(strlen((char*)message) + 1, message, encrypted, public_key, RSA_PKCS1_PADDING);
    if (result == -1) {
        perror("Unable to encrypt using public key");
        exit(1);
    }
    
    return result;
}

// Decryption using the private key
int decrypt_with_private_key(RSA *private_key,unsigned char *encrypted, unsigned char *decrypted) {
    int result = RSA_private_decrypt(RSA_size(private_key), encrypted, decrypted, private_key, RSA_PKCS1_PADDING);
    if (result == -1) {
        perror("Unable to decrypt using private key");
        exit(1);
    }
    
    return result;
}

int main(int argc, char *argv[]) {
    //Stores the help message to reduce the amount of copy and pasting
    char *help_message = "\nUsage: ./RSA_Encryption [encrypt/decrypt] [source_filename]"
                        " [public_key_filename/private_key_filename] [destination_filename]\nExample:"
                        "\n./RSA_Encryption encrypt AES_key.txt public_key.pem encrypted_AES_key.txt";

	//Check for correct number of argument
	if (argc != 5) {
        printf("%s", help_message);
        return 1;
    }
    
    unsigned char message[KEY_LENGTH / 8]; // Buffer to hold message to encrypt/decrypt
    unsigned char encrypted[(KEY_LENGTH / 8) + 1];  // Buffer to hold encrypted data
    unsigned char decrypted[(KEY_LENGTH / 8) + 1];  // Buffer to hold decrypted data
    //Initialize buffers
    for(int i = 0; i < KEY_LENGTH / 8; i++){
        message[i] = '\0';
    }
    for(int i = 0; i < KEY_LENGTH / 8; i++){
        encrypted[i] = '\0';
        decrypted[i] = '\0';
    }

    //Stores source filename from command line
    char source_filename[100];
    strcpy(source_filename, argv[2]);
    // Open the file that contains the message
    FILE *source_fp = fopen(source_filename, "rb");
    if (source_fp == NULL) {
        printf("Unable to read message from file: %s\n", source_filename);
        perror("fopen");
        exit(1);
    }

    //Stores destination filename from command line
    char destination_filename[100];
    strcpy(destination_filename, argv[4]);
    // Open file to write the result of the encryption/decryption
    FILE *destination_fp = fopen(destination_filename, "wb");
    if (destination_fp == NULL) {
        printf("Unable to write result to file: %s\n", destination_filename);
        perror("fopen");
        exit(1);
    }
    
    char encrypt_or_decrypt[100]; //Stores whether the user wants to encrypt or decrypt the file
    strcpy(encrypt_or_decrypt, argv[1]);

    //Encrypts or decrypts the data
    if(strcmp(encrypt_or_decrypt, "encrypt") == 0){
        //Stores public key filename from command line
        char public_key_filename[100];
        strcpy(public_key_filename, argv[3]);

        //Loads public key from file
        RSA *public_key = load_public_key(public_key_filename);

        char ch;
        int count = 0;
        // Printing what is written in file character by character using loop.
        while ((ch = fgetc(source_fp)) != 0xff) {
            // Once the words in the file have been gathered, the words are encrypted
            if(count == KEY_LENGTH / 8 || ch == EOF){
                int encrypted_length = encrypt_with_public_key(public_key, (unsigned char*)message, encrypted);
                encrypted[encrypted_length] = '\0';

                fprintf(destination_fp, "%s", encrypted);
            }

            message[count] = ch;

            if(ch == EOF){
                break;
            }
            else if(count == KEY_LENGTH / 8){
                for(int i = 0; i < KEY_LENGTH / 8; i++){
                    message[i] = '\0';
                }
                count = 0;
            }
            count++;
        }
        // Close public key
        RSA_free(public_key);
        // Close the files
        fclose(source_fp);
        fclose(destination_fp);
    }
    else if(strcmp(encrypt_or_decrypt, "decrypt") == 0){    
        //Stores public key filename from command line
        char private_key_filename[100];
        strcpy(private_key_filename, argv[3]);

        //Loads public key from file
        RSA *private_key = load_private_key(private_key_filename);

        char ch;
        int count = 0;

        // Printing what is written in file character by character using loop.
        while ((ch = fgetc(source_fp)) != 0xff) {
            // Once the words in the file have been gathered, the words are decrypted
            if(count == KEY_LENGTH / 8 || ch == EOF){
                int decrypted_length = decrypt_with_private_key(private_key, message, decrypted);
                decrypted[decrypted_length] = '\0';
                //Will check to make sure that the string is of the desired length since the message will always have a length of 65
                if(decrypted_length != 65){
                    printf("failure");
                    break;
                }
                else{
                    printf("sucess");
                }
                
                fprintf(destination_fp, "%s", decrypted);
            }

            message[count] = ch;
            if(ch == EOF){
                break;
            }
            else if(count == KEY_LENGTH / 8){
                for(int i = 0; i < KEY_LENGTH / 8; i++){
                    message[i] = '\0';
                }
                count = 0;
            }
            count++;
        }
        // Close private key
        RSA_free(private_key);
        // Close the files
        fclose(source_fp);
        fclose(destination_fp);
    }
    else{
        printf("Must use \"encrypt\" or \"decrypt\" keyword as first argument. Remove quotation marks.%s", help_message);
        return 1;
    }
    return 0;
}