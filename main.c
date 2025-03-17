/*
 * DiscountTeddyBear
 * Date 3/5/2025
 * 
 * Description:
 * This program is used to call all the necessary 
 * programs to perform end-to-end encryption
 * 
 * Notes:
 * If you do not have OpenSSL installed, run the following command:
 * sudo apt-get install libssl-dev
 * 
 * Compile program with the following command:
 * gcc main.c -o main -lssl -lcrypto
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>

//Runs the Sender_Receiver_Communication.c program to receive a file
void Receiver_Communication(char public_key_filename[], char private_key_filename[], char encrypted_data_filename[], char encrypted_AES_cypher_key_filename[], char decrypted_AES_cypher_key_filename[]){
    // Form the command string with arguments
    char command[256];
    snprintf(command, sizeof(command), "./Sender_Receiver_Communication receive %s %s %s %s %s", public_key_filename, private_key_filename, encrypted_data_filename, encrypted_AES_cypher_key_filename, decrypted_AES_cypher_key_filename);

    // Open the command for reading (run Sender_Receiver_Communication program)
    FILE *fp = popen(command, "r");
    if (fp == NULL) {
        perror("popen failed");
        exit(EXIT_FAILURE);
    }
    //Prints messages from Sender_Receiver_Communication.c
    char output[1000];
    while (fgets(output, sizeof(output), fp) != NULL) {
        printf("Sender_Receiver_Communication: %s", output);
    }

    // Close the pipe
    fclose(fp);
}

//Runs the Sender_Receiver_Communication.c program to send a file
void Sender_Communication(char receiver_ip[], char encrypted_data_filename[], char public_key_filename[], char AES_cypher_key_filename[], char encrypted_AES_cypher_key_filename[]){
    // Form the command string with arguments
    char command[256];
    snprintf(command, sizeof(command), "./Sender_Receiver_Communication send %s %s %s %s %s", receiver_ip, encrypted_data_filename, public_key_filename, AES_cypher_key_filename, encrypted_AES_cypher_key_filename);

    // Open the command for reading (run Sender_Receiver_Communication program)
    FILE *fp = popen(command, "r");
    if (fp == NULL) {
        perror("popen failed");
        exit(EXIT_FAILURE);
    }
    //Prints messages from Sender_Receiver_Communication.c
    char output[1000];
    while (fgets(output, sizeof(output), fp) != NULL) {
        printf("Sender_Receiver_Communication: %s", output);
    }

    // Close the pipe
    fclose(fp);
}

//Runs the AES_Encryption.c program to encrypt or decrypt a text file
void AES_Encryption(char encrypt_or_decrypt[], char cypher_key[], char source_filename[], char destination_filename[]){
    // Form the command string with arguments
    char command[256];
    snprintf(command, sizeof(command), "./AES_Encryption %s %s %s %s", encrypt_or_decrypt, cypher_key, source_filename, destination_filename);

    // Open the command for reading (run AES_Encryption program)
    FILE *fp = popen(command, "r");
    if (fp == NULL) {
        perror("popen failed");
        exit(EXIT_FAILURE);
    }

    //Prints messages from AES_Encryption.c
    char output[1000];
    while (fgets(output, sizeof(output), fp) != NULL) {
        printf("AES_Encryption: %s", output);
    }

    // Close the pipe
    fclose(fp);
}

//Extracts the cypher key used in AES_Encryption.c from a file
void Extract_AES_Encryption_Cypher_Key_From_File(char filename[], char cypher_key[]){
    // Opening file in reading mode
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        perror("ERROR! File can't be opened! \n");
        exit(EXIT_FAILURE);
    }

    char ch; // Character buffer that stores the read character till the next iteration
    int count = 0; // Counts number of iterations through loop
    while ((ch = fgetc(file)) != EOF) {
        cypher_key[count] = ch;
        count++;
    }
}

//Runs the Key_Generator.c program to generate the public and private 
//keys that will be used by RSA_Encryption
void Generate_RSA_Keys(){
    // Form the command string with arguments
    char command[256];
    snprintf(command, sizeof(command), "./Key_Generator RSA");

    // Open the command for reading (run Key_Generator program)
    FILE *fp = popen(command, "r");
    if (fp == NULL) {
        perror("popen failed");
        exit(EXIT_FAILURE);
    }

    //Prints messages from Key_Generator.c
    char output[1000];
    while (fgets(output, sizeof(output), fp) != NULL) {
        printf("Key_Generator: %s", output);
    }
    
    // Close the pipe
    fclose(fp);
}

//Runs the Key_Generator.c program to generate the cypher key that will be used by AES_Encryption
void Generate_AES_Key(){
    // Form the command string with arguments
    char command[256];
    snprintf(command, sizeof(command), "./Key_Generator AES");

    // Open the command for reading (run Key_Generator program)
    FILE *fp = popen(command, "r");
    if (fp == NULL) {
        perror("popen failed");
        exit(EXIT_FAILURE);
    }

    //Prints messages from Key_Generator.c
    char output[1000];
    while (fgets(output, sizeof(output), fp) != NULL) {
        printf("Key_Generator: %s", output);
    }
    
    // Close the pipe
    fclose(fp);
}

void test(){
    // The arguments to pass to programB
    char *arg1 = "Hello";
    char *arg2 = "World";

    // Form the command string with arguments
    char command[256];
    snprintf(command, sizeof(command), "./test %s %s", arg1, arg2);

    // Open the command for reading (run programB)
    FILE *fp = popen(command, "r");
    if (fp == NULL) {
        perror("popen failed");
        exit(EXIT_FAILURE);
    }

    // Read the output from programB
    char output[256];
    while (fgets(output, sizeof(output), fp) != NULL) {
        printf("from test: %s", output);
    }

    // Close the pipe
    fclose(fp);
}

//if sender:
//generate cypher key
//encrypt file
//connect to receiver
//receive public key from receiver
//encrypt cypherkey with public key from receiver
//send encrypted cypher key to receiver
//send encrypted file to receiver
//end connection to receiver
//
//if reciever:
//generate public and private key
//listen for sender
//connect to sender
//send the public key to sender to encrypts the sender's cypherkey
//receive encrypted cypher key
//decrypt encrypted cypher key using the private key
//receive encrypted file
//end connection to sender
//decrypt encrypted file using the decrypted cypher key
int main(int argc, char *argv[]) {
    //Stores the help message to reduce the amount of copy and pasting
    char *help_message = "\nUsage: ./main [send/receive] [source_filename/output_filename]"
                        " [ip_address_of_receiver](Required when in send mode. Leave empty in receive mode)\n"
                        "Example 1:\n./main send test.txt 127.0.0.1\n"
                        "Example 2:\n./main receive received_test.txt\n";

    //Check for correct number of argument
	if (argc < 3 ||argc > 4) {
        printf("Incorrect number of arguments.%s", help_message);
        return 1;
    }

    char send_or_receive[100]; //Stores whether the user wants to send or receive a file
    strcpy(send_or_receive, argv[1]);

    char user_filename[100]; //Stores the filename the user wants to send or receive data in
    strcpy(user_filename, argv[2]);

    char ip_address_of_receiver[100]; //Stores the ip address of the receiver in send mode
    if(argc == 4){
        strcpy(ip_address_of_receiver, argv[3]);
    }

    //Checks if send mode has both a source_filename and an ip address as arguments
    if(argc == 3 && strcmp(send_or_receive, "send") == 0){
        printf("Missing argument for send mode.\nEnsure that both the source_filename and the ip_address_of_receiver are included as arguments.%s", help_message);
        return 1;
    }
    //Checks if send mode has only an output_filename
    else if(argc == 4 && strcmp(send_or_receive, "receive") == 0){
        printf("Too many arguments for receive mode.\nOnly an output_filename is needed. Please remove the ip_address_of_receiver argument.%s", help_message);
        return 1;
    }
    else if(strcmp(send_or_receive, "send") != 0 && strcmp(send_or_receive, "receive") != 0){
        printf("Must use \"send\" or \"receive\" keyword as first argument. Remove quotation marks.%s", help_message);
        return 1;
    }

    //List of filenames used as constants in the programs

    //If Sender
    char *AES_Encryption_cypher_key_filename = "AES_key.txt";
    char *AES_Encryption_result_filename = "AES_Encryption_Result.txt";
    char *public_key_received_filename = "public_key_received.pem";
    char *encrypted_AES_cypher_key_filename = "encrypted_AES_key.txt";

    //If Receiver
    char *public_key_filename = "public_key.pem";
    char *private_key_filename = "private_key.pem";
    char *encrypted_AES_cypher_key_received_ilename = "encrypted_AES_key_received.txt";
    char *decrypted_AES_cypher_key_filename = "decrypted_AES_cypher_key.txt";
    char *encrypted_data_received_filename = "encrypted_data_received.txt";



    //Executes programs to send the source file to the receiver
    if(strcmp(send_or_receive, "send") == 0){

        Generate_AES_Key();

        char AES_Encryption_cypher_key[100];
        Extract_AES_Encryption_Cypher_Key_From_File(AES_Encryption_cypher_key_filename, AES_Encryption_cypher_key);

        AES_Encryption("encrypt", AES_Encryption_cypher_key, user_filename, AES_Encryption_result_filename);
        printf("Encrypted %s\n", user_filename);

        Sender_Communication(ip_address_of_receiver, AES_Encryption_result_filename, public_key_received_filename, AES_Encryption_cypher_key_filename, encrypted_AES_cypher_key_filename);
        printf("Encrypted file sent to %s\n", ip_address_of_receiver);
    }

    //Executes programs to receive the encrypted source file from sender
    if(strcmp(send_or_receive, "receive") == 0){

        Generate_RSA_Keys();

        Receiver_Communication(public_key_filename, private_key_filename, encrypted_data_received_filename, encrypted_AES_cypher_key_received_ilename, decrypted_AES_cypher_key_filename);
        printf("Received encrypted file\n");

        char AES_Encryption_cypher_key[100];
        Extract_AES_Encryption_Cypher_Key_From_File(decrypted_AES_cypher_key_filename, AES_Encryption_cypher_key);

        AES_Encryption("decrypt", AES_Encryption_cypher_key, encrypted_data_received_filename, user_filename);
        printf("Decrypted file and sent result to %s\n", user_filename);
    }

    printf("End-to-End Encryption Completed\n");
  
    return 0;
}
