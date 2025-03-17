/*
 * DiscountTeddyBear
 * Date 3/5/2025
 * Sender-Receiver Communication
 * 
 * Description:
 * This program is used to communicate between a sender and a receiver
 * using sockets for communication. The sender is the computer sending
 * data while the receiver is the computer receiving that data.
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 8080  // The port to bind the receiver to
#define BUFFER_SIZE 1024

//Runs the RSA_Encryption.c program to encrypt or decrypt a text file
//Will return whether or not the program failed through the check_if_failure variable
void RSA_Encryption(char *check_if_failure, char encrypt_or_decrypt[], char source_filename[], char key_filename[], char destination_filename[]){
    // Form the command string with arguments
    char command[256];
    snprintf(command, sizeof(command), "./RSA_Encryption %s %s %s %s", encrypt_or_decrypt, source_filename, key_filename, destination_filename);

    // Open the command for reading (run RSA_Encryption program)
    FILE *fp = popen(command, "r");
    if (fp == NULL) {
        perror("popen failed");
        exit(EXIT_FAILURE);
    }

    //Will store whether RSA_Encryption.c was sucessful for failed
    char output[1000];
    fgets(output, sizeof(output), fp);
    strcpy(check_if_failure, output);

    // Close the pipe
    fclose(fp);
}

// Function to receive a file from the sender
void Receive_File(int sender_sock, char filename[]) {
    char buffer[BUFFER_SIZE + 1];
    FILE *fp;
    int bytes_received;
    //Initializes buffer
    for(int i = 0; i < BUFFER_SIZE; i++){
        buffer[i] = '\0';
    }

    // Open file to write the received data
    fp = fopen(filename, "wb");
    if (fp == NULL) {
        printf("Failed to open file\n");
        exit(EXIT_FAILURE);
    }
    
    // Receive the file data in chunks
    while ((bytes_received = read(sender_sock, buffer, sizeof(buffer))) > 0){ //&& (activity = select(sender_sock + 1, &readfds, NULL, NULL, &timeout)) > 0) {
        buffer[BUFFER_SIZE + 1] = '\0';
        //Ends the loop if end of file is reached
        if(strcmp(buffer, "EOF") == 0 || strcmp(buffer, "OF") == 0 ){
            break;
        }
        fprintf(fp, "%s", buffer);

        for(int i = 0; i < BUFFER_SIZE; i++){
            buffer[i] = '\0';
        }
    }
    
    if (bytes_received < 0) {
        printf("Error in receiving file\n");
        exit(EXIT_FAILURE);
    }

    // Close the file
    fclose(fp);
}

// Function to send a file to the receiver
void Send_File(int receiver_sock, char filename[]) {
    FILE *fp;
    char buffer[BUFFER_SIZE];
    //Initializes buffer
    for(int i = 0; i < BUFFER_SIZE; i++){
        buffer[i] = '\0';
    }

    // Open the file to send
    fp = fopen(filename, "rb");
    if (fp == NULL) {
        printf("File not found\n");
        exit(EXIT_FAILURE);
    }

    char ch;
    int count = 0;

    // Printing what is written in file character by character using loop.
    while ((ch = fgetc(fp)) != 0xff) {
        // Once the words in the file have been gathered, the words are send to the receiver
        if(count == BUFFER_SIZE || ch == EOF){
            send(receiver_sock, buffer, sizeof(buffer), 0);
            
            for(int i = 0; i < BUFFER_SIZE; i++){
                buffer[i] = '\0';
            }
            count = 0;
        }
        
        buffer[count] = ch;
        count++;
        if(ch == EOF){
            break;
        }
    }
    // Pause for 1 millisecond (1000 microseconds)
    //usleep(1000);
    //char *empty_string = "\0";
    //send(receiver_sock, empty_string, 0, 0);
    //Lets the receiver know that the file has ended
    send(receiver_sock, "EOF", 3, 0);

    // Close the file
    fclose(fp);
}

//connect to receiver
//receive public key from receiver
//encrypt cypherkey with public key from receiver
//send encrypted cypher key to receiver
//send encrypted file to receiver
//end connection to receiver
int Send_Data_To_Receiver(char receiver_ip[], char encrypted_data_filename[], char public_key_filename[], char AES_cypher_key_filename[], char encrypted_AES_cypher_key_filename[]){
    int receiver_sock;
    struct sockaddr_in receiver_addr;
    char buffer[BUFFER_SIZE];

    // Create a socket
    if ((receiver_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("Socket creation failed\n");
        exit(EXIT_FAILURE);
    }

    receiver_addr.sin_family = AF_INET;
    receiver_addr.sin_port = htons(PORT);
    
    // Convert receiver IP address from text to binary
    if (inet_pton(AF_INET, receiver_ip, &receiver_addr.sin_addr) <= 0) {
        printf("Invalid address or address not supported\n");
        exit(EXIT_FAILURE);
    }

    // Connect to the receiver
    if (connect(receiver_sock, (struct sockaddr *)&receiver_addr, sizeof(receiver_addr)) < 0) {
        printf("Connection failed\n");
        exit(EXIT_FAILURE);
    }
    
    // Receive a message from the receiver
    Receive_File(receiver_sock, public_key_filename);

    char check_if_failure[7] = "failure";
    //Checks whether the receiver was able to decrypt the encrypted AES cypher key
    while(strcmp(check_if_failure, "failure") == 0){
        check_if_failure[0] = '\0'; // Resets value

        //Encrypts AES cypher key using RSA
        RSA_Encryption(check_if_failure, "encrypt", AES_cypher_key_filename, public_key_filename, encrypted_AES_cypher_key_filename);

        //Sends encrypted AES cypher key
        Send_File(receiver_sock, encrypted_AES_cypher_key_filename);
       
        //Receives whether the RSA encryption was successful or not from the receiver
        read(receiver_sock, check_if_failure, 7);
    }
    //Sends AES encrypted data
    Send_File(receiver_sock, encrypted_data_filename);

    // Close the socket
    close(receiver_sock);
}

//listen for sender
//connect to sender
//send the public key to sender to encrypts the sender's cypherkey
//receive encrypted cypher key
//decrypt encrypted cypher key using the private key
//receive encrypted file
//end connection to sender
int Listen_For_Incoming_Connections_From_Sender(char public_key_filename[], char private_key_filename[], char encrypted_data_filename[], char encrypted_AES_cypher_key_filename[], char decrypted_AES_cypher_key_filename[]){
    int receiver_sock, sender_sock;
    struct sockaddr_in receiver_addr, sender_addr;
    socklen_t addr_size;
    char buffer[BUFFER_SIZE];

    // Create a socket
    if ((receiver_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("Socket creation failed\n");
        exit(EXIT_FAILURE);
    }

    receiver_addr.sin_family = AF_INET;
    receiver_addr.sin_addr.s_addr = INADDR_ANY; // Allow any IP address to connect
    receiver_addr.sin_port = htons(PORT); // Bind to the defined port
    
    // Bind the socket
    if (bind(receiver_sock, (struct sockaddr *)&receiver_addr, sizeof(receiver_addr)) < 0) {
        printf("Bind failed\n");
        exit(EXIT_FAILURE);
    }
    
   
    // Listen for incoming connections
    if (listen(receiver_sock, 5) < 0) {
        printf("Listen failed\n");
        exit(EXIT_FAILURE);
    }
    
    printf("Receiver is listening on port %d...\n", PORT);

    addr_size = sizeof(sender_addr);
    // Accept incoming sender connection
    if ((sender_sock = accept(receiver_sock, (struct sockaddr *)&sender_addr, &addr_size)) < 0) {
        printf("Accept failed\n");
        exit(EXIT_FAILURE);
    }

    printf("Connection accepted from %s\n", inet_ntoa(sender_addr.sin_addr));

    
    //Sends public key
    Send_File(sender_sock, public_key_filename);

    char check_if_failure[7] = "failure";
    //Checks whether the receiver was able to decrypt the encrypted AES cypher key
    while(strcmp(check_if_failure, "failure") == 0){
        check_if_failure[0] = '\0'; // Resets value

        //Receives the encrypted AES cypher key file
        Receive_File(sender_sock, encrypted_AES_cypher_key_filename);

        //Decrypts AES cypher key using RSA
        RSA_Encryption(check_if_failure, "decrypt", encrypted_AES_cypher_key_filename, private_key_filename, decrypted_AES_cypher_key_filename);

        //Sends whether the RSA encryption was successful or not to sender
        write(sender_sock, check_if_failure, strlen(check_if_failure));
    }

    //Receives the AES encrypted data to be decrypted using the AES cypher key file
    Receive_File(sender_sock, encrypted_data_filename);

    // Close the connection
    close(sender_sock);
    close(receiver_sock);
}

// Executes program
int main(int argc, char *argv[]) {
    //Stores the help message to reduce the amount of copy and pasting
    char *help_message = "\nUsage 1: ./Sender_Receiver_Communication [send] [ip_address_of_receiver] [encrypted_data_filename] "
                        "[public_key_filename] [AES_cypher_key_filename] [encrypted_AES_cypher_key_filename]\n"
                        "\nUsage 2: ./Sender_Receiver_Communication [receive] [public_key_filename] [private_key_filename] "
                        "[encrypted_data_filename] [encrypted_AES_cypher_key_filename] [decrypted_AES_cypher_key_filename]\n"
                        "Example 1:\n./Sender_Receiver_Communication send 127.0.0.1 encrypted_data.txt public_key_2.pem AES_cypher_key.txt encrypted_AES_cypher_key.txt\n"
                        "Example 2:\n./Sender_Receiver_Communication receive public_key.pem private_key.pem encrypted_data.txt encrypted_AES_cypher_key.txt decrypted_AES_cypher_key.txt\n";

    char send_or_receive[100];

    // Checks for the correct number of arguments
    if (argc == 7){
        strcpy(send_or_receive, argv[1]);
    }
    else{
        printf("Incorrect number of arguments.%s", help_message);
        exit(EXIT_FAILURE);
    }

    // Determines if the program is in 'send' mode or 'reveive' mode
    if (argc == 7 && strcmp(send_or_receive, "receive") == 0){
        char public_key_filename[100];
        strcpy(public_key_filename, argv[2]);
        char private_key_filename[100];
        strcpy(private_key_filename, argv[3]);
        char encrypted_data_filename[100];
        strcpy(encrypted_data_filename, argv[4]);
        char encrypted_AES_cypher_key_filename[100];
        strcpy(encrypted_AES_cypher_key_filename, argv[5]);
        char decrypted_AES_cypher_key_filename[100];
        strcpy(decrypted_AES_cypher_key_filename, argv[6]);

        Listen_For_Incoming_Connections_From_Sender(public_key_filename, private_key_filename, encrypted_data_filename, encrypted_AES_cypher_key_filename, decrypted_AES_cypher_key_filename);
    }
    else if (argc == 7 && strcmp(send_or_receive, "send") == 0){
        char receiver_ip[100];
        strcpy(receiver_ip, argv[2]);
        char encrypted_data_filename[100];
        strcpy(encrypted_data_filename, argv[3]);
        char public_key_filename[100];
        strcpy(public_key_filename, argv[4]);
        char AES_cypher_key_filename[100];
        strcpy(AES_cypher_key_filename, argv[5]);
        char encrypted_AES_cypher_key_filename[100];
        strcpy(encrypted_AES_cypher_key_filename, argv[6]);

        Send_Data_To_Receiver(receiver_ip, encrypted_data_filename, public_key_filename, AES_cypher_key_filename, encrypted_AES_cypher_key_filename);
    }
    else{
        printf("Must use either 'send' or 'receive' as argument.%s", help_message);
        exit(EXIT_FAILURE);
    }

    return 0;
}
