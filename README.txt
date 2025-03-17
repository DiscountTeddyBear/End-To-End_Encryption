# End-To-End_Encryption
The task for this project is to create a series of C programs that can execute end-to-end encryption between two systems. 

End-to-end encryption utilizes both AES encryption and RSA encryption to keep data secure during transit. To accomplish this, the programs will first encrypt the user’s selected file using AES encryption. 

Since AES uses symmetric encryption, the programs will then securely transfer the cypher key used for AES encryption to the target system using RSA. Since RSA uses asymmetric encryption, the AES cypher key will be encrypted using the public key generated and decrypted using the private key.

Finally, the programs on the system that received the encrypted data will decrypt the data to get the original plain text.   

# Usage
./main [send/receive] [source_filename/output_filename] [ip_address_of_receiver](Required when in send mode. Leave empty in receive mode)

Example 1: 

./main send test.txt 127.0.0.1

Example 2: 

./main receive received_test.txt

# Notes
To compile the programs easily on your Linux system, run the provided program:

./compile_c_programs.sh


If you do not have OpenSSL installed on your Linux system, run the following command:

sudo apt-get install libssl-dev

