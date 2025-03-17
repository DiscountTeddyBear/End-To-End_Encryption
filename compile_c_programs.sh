#!/bin/bash

# DiscountTeddyBear
# Date 3/14/2025
# compile_c_programs
# 
# Description:
# This compiles all the programs in this project.
# 
# Usage: ./compile_c_programs.sh

# Programs that do not require any additional libraries 
regular_program_filenames=("AES_Encryption.c" "Sender_Receiver_Communication.c")

# Programs that require the OpenSSL libraries at compilation
# If OpenSSL is not installed, run the following command:
# sudo apt-get install libssl-dev
openssl_program_filenames=("main.c" "Key_Generator.c" "RSA_Encryption.c")

# Loop through each file that needs openssl
for source_file in "${regular_program_filenames[@]}"; do
    # Check if the file exists
    if [ ! -f "$source_file" ]; then
        echo "Error: File '$source_file' not found!"
        continue
    fi

    # Get the name of the output executable (strip the .c extension)
    output_file="${source_file%.c}"

    # Compile the C program
    echo "Compiling $source_file into $output_file ..."
    gcc "$source_file" -o "$output_file"

    # Check if the compilation was successful
    if [ $? -eq 0 ]; then
        echo "Successfully compiled $source_file into $output_file"
    else
        echo "Compilation of $source_file failed"
    fi
done

# Loop through each file that needs openssl
for source_file in "${openssl_program_filenames[@]}"; do
    # Check if the file exists
    if [ ! -f "$source_file" ]; then
        echo "Error: File '$source_file' not found!"
        continue
    fi

    # Get the name of the output executable (strip the .c extension)
    output_file="${source_file%.c}"

    # Compile the C program with OpenSSL libraries
    echo "Compiling $source_file into $output_file ..."
    gcc "$source_file" -o "$output_file" -lssl -lcrypto

    # Check if the compilation was successful
    if [ $? -eq 0 ]; then
        echo "Successfully compiled $source_file into $output_file"
    else
        echo "Compilation of $source_file failed"
    fi
done
