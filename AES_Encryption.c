/*
 * DiscountTeddyBear
 * Date 2/11/2025
 * ADVANCED ENCRYPTION STANDARD (AES)
 * Documentation (Referred to as Reference Document in comments): 
 * https://csrc.nist.gov/files/pubs/fips/197/final/docs/fips-197.pdf
 * 
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>


//Cipher Key used for encryption and decryption
unsigned cypher_key[32];

/*
 * Number of columns (32-bit words) comprising the State. For this
 * standard, Nb = 4. (Also see Sec. 6.3.)
 */
int Nb = 4;

/*
 * Number of 32-bit words comprising the Cipher Key. For this
 * standard, Nk = 4, 6, or 8. (Also see Sec. 6.3.)
 */
int Nk;

/*
 * Number of rounds, which is a function of Nk and Nb (which is
 * fixed). For this standard, Nr = 10, 12, or 14. (Also see Sec. 6.3.)
 */
int Nr;

//Stores the round keys after the cypher key has been fully expanded.
unsigned round_keys[150];

//Substitution values for the byte xy (in hexadecimal format). Used by Sub_Bytes() (Figure 7 on page 16 of the Referece Document).
//Ex: If the byte equals 0x53, then the substitution value would be determined by the intersection
//of the row with index '5' and the column with index '3', resulting in the byte having the value 0xed.
unsigned s_box[256] = 
/*       |---------------------------------------------------  Y  -----------------------------------------------------|*/
/* _        0      1      2      3      4      5      6      7      8      9      a      b      c      d      e      f  */
/* | 0*/{ 0x63 , 0x7c , 0x77 , 0x7b , 0xf2 , 0x6b , 0x6f , 0xc5 , 0x30 , 0x01 , 0x67 , 0x2b , 0xfe , 0xd7 , 0xab , 0x76
/* | 1*/, 0xca , 0x82 , 0xc9 , 0x7d , 0xfa , 0x59 , 0x47 , 0xf0 , 0xad , 0xd4 , 0xa2 , 0xaf , 0x9c , 0xa4 , 0x72 , 0xc0
/* | 2*/, 0xb7 , 0xfd , 0x93 , 0x26 , 0x36 , 0x3f , 0xf7 , 0xcc , 0x34 , 0xa5 , 0xe5 , 0xf1 , 0x71 , 0xd8 , 0x31 , 0x15
/* | 3*/, 0x04 , 0xc7 , 0x23 , 0xc3 , 0x18 , 0x96 , 0x05 , 0x9a , 0x07 , 0x12 , 0x80 , 0xe2 , 0xeb , 0x27 , 0xb2 , 0x75
/* | 4*/, 0x09 , 0x83 , 0x2c , 0x1a , 0x1b , 0x6e , 0x5a , 0xa0 , 0x52 , 0x3b , 0xd6 , 0xb3 , 0x29 , 0xe3 , 0x2f , 0x84
/* | 5*/, 0x53 , 0xd1 , 0x00 , 0xed , 0x20 , 0xfc , 0xb1 , 0x5b , 0x6a , 0xcb , 0xbe , 0x39 , 0x4a , 0x4c , 0x58 , 0xcf
/* | 6*/, 0xd0 , 0xef , 0xaa , 0xfb , 0x43 , 0x4d , 0x33 , 0x85 , 0x45 , 0xf9 , 0x02 , 0x7f , 0x50 , 0x3c , 0x9f , 0xa8
/*   7*/, 0x51 , 0xa3 , 0x40 , 0x8f , 0x92 , 0x9d , 0x38 , 0xf5 , 0xbc , 0xb6 , 0xda , 0x21 , 0x10 , 0xff , 0xf3 , 0xd2
/* X 8*/, 0xcd , 0x0c , 0x13 , 0xec , 0x5f , 0x97 , 0x44 , 0x17 , 0xc4 , 0xa7 , 0x7e , 0x3d , 0x64 , 0x5d , 0x19 , 0x73
/*   9*/, 0x60 , 0x81 , 0x4f , 0xdc , 0x22 , 0x2a , 0x90 , 0x88 , 0x46 , 0xee , 0xb8 , 0x14 , 0xde , 0x5e , 0x0b , 0xdb
/* | a*/, 0xe0 , 0x32 , 0x3a , 0x0a , 0x49 , 0x06 , 0x24 , 0x5c , 0xc2 , 0xd3 , 0xac , 0x62 , 0x91 , 0x95 , 0xe4 , 0x79
/* | b*/, 0xe7 , 0xc8 , 0x37 , 0x6d , 0x8d , 0xd5 , 0x4e , 0xa9 , 0x6c , 0x56 , 0xf4 , 0xea , 0x65 , 0x7a , 0xae , 0x08
/* | c*/, 0xba , 0x78 , 0x25 , 0x2e , 0x1c , 0xa6 , 0xb4 , 0xc6 , 0xe8 , 0xdd , 0x74 , 0x1f , 0x4b , 0xbd , 0x8b , 0x8a
/* | d*/, 0x70 , 0x3e , 0xb5 , 0x66 , 0x48 , 0x03 , 0xf6 , 0x0e , 0x61 , 0x35 , 0x57 , 0xb9 , 0x86 , 0xc1 , 0x1d , 0x9e
/* | e*/, 0xe1 , 0xf8 , 0x98 , 0x11 , 0x69 , 0xd9 , 0x8e , 0x94 , 0x9b , 0x1e , 0x87 , 0xe9 , 0xce , 0x55 , 0x28 , 0xdf
/* | f*/, 0x8c , 0xa1 , 0x89 , 0x0d , 0xbf , 0xe6 , 0x42 , 0x68 , 0x41 , 0x99 , 0x2d , 0x0f , 0xb0 , 0x54 , 0xbb , 0x16};
/* -  */

//Inverse S-box: substitution values for the byte xy (in hexadecimal format). Used by InvSub_Bytes() (Figure 14 on page 22 of the Referece Document).
//Ex: If the byte equals 0xed, then the substitution value would be determined by the intersection
//of the row with index 'e' and the column with index 'd', resulting in the byte having the value 0x53.
unsigned inverse_s_box[256] = 
/*       |---------------------------------------------------  Y  -----------------------------------------------------|*/
/* _        0      1      2      3      4      5      6      7      8      9      a      b      c      d      e      f  */
/* | 0*/{ 0x52 , 0x09 , 0x6a , 0xd5 , 0x30 , 0x36 , 0xa5 , 0x38 , 0xbf , 0x40 , 0xa3 , 0x9e , 0x81 , 0xf3 , 0xd7 , 0xfb
/* | 1*/, 0x7c , 0xe3 , 0x39 , 0x82 , 0x9b , 0x2f , 0xff , 0x87 , 0x34 , 0x8e , 0x43 , 0x44 , 0xc4 , 0xde , 0xe9 , 0xcb
/* | 2*/, 0x54 , 0x7b , 0x94 , 0x32 , 0xa6 , 0xc2 , 0x23 , 0x3d , 0xee , 0x4c , 0x95 , 0x0b , 0x42 , 0xfa , 0xc3 , 0x4e
/* | 3*/, 0x08 , 0x2e , 0xa1 , 0x66 , 0x28 , 0xd9 , 0x24 , 0xb2 , 0x76 , 0x5b , 0xa2 , 0x49 , 0x6d , 0x8b , 0xd1 , 0x25
/* | 4*/, 0x72 , 0xf8 , 0xf6 , 0x64 , 0x86 , 0x68 , 0x98 , 0x16 , 0xd4 , 0xa4 , 0x5c , 0xcc , 0x5d , 0x65 , 0xb6 , 0x92
/* | 5*/, 0x6c , 0x70 , 0x48 , 0x50 , 0xfd , 0xed , 0xb9 , 0xda , 0x5e , 0x15 , 0x46 , 0x57 , 0xa7 , 0x8d , 0x9d , 0x84
/* | 6*/, 0x90 , 0xd8 , 0xab , 0x00 , 0x8c , 0xbc , 0xd3 , 0x0a , 0xf7 , 0xe4 , 0x58 , 0x05 , 0xb8 , 0xb3 , 0x45 , 0x06
/*   7*/, 0xd0 , 0x2c , 0x1e , 0x8f , 0xca , 0x3f , 0x0f , 0x02 , 0xc1 , 0xaf , 0xbd , 0x03 , 0x01 , 0x13 , 0x8a , 0x6b
/* X 8*/, 0x3a , 0x91 , 0x11 , 0x41 , 0x4f , 0x67 , 0xdc , 0xea , 0x97 , 0xf2 , 0xcf , 0xce , 0xf0 , 0xb4 , 0xe6 , 0x73
/*   9*/, 0x96 , 0xac , 0x74 , 0x22 , 0xe7 , 0xad , 0x35 , 0x85 , 0xe2 , 0xf9 , 0x37 , 0xe8 , 0x1c , 0x75 , 0xdf , 0x6e
/* | a*/, 0x47 , 0xf1 , 0x1a , 0x71 , 0x1d , 0x29 , 0xc5 , 0x89 , 0x6f , 0xb7 , 0x62 , 0x0e , 0xaa , 0x18 , 0xbe , 0x1b
/* | b*/, 0xfc , 0x56 , 0x3e , 0x4b , 0xc6 , 0xd2 , 0x79 , 0x20 , 0x9a , 0xdb , 0xc0 , 0xfe , 0x78 , 0xcd , 0x5a , 0xf4
/* | c*/, 0x1f , 0xdd , 0xa8 , 0x33 , 0x88 , 0x07 , 0xc7 , 0x31 , 0xb1 , 0x12 , 0x10 , 0x59 , 0x27 , 0x80 , 0xec , 0x5f
/* | d*/, 0x60 , 0x51 , 0x7f , 0xa9 , 0x19 , 0xb5 , 0x4a , 0x0d , 0x2d , 0xe5 , 0x7a , 0x9f , 0x93 , 0xc9 , 0x9c , 0xef
/* | e*/, 0xa0 , 0xe0 , 0x3b , 0x4d , 0xae , 0x2a , 0xf5 , 0xb0 , 0xc8 , 0xeb , 0xbb , 0x3c , 0x83 , 0x53 , 0x99 , 0x61
/* | f*/, 0x17 , 0x2b , 0x04 , 0x7e , 0xba , 0x77 , 0xd6 , 0x26 , 0xe1 , 0x69 , 0x14 , 0x63 , 0x55 , 0x21 , 0x0c , 0x7d};
/* -  */


/*================================================================================
 *
 * Functions that support other functions
 * 
 *================================================================================
 */


//Returns the bit values of a specified range within a byte of 32 bits.
unsigned get_n_bits (unsigned bits, int width, int index){
	unsigned mask = 0x00000001; 
	if(index == 0){
		unsigned int updated_mask = ((mask << (width + 1)) - 1); 
        //Ex: width = 4; updated_mask = ((00000001 << 4) - 1) -> ((00010000) - 1) -> 00001111
		return bits & updated_mask;
	}
    else if((width + index - 1) >= 31){
        unsigned int updated_mask = (~((mask << index) - 1));
        //Ex: index = 4; updated_mask = ~((00000001 << 4) - 1) -> ~((00010000) - 1)-> ~(00001111) -> 11110000
	    return bits & updated_mask;
    }
    else{
        unsigned int updated_mask = (((mask << (width + index)) - 1)) & (~((mask << index) - 1));
        //Ex: width = 4, index = 3; updated_mask = (((00000001 << (4 + 3)) - 1) -> (1000000 - 1) -> 01111111)   &   (~((00000001 << 3) - 1) -> ~((00001000) - 1)-> ~(00000111) -> 11111000) == updated_mask = 01111000
	    return bits & updated_mask;
    }
}

/* 
 * Multiplies the input byte with the multiplier byte.  
 * Returns the product of that multiplication as a byte.
 * 
 * We need to treat each of the input bytes as polynomials.
 * For two bytes {a7,a6,a5,a4,a3,a2,a1,a0} and {b7,b6,b5,b4,b3,b2,b1,b0}, 
 * the sum is {c7,c6,c5,c4,c3,c2,c1,c0}, where each ci = ai ^ bi 
 * (i.e., c7 = a7 ^ b7, c6 = a6 ^ b6, ...c0 = a0 ^ b0).
 * 
 * Ex: If byte 1 = 0x57, or 01010111 in binary, then it would equal: 
 * {0a7,1a6,0a5,1a4,0a3,1a2,1a1,1a0}, which would equal: 
 * {a6,a4,a2,a1,a0}. 
 * 
 * Using this concept, we can determine that {57} • {83} = {c1}, because:
 * 
 * (a6 + a4 + a2 + a + 1) * (a7 + a + 1) (The 1 at the end is the equivalent of a0).
 * = a13 + a11 + a9 + a8 + a7 + a7 + a5 + a3 + a2 + a + a6 + a4 + a2 + a + 1
 * 
 * Remember that when adding, you are actually using XOR,
 * so a7 + a7 is actually a7 ^ a7, which makes it 0a7, removing it from the equation.
 * Therefor we get:
 * 
 * = a13 + a11 + a9 + a8 + a6 + a5 + a4 + a3 + 1
 * 
 * We are not done yet. Now we need to find the modulo of the polynomial we just calculated
 * and an irreducible polynomial of degree 8.  
 * A polynomial is irreducible if its only divisors are one and itself. 
 * For the AES algorithm, this irreducible polynomial is:
 * m(a) = a8 + a4 + a3 + a + 1 .
 * When we modulo our polynomial with the irreducible polynomial, we get: 
 * 
 * (a13 + a11 + a9 + a8 + a6 + a5 + a4 + a3 + 1) % (a8 + a4 + a3 + a + 1)
 * = a7 + a6 + 1
 * 
 * The final step is to convert this polynomial back into a byte we can use:
 * 
 * a7 + a6 + 1 = 11000001 
 * Which equals: 0xc1.
 * 
 * Pages 10-11 of Reference Document.
 */
unsigned Multiply_Byte(unsigned byte, unsigned multiplier){
    unsigned mask = 0x01;

    unsigned byte_bits[8]; //Stores each bit of the byte variable
    unsigned multiplier_bits[8]; //Stores each bit of the multiplier variable
    for(int i = 0; i < 8; i++){
        byte_bits[i] = (byte >> i) & mask;
        multiplier_bits[i] = (multiplier >> i) & mask;
    }
    unsigned counter[14]; //Keeps track of which bits are 1 and 0 through all of the operations. 
    for(int i = 0; i < 14; i++){
        counter[i] = 0x00;
    }
    //Multiplies the byte value with the multiplier value and stores the result in the counter variable
    for(int i = 0; i < 8; i++){
        for(int j = 0; j < 8; j++){
            if(byte_bits[i] == 0x01 && multiplier_bits[j] == 0x01){
                counter[i + j] = counter[i + j] ^ 0x01;
            }
        }
    }
    /*
     * A polynomial is irreducible if its only divisors are one and itself. 
     * For the AES algorithm, this irreducible polynomial is:
     * m(a) = a8 + a4 + a3 + a + 1 .
     * Page 10 of Reference Document.
     */
    int irreducible[9] = {1, 0, 0, 0, 1, 1, 0, 1, 1};

    //Finds the modulo of the polynomial in the counter array and the irreducible polynomial. 
    for(int i = 14; i > 7; i--){
        if(counter[i] == 0x01){
            for(int j = 0; j < 9; j++){
                if(irreducible[j] == 1){
                    counter[i - j] = counter[i - j] ^ 0x01;
                }
            }
        }
    }

    unsigned result = 0x00;
    //Converts the polynomial in the counter array back into a byte we can use.
    for(int i = 0; i < 8; i++){
        result = result | (counter[i] << i);
    }
    return result;
}

/*================================================================================
 *
 * Functions to encrypt the text
 * 
 *================================================================================
 */

/*
 * Transformation in the Cipher that takes all of the columns of the
 * State and mixes their data (independently of one another) to
 * produce new columns.
 * Pages 17-18 of Reference Document.
 */
void Mix_Columns(unsigned *state){
    unsigned mask = 0Xff;

    for(int i = 0; i < 4; i++){
        unsigned byte1 = (get_n_bits(state[0], 8, (i * 8)) >> (i * 8)) & mask;
        unsigned byte2 = (get_n_bits(state[1], 8, (i * 8)) >> (i * 8)) & mask;
        unsigned byte3 = (get_n_bits(state[2], 8, (i * 8)) >> (i * 8)) & mask;
        unsigned byte4 = (get_n_bits(state[3], 8, (i * 8)) >> (i * 8)) & mask;

        unsigned new_byte1 = Multiply_Byte(byte1, 0x02) ^ Multiply_Byte(byte2, 0x03) ^ byte3                      ^ byte4                      ;
        unsigned new_byte2 = byte1                      ^ Multiply_Byte(byte2, 0x02) ^ Multiply_Byte(byte3, 0x03) ^ byte4                      ;
        unsigned new_byte3 = byte1                      ^ byte2                      ^ Multiply_Byte(byte3, 0x02) ^ Multiply_Byte(byte4, 0x03) ;
        unsigned new_byte4 = Multiply_Byte(byte1, 0x03) ^ byte2                      ^ byte3                      ^ Multiply_Byte(byte4, 0x02) ;

        state[0] = state[0] & ~(mask << (i * 8));     //Clears the bits from the byte
        state[0] = state[0] | (new_byte1 << (i * 8)); //Inputes the new bits into the byte

        state[1] = state[1] & ~(mask << (i * 8));
        state[1] = state[1] | (new_byte2 << (i * 8));

        state[2] = state[2] & ~(mask << (i * 8));
        state[2] = state[2] | (new_byte3 << (i * 8));

        state[3] = state[3] & ~(mask << (i * 8));
        state[3] = state[3] | (new_byte4 << (i * 8));
    }
}

/*
 * Transformation in the Cipher that processes the State by cyclically
 * shifting the last three rows of the State by different offsets.
 * Ex: 
 * state[1] = s0,0 s0,1 s0,2 s0,3 -> s0,0 s0,1 s0,2 s0,3
 * state[2] = s1,0 s1,1 s1,2 s1,3 -> s1,1 s1,2 s1,3 s1,0
 * state[3] = s2,0 s2,1 s2,2 s2,3 -> s2,2 s2,3 s2,0 s2,1
 * state[4] = s3,0 s3,1 s3,2 s3,3 -> s3,3 s3,0 s3,1 s3,2
 * Page 17 of Reference Document.
 */
void Shift_Rows(unsigned *state){
    for(int i = 1; i < 4; i++){
        unsigned int left_bits = get_n_bits(state[i], (i * 8), (32 - (i * 8)));
        unsigned int right_bits = get_n_bits(state[i], (32 - (i * 8)), 0);
        state[i] = (right_bits << (i * 8)) | (left_bits >> (32 - (i * 8)));
    }
}

/*
 * Transformation in the Cipher that processes the State using a non
 * linear byte substitution table (S-box) that operates on each of the
 * State bytes independently. Stored in the s_box variable.
 * Ex: 0x19a09ae9 becomes 0xd4e0b81e.
 * Pages 15-16 of Reference Document.
 */
void Sub_Bytes(unsigned *state){
    unsigned mask = 0Xff;

    for(int i = 0; i < 4; i++){
    unsigned byte1 = get_n_bits(state[i], 8, 0) & mask;
    byte1 = s_box[byte1];

    unsigned byte2 = (get_n_bits(state[i], 8, 8) >> 8) & mask;
    byte2 = s_box[byte2];

    unsigned byte3 = (get_n_bits(state[i], 8, 16) >> 16) & mask;
    byte3 = s_box[byte3];

    unsigned byte4 = (get_n_bits(state[i], 8, 24) >> 24) & mask;
    byte4 = s_box[byte4];

    state[i] = byte1 |
                (byte2 << 8) |
                (byte3 << 16) |
                (byte4 << 24); 
    }
}

/*
 * Function used in the Key Expansion routine that takes a four-byte
 * word and performs a cyclic permutation.
 * Ex:
 * bytes = s0 s1 s2 s3 -> s1 s2 s3 s0
 * Page 19 of Reference Document.
 */
unsigned Rot_Word(unsigned bytes){
    unsigned int left_bits = get_n_bits(bytes, 8, 24);
    unsigned int right_bits = get_n_bits(bytes, 24, 0);
    unsigned int result = (right_bits << 8) | (left_bits >> 24);
    return result;
}

/*
 * Function used in the Key Expansion routine that takes a four-byte
 * input word and applies an S-box to each of the four bytes to
 * produce an output word.
 * Page 19 of Reference Document.
 */
unsigned Sub_Word(unsigned bytes){
    unsigned mask = 0Xff;

    unsigned byte1 = get_n_bits(bytes, 8, 0) & mask;
    byte1 = s_box[byte1];

    unsigned byte2 = (get_n_bits(bytes, 8, 8) >> 8) & mask;
    byte2 = s_box[byte2];

    unsigned byte3 = (get_n_bits(bytes, 8, 16) >> 16) & mask;
    byte3 = s_box[byte3];

    unsigned byte4 = (get_n_bits(bytes, 8, 24) >> 24) & mask;
    byte4 = s_box[byte4];

    unsigned result = byte1 |
                (byte2 << 8) |
                (byte3 << 16) |
                (byte4 << 24);

    return result;
}

/* 
 * The AES algorithm takes the Cipher Key, K, and performs a Key Expansion routine to generate a
 * key schedule. The Key Expansion generates a total of Nb (Nr + 1) words: the algorithm requires
 * an initial set of Nb words, and each of the Nr rounds requires Nb words of key data. The
 * resulting key schedule consists of a linear array of 4-byte words with i in the range
 * 0 <= i < Nb(Nr + 1).
 * Page 20 of Reference Document. Based off pseudo code from Figure 11.
 */
void Key_Expansion(unsigned *round_key, unsigned *round_constant){
    for(int i = Nk; i < Nk + Nk; i++){
        unsigned previous_key = round_key[i % Nk];
        unsigned current_key = round_key[(i - 1) % Nk];

        if (i % Nk == 0){
            current_key = Sub_Word(Rot_Word(current_key)) ^ (*round_constant << 24);
        }
        
        else if (Nk > 6 && i % Nk == 4){
            current_key = Sub_Word(current_key);
        }
        
        round_key[i % Nk] = current_key ^ previous_key;
    }

    *round_constant = Multiply_Byte(*round_constant, 0x02);
}

/*
 * Transformation in the Cipher and Inverse Cipher in which a Round
 * Key is added to the State using an XOR operation. The length of a
 * Round Key equals the size of the State (i.e., for Nb = 4, the Round
 * Key length equals 128 bits/16 bytes).
 * Pages 18-19 of Reference Document.
 */
void Add_Round_Key(unsigned *state, unsigned *round_key, unsigned *round_constant){
    unsigned mask = 0Xff;
    
    for(int i = 0; i < 4; i++){
        //Gathers collumn of values from the state
        unsigned byte1 = get_n_bits(state[i], 8, 0) & mask;
        unsigned byte2 = (get_n_bits(state[i], 8, 8) >> 8) & mask;
        unsigned byte3 = (get_n_bits(state[i], 8, 16) >> 16) & mask;
        unsigned byte4 = (get_n_bits(state[i], 8, 24) >> 24) & mask;

        //Gathers row of values from the round key
        unsigned round_byte1 = (get_n_bits(round_key[3], 8, (24 - (i * 8))) >> (24 - (i * 8))) & mask;
        unsigned round_byte2 = (get_n_bits(round_key[2], 8, (24 - (i * 8))) >> (24 - (i * 8))) & mask;
        unsigned round_byte3 = (get_n_bits(round_key[1], 8, (24 - (i * 8))) >> (24 - (i * 8))) & mask;
        unsigned round_byte4 = (get_n_bits(round_key[0], 8, (24 - (i * 8))) >> (24 - (i * 8))) & mask;

        //Performs the XOR operation between the state and the round key
        unsigned new_byte1 = byte1 ^ round_byte1;
        unsigned new_byte2 = byte2 ^ round_byte2;
        unsigned new_byte3 = byte3 ^ round_byte3;
        unsigned new_byte4 = byte4 ^ round_byte4;

        state[i] = state[i] & 0x00; //Clears the bits from the state
        
        //Inputs new bytes into the state
        state[i] = new_byte1 |
                    (new_byte2 << 8) |
                    (new_byte3 << 16) |
                    (new_byte4 << 24);
    }

    Key_Expansion(round_key, round_constant);

}

/*
 * Encrypts the plaintext. The plaintext must be stored as a 128 bit hexadecimal integer.
 * Will send the end result of the encryption to the result parameter.
 * Page 15 of Reference Document. Based off pseudo code from Figure 5.
 */
void Cipher(unsigned *state, unsigned *result){
    unsigned round_constant = 0x01; //Utilized for key expansion
    unsigned round_key[Nk]; //Stores the current round key generated by the cypher key being expanded by the round key expansion function
    for(int i = 0; i < Nk; i++){
        round_key[i] = cypher_key[i];
    }

    Add_Round_Key(state, round_key, &round_constant); // See Sec. 5.1.4 of Reference Document.

    for(int i = 1; i < Nr; i++){
        Sub_Bytes(state);  // See Sec. 5.1.1 of Reference Document.
        Shift_Rows(state);  // See Sec. 5.1.2 of Reference Document.
        Mix_Columns(state); // See Sec. 5.1.3 of Reference Document.
        Add_Round_Key(state, round_key, &round_constant);
    }

    Sub_Bytes(state);
    Shift_Rows(state);
    Add_Round_Key(state, round_key, &round_constant);

    for(int i = 0; i < 4; i++){
        result[i] = state[i];
    }
}


/*================================================================================
 *
 * Functions to decrypt the encrypted text
 * 
 *================================================================================
 */


/*
 * Transformation in the Inverse Cipher that is the inverse of
 * Shift_Rows().
 * Ex: 
 * state[1] = s0,0 s0,1 s0,2 s0,3 -> s0,0 s0,1 s0,2 s0,3
 * state[2] = s1,0 s1,1 s1,2 s1,3 -> s1,3 s1,0 s1,1 s1,2
 * state[3] = s2,0 s2,1 s2,2 s2,3 -> s2,2 s2,3 s2,0 s2,1
 * state[4] = s3,0 s3,1 s3,2 s3,3 -> s3,1 s3,2 s3,3 s3,0
 * Pages 21-22 of Reference Document.
 */
void Inv_Shift_Rows(unsigned *state){
    for(int i = 1; i < 4; i++){
        unsigned int left_bits = get_n_bits(state[i], (32 - (i * 8)), (i * 8));
        unsigned int right_bits = get_n_bits(state[i], (i * 8), 0);
        state[i] = (right_bits << (32 - (i * 8))) | (left_bits >> (i * 8));
    }
}

/*
 * Transformation in the Inverse Cipher that is the inverse of
 * Sub_Bytes(). Inverse of S-Box is stored as inverse_s_box.
 * Ex: 0x19a09ae9 becomes 0x8e4737eb.
 * Page 22 of Reference Document.
 */
void Inv_Sub_Bytes(unsigned *state){
    unsigned mask = 0Xff;

    for(int i = 0; i < 4; i++){
    unsigned byte1 = get_n_bits(state[i], 8, 0) & mask;
    byte1 = inverse_s_box[byte1];

    unsigned byte2 = (get_n_bits(state[i], 8, 8) >> 8) & mask;
    byte2 = inverse_s_box[byte2];

    unsigned byte3 = (get_n_bits(state[i], 8, 16) >> 16) & mask;
    byte3 = inverse_s_box[byte3];

    unsigned byte4 = (get_n_bits(state[i], 8, 24) >> 24) & mask;
    byte4 = inverse_s_box[byte4];

    state[i] = byte1 |
                (byte2 << 8) |
                (byte3 << 16) |
                (byte4 << 24); 
    }
}

/*
 * Transformation in the Inverse Cipher that is the inverse of
 * Mix_Columns().
 * Page 23 of Reference Document.
 */
void Inv_Mix_Columns(unsigned *state){
    unsigned mask = 0Xff;

    for(int i = 0; i < 4; i++){
        unsigned byte1 = (get_n_bits(state[0], 8, (i * 8)) >> (i * 8)) & mask;
        unsigned byte2 = (get_n_bits(state[1], 8, (i * 8)) >> (i * 8)) & mask;
        unsigned byte3 = (get_n_bits(state[2], 8, (i * 8)) >> (i * 8)) & mask;
        unsigned byte4 = (get_n_bits(state[3], 8, (i * 8)) >> (i * 8)) & mask;

        unsigned new_byte1 = Multiply_Byte(byte1, 0x0e) ^ Multiply_Byte(byte2, 0x0b) ^ Multiply_Byte(byte3, 0x0d) ^ Multiply_Byte(byte4, 0x09) ;
        unsigned new_byte2 = Multiply_Byte(byte1, 0x09) ^ Multiply_Byte(byte2, 0x0e) ^ Multiply_Byte(byte3, 0x0b) ^ Multiply_Byte(byte4, 0x0d) ;
        unsigned new_byte3 = Multiply_Byte(byte1, 0x0d) ^ Multiply_Byte(byte2, 0x09) ^ Multiply_Byte(byte3, 0x0e) ^ Multiply_Byte(byte4, 0x0b) ;
        unsigned new_byte4 = Multiply_Byte(byte1, 0x0b) ^ Multiply_Byte(byte2, 0x0d) ^ Multiply_Byte(byte3, 0x09) ^ Multiply_Byte(byte4, 0x0e) ;

        state[0] = state[0] & ~(mask << (i * 8));     //Clears the bits from the byte
        state[0] = state[0] | (new_byte1 << (i * 8)); //Inputes the new bits into the byte

        state[1] = state[1] & ~(mask << (i * 8));
        state[1] = state[1] | (new_byte2 << (i * 8));

        state[2] = state[2] & ~(mask << (i * 8));
        state[2] = state[2] | (new_byte3 << (i * 8));

        state[3] = state[3] & ~(mask << (i * 8));
        state[3] = state[3] | (new_byte4 << (i * 8));
    }
}

/*
 * Transformation in the Cipher and Inverse Cipher in which a Round
 * Key is added to the State using an XOR operation. The length of a
 * Round Key equals the size of the State (i.e., for Nb = 4, the Round
 * Key length equals 128 bits/16 bytes).
 * Pages 18-19 of Reference Document.
 */
void Inv_Add_Round_Key(unsigned *state, int round_number){
    unsigned mask = 0Xff;

    for(int i = 0; i < 4; i++){
        //Gathers collumn of values from the state
        unsigned byte1 = get_n_bits(state[i], 8, 0) & mask;
        unsigned byte2 = (get_n_bits(state[i], 8, 8) >> 8) & mask;
        unsigned byte3 = (get_n_bits(state[i], 8, 16) >> 16) & mask;
        unsigned byte4 = (get_n_bits(state[i], 8, 24) >> 24) & mask;

        //Gathers row of values from the round key
        unsigned round_byte1 = (get_n_bits(round_keys[round_number + 3], 8, (24 - (i * 8))) >> (24 - (i * 8))) & mask;
        unsigned round_byte2 = (get_n_bits(round_keys[round_number + 2], 8, (24 - (i * 8))) >> (24 - (i * 8))) & mask;
        unsigned round_byte3 = (get_n_bits(round_keys[round_number + 1], 8, (24 - (i * 8))) >> (24 - (i * 8))) & mask;
        unsigned round_byte4 = (get_n_bits(round_keys[round_number + 0], 8, (24 - (i * 8))) >> (24 - (i * 8))) & mask;

        //Performs the XOR operation between the state and the round key
        unsigned new_byte1 = byte1 ^ round_byte1;
        unsigned new_byte2 = byte2 ^ round_byte2;
        unsigned new_byte3 = byte3 ^ round_byte3;
        unsigned new_byte4 = byte4 ^ round_byte4;

        state[i] = state[i] & 0x00; //Clears the bits from the state
        
        //Inputs new bytes into the state
        state[i] = new_byte1 |
                    (new_byte2 << 8) |
                    (new_byte3 << 16) |
                    (new_byte4 << 24);
    }
}
 
/*
 * Decrypts the encrypted plaintext. The encrypted plaintext must be stored as a 128 bit hexadecimal integer.
 * Will send the end result of the decryption to the result parameter.
 * Page 21 of Reference Document. Based off pseudo code from Figure 12.
 */
void Inv_Cipher(unsigned *state, unsigned *result){
   
    Inv_Add_Round_Key(state, Nk * Nr); // See Sec. 5.1.4 of Reference Document.
    Inv_Shift_Rows(state);  // See Sec. 5.3.1 of Reference Document.
    Inv_Sub_Bytes(state);  // See Sec. 5.3.2 of Reference Document.

    for(int i = (Nr - 1); i > 0; i--){
        Inv_Add_Round_Key(state, i * Nk);
        Inv_Mix_Columns(state); // See Sec. 5.3.3 of Reference Document.
        Inv_Shift_Rows(state); 
        Inv_Sub_Bytes(state); 
    }

    Inv_Add_Round_Key(state, 0);
    
    for(int i = 0; i < 4; i++){
        result[i] = state[i];
    }
}

/* 
 * The AES algorithm takes the Cipher Key, K, and performs a Key Expansion routine to generate a
 * key schedule. The Key Expansion generates a total of Nb (Nr + 1) words: the algorithm requires
 * an initial set of Nb words, and each of the Nr rounds requires Nb words of key data. The
 * resulting key schedule consists of a linear array of 4-byte words with i in the range
 * 0 <= i < Nb(Nr + 1).
 * The purpose of this function is to store the round key generated and the round constants
 * used for use during decryption.
 * Page 20 of Reference Document. Based off pseudo code from Figure 11.
 */
void Full_Key_Expansion(){
    unsigned round_constant = 0x01; //Utilized for key expansion
    unsigned round_key[Nk]; //Stores the current round key generated by the cypher key being expanded by the round key expansion function
    for(int i = 0; i < Nk; i++){
        round_key[i] = cypher_key[i];
        round_keys[i] = cypher_key[i];
    }

    for(int i = Nk; i < Nk * (Nr + 1); i++){
        unsigned previous_key = round_key[i % Nk];
        unsigned current_key = round_key[(i - 1) % Nk];

        if (i != Nk && i % Nk == 0){
            round_constant = Multiply_Byte(round_constant, 0x02);
        }
        if (i % Nk == 0){
            current_key = Sub_Word(Rot_Word(current_key)) ^ (round_constant << 24);
        }
        
        else if (Nk > 6 && i % Nk == 4){
            current_key = Sub_Word(current_key);
        }
        
        round_key[i % Nk] = current_key ^ previous_key;

        round_keys[i] = current_key ^ previous_key;
    }
   
}

/*================================================================================
 *
 * Functions to read a file and write to a file
 * 
 *================================================================================
 */

/*
 * Converts hex values stored as Strings into hex values.
 * Stores result in the result variable.
 */
void Convert_String_Hex_To_Hex(char hex_string[], unsigned *hex_code){
    unsigned bits;
    char line[8];
    for(int i = 0; i < 4; i++){
        strncpy(line, &hex_string[i * 8], 8);
        sscanf(line, "%x", &bits);
        hex_code[i] = bits;
    }
}

/*
 * Converts ascii variable into hex.
 * Stores result in the result variable.
 */
void Convert_ascii_To_Hex(char words[], unsigned *hex_words){
    char line[4];

    for(int i = 0; i < 4; i++){
        strncpy(line, &words[i * 4], 4);
        for(int j = 0; j < 4; j++){
            hex_words[i] = hex_words[i] | line[j] << (24 - (j * 8));
        }

    }
}

/*
 * Converts hex variable into a String.
 * Stores result in the result variable.
 */
void Convert_Hex_To_String(unsigned *hex_words, char *str_words){
    int count = 0;
    for(int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++){
            str_words[count] = (char)((hex_words[i] >> (24 - (j * 8))) & 0xff);
            count++;
        }
    }
    str_words[17] = '\0';
}


/*
 * Encrypts the plain text of the specified file.
 * Stores the result in a new file with the designated filename.
 */
void Encrypt_File(char source_filename[], char destination_filename[]){
    FILE *file_read;
    FILE *file_write;

    // Character buffer that stores the read character till the next iteration
    char ch;

    // Opening file in reading mode
    file_read = fopen(source_filename, "r");
    // Create file to store encrypted text
    file_write = fopen(destination_filename, "w");

    if (NULL == file_read) {
        printf("\n!ERROR! %s can't be opened or it does not exist!\nEnding program...\n", source_filename);
        exit(1);
    }

    int count = 0; // Keeps track of the number of iterations of the while loop
    char words[16]; // Temporarily stores the characters in the file
    unsigned hex_words[4]; // Temporarily stores the result of converting the string of text to hex
    unsigned result[4]; // emporarily stores the result of encrypting the string of text
    char str_words[17]; // Temporarily stores the result of converting the hex to a string of text

    // Printing what is written in file character by character using loop.
    while ((ch = fgetc(file_read)) != 0xff) {
        // Once the words in the file have been gathered, the words are encrypted
        if(count == 16 || ch == EOF){
            for(int i = 0; i < 4; i++){
                hex_words[i] = hex_words[i] & 0x00000000;
                result[i] = result[i] & 0x00000000;
            }
            
            Convert_ascii_To_Hex(words, hex_words);
            
            Cipher(hex_words, result);


            for(int i = 0; i < 4; i++){
                fprintf(file_write, "%08x", result[i]);
            }
            for(int i = 0; i < 16; i++){
                words[i] = '\0';
            }
            count = 0;
        }

        words[count] = ch;
        count++;
        if(ch == EOF){
            break;
        }
    }

    // Closing the filez
    fclose(file_read);
    fclose(file_write);
}

/*
 * Decrypts the encrypted text of the specified file.
 * Stores the result in a new file with the designated filename.
 */
void Decrypt_File(char source_filename[], char destination_filename[]){
    FILE *file_read;
    FILE *file_write;

    // Character buffer that stores the read character till the next iteration
    char ch;

    // Opening file in reading mode
    file_read = fopen(source_filename, "r");
    // Create file to store encrypted text
    file_write = fopen(destination_filename, "w");

    if (file_read == NULL) {
        printf("ERROR! File can't be opened! \n");
        exit;
    }

    int count = 0; // Keeps track of the number of iterations of the while loop
    char words[32]; // Temporarily stores the characters in the file
    unsigned hex_words[4]; // Temporarily stores the result of converting the string of text to hex
    unsigned result[4]; // emporarily stores the result of encrypting the string of text
    char str_words[17]; // Temporarily stores the result of converting the hex to a string of text

    // Printing what is written in file character by character using loop.
    while ((ch = fgetc(file_read)) != 0xff) {
        // Once the words in the file have been gathered, the words are encrypted
        if(count == 32 || ch == EOF){
            for(int i = 0; i < 4; i++){
                hex_words[i] = hex_words[i] & 0x00000000;
                result[i] = result[i] & 0x00000000;
            }
            for(int i = 0; i < 17; i++){
                str_words[i] = '\0';
            }
            
            Convert_String_Hex_To_Hex(words, hex_words);
            
            Inv_Cipher(hex_words, result);

            Convert_Hex_To_String(result, str_words);


            fprintf(file_write, "%s", str_words);

            count = 0;
            //Resets word array so no stray letters carry over
            for(int i = 0; i < 32; i++){
                words[i] = '\0';
            }
        }

        words[count] = ch;

        count++;
        if(ch == EOF){
            break;
        }
    }

    // Closing the filez
    fclose(file_read);
    fclose(file_write);
}


/*================================================================================
 *
 * Functions to store the cypher key used in the cypher key variable
 * 
 *================================================================================
 */


//Extracts the Cypher Key from the inputted string
void Get_Cipher_Key(char *cipher){
    unsigned bits;
    char line[8];
    for(int i = 0; i < (strlen(cipher) / 8); i++){
        strncpy(line, &cipher[i * 8], 8);
        sscanf(line, "%x", &bits);
        cypher_key[i] = bits;
    }
}


//Generates a random 256 bit cypher key to be used during encryption
void Generate_New_Cypher_Key(){
    char string_hex[9]; 
    unsigned hex;
    srand(time(NULL));

    for(int i = 0; i < 8; i++){
        int random = rand() % 4294967296; //The largest hex value is 0xffffffff, which is 4294967295

        sprintf(string_hex, "%08x", random);
        sscanf(string_hex, "%08x", &hex);

        cypher_key[i] = hex;
    }
    printf("================================================================\n");
    printf("!IMPORTANT! The following Cypher Key was used:\n\n");
    for(int i = 0; i < 8; i++){
        printf("%08x", cypher_key[i]);
    }
    printf("\n\nThis Cypher Key is needed to decrypt the file.\n");
    printf("Make sure to save it in a secure location.\n");
    printf("================================================================\n");
}
    

/*================================================================================
 *
 * Main Function
 * 
 *================================================================================
 */
int main(int argc, char *argv[]){
    //Stores the help message to reduce the amount of copy and pasting
    char *help_message = "\nUsage: ./AES_Encryption [encrypt/decrypt] [cypher_key](Optional if encrypting)"
                        " [source_filename.txt] [destination_filename.txt]\nExample:"
                        "\n./AESencryption decrypt 000102030405060708090a0b0c0d0e0f my_file.txt result.txt\n";

	//Check for correct number of argument
	if (argc < 4 ||argc > 5) {
        printf("%s", help_message);
        return 1;
    }

    char encrypt_or_decrypt[100]; //Stores whether the user wants to encrypt or decrypt the file
    strcpy(encrypt_or_decrypt, argv[1]);

    char source_filename[100]; //Stores the filename the user wants to encrypt or decrypt
    char destination_filename[100]; //Stores the filename the user wants to send the results of the encryption or decryption to

    //If no cypher_key is inputted during encryption, a 256 bit cypher_key will be created
    if(argc == 4 && strcmp(encrypt_or_decrypt, "encrypt") == 0){
        Nk = 8;
        Nr = 14;

        strcpy(source_filename, argv[2]);
        strcpy(destination_filename, argv[3]);

        Generate_New_Cypher_Key();
    }
    //cypher_key is needed for decryption
    else if(argc == 4 && strcmp(encrypt_or_decrypt, "decrypt") == 0){
        printf("Must provide a cypher_key when decrypting.%s", help_message);
        return 1;
    }
    //If cypher_key is provided, then it will be stored in the cypher_key variable
    else if(argc == 5){
        char cipher[100];
	    strcpy(cipher, argv[2]);

        if(strlen(cipher) / 8 != 4 && strlen(cipher) / 8 != 6 && strlen(cipher) / 8 != 8){
            printf("cypher_key must be a 128 bit, 192 bit, or 256 bit hexadecimal integer.%s", help_message);
            return 1;
        }

        Nk = strlen(cipher) / 8;
        Nr = Nk + Nb + 2;

        Get_Cipher_Key(cipher);

        strcpy(source_filename, argv[3]);
        strcpy(destination_filename, argv[4]);
    }
    else{
        printf("Must use \"encrypt\" or \"decrypt\" keyword as first argument. Remove quotation marks.%s", help_message);
        return 1;
    }


    //Encrypts or decrypts the source file
    if(strcmp(encrypt_or_decrypt, "encrypt") == 0){
        
        Encrypt_File(source_filename, destination_filename);

    }
    else if(strcmp(encrypt_or_decrypt, "decrypt") == 0){

        Full_Key_Expansion();
        
        Decrypt_File(source_filename, destination_filename);
    }

	return 0;
}