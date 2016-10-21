// Austin Shipley
// DES brute force decryption

/*
This program generates every key value from 0 to 2^64 and tries to decrypt the
given ciphertext and match it with the known plaintext.
It makes extensive use of the uint64_t data type which stores unsigned 64 bit
integers. I use these to store the 64 bit key and the 64 bit sized block of
text. Also used is the data type uint32_t.
This program has the ability to divide the workload and be run on several
different computers to speed up the search time tremendously.
This program is designed with speed in mind, as we have to try an enourmous
number of combinations.
*/

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>

// All of the necessary matrices and tables for DES.
int IP[64];
int IPinv[64];
int E[64];
int P[64];
int sBoxes[8][64];
int PC1[64];
int PC2[64];
int keyShifts[16];

void getTables();
uint64_t decrypt(uint64_t, uint64_t);
uint64_t feistel(uint32_t , uint64_t);
uint64_t* keySchedule(uint64_t);
uint64_t permute(uint64_t , int*);

// Generates sequential keys and tries to decrypt the cipher text and match it
// with the known plaintext.
int main()
{
    // The program will try all keys between these these two (and including them).
    // The function getKeyRange reassigns them based on how many other computers
    // you plan to have running this program.
    uint64_t startKey = 0b0;
    uint64_t endKey = 0b1111111111111111111111111111111111111111111111111111111111111111;
    int numComputers, yourNum;

    printf("How many computers will be running this program?\n");
    scanf("%d", &numComputers);
    printf("What number are you? 0 through numComputers-1\n");
    scanf("%d", &yourNum);

    endKey = endKey / numComputers;
    startKey = endKey * yourNum;
    endKey = startKey + endKey;

    uint64_t knownPlainText = 0b1100000111101100001000101101101101001110101111100000;
    uint64_t matchingCipherText = 0b000000110011101110100010100000101000111100110001001110000100;
    uint64_t decryptedCipherText;
    uint64_t key;


    // Start guessing keys and decrypting.
    for(key = startKey; key <= endKey; key += 0b1 )
    {
        decryptedCipherText = decrypt(matchingCipherText, key);

        // Break if we have succeeded.
        if(decryptedCipherText == knownPlainText)
            break;
    }

    printf("The key I found was %llu\n"
            "The should-be plaintext is %llu\n"
            "The actual plaintext is %llu",
            (unsigned long long)key,
            (unsigned long long)decryptedCipherText,
            (unsigned long long)knownPlainText);
}

uint64_t decrypt(uint64_t text, uint64_t key)
{
    // An array for the precomputed round keys.
    uint64_t* roundKey = keySchedule(key);
    // Used for switching halves. right and left are bitmasks.
    uint32_t rightHalf;
    uint64_t right = 0b0000000000000000000000000000000011111111111111111111111111111111;
    uint32_t leftHalf;
    uint64_t left = 0b1111111111111111111111111111111100000000000000000000000000000000;
    uint32_t temp;
    // The round we are currently on
    int round;

    // Apply the Initial Permutation matrix.
    text = permute(text, IPinv);

    // Do the feistel rounds in reverse order.
    for(round = 16; round > 0; round--)
    {
        leftHalf = (uint32_t) text & left;
        rightHalf = (uint32_t) text & right;
        temp = rightHalf;

        // XOR the left half with the output of the Feistel function.
        // Go ahead and switch the halves by assiging this to the rightHalf
        // and assigning temp to leftHalf.
        rightHalf = leftHalf ^ feistel(rightHalf, roundKey[round]);
        leftHalf = temp;
    }

    // Put text back together with the halves.
    text = rightHalf;
    text = text << 32;
    text = text | leftHalf;

    // Apply the inverse of the Initial Permatation matrix.
    return permute(text, IPinv);
}

// The Feistel function. Expands the 32 bit half to 48 bits, XOR the result with
// the 48 bit round key, send the result throught the appropriate S-Box.
uint64_t feistel(uint32_t half, uint64_t roundKey)
{

}

// Generates an array of all the 48 bit roundKeys from the given key.
uint64_t* keySchedule(uint64_t key)
{

}

// Applies the passed permutation array to the text.
uint64_t permute(uint64_t text, int* perm)
{

}
/*
// Read all of the hard coded tables in DES. This is here so it's not so
// cluttered up top.
void getTables()
{
    // All of the necessary matrices and tables for DES.
    IP = {58, 50, 42, 34, 26, 18, 10, 2,
		  60, 52, 44, 36, 28, 20, 12, 4,
		  62, 54, 46, 38, 30, 22, 14, 6,
		  64, 56, 48, 40, 32, 24, 16, 8,
		  57, 49, 41, 33, 25, 17,  9, 1,
		  59, 51, 43, 35, 27, 19, 11, 3,
		  61, 53, 45, 37, 29, 21, 13, 5,
		  63, 55, 47, 39, 31, 23, 15, 7};

    IPinv ={ 4, 11,  2, 14, 15,  0,  8, 13,
             3, 12,  9,  7,  5, 10,  6,  1,
            13,  0, 11,  7,  4,  9,  1, 10,
            14,  3,  5, 12,  2, 15,  8,  6,
             1,  4, 11, 13, 12,  3,  7, 14,
            10, 15,  6,  8,  0,  5,  9,  2,
             6, 11, 13,  8,  1,  4, 10,  7,
             9,  5,  0, 15, 14,  2,  3, 12};

    E ={32,  1,  2,  3,  4,  5,
 	     4,  5,  6,  7,  8,  9,
	     8,  9, 10, 11, 12, 13,
	    12, 13, 14, 15, 16, 17,
	    16, 17, 18, 19, 20, 21,
	    20, 21, 22, 23, 24, 25,
	    24, 25, 26, 27, 28, 29,
	    28, 29, 30, 31, 32,  1};

    P =  {16,  7, 20, 21,
		  29, 12, 28, 17,
		   1, 15, 23, 26,
		   5, 18, 31, 10,
		   2,  8, 24, 14,
		  32, 27,  3,  9,
		  19, 13, 30,  6,
		  22, 11,  4, 25};

    PC1 ={57, 49,  41, 33,  25,  17,  9,
		   1, 58,  50, 42,  34,  26, 18,
		  10,  2,  59, 51,  43,  35, 27,
		  19, 11,   3, 60,  52,  44, 36,
		  63, 55,  47, 39,  31,  23, 15,
		   7, 62,  54, 46,  38,  30, 22,
		  14,  6,  61, 53,  45,  37, 29,
		  21, 13,   5, 28,  20,  12,  4};

    PC2 ={14, 17, 11, 24,  1,  5,
		   3, 28, 15,  6, 21, 10,
		  23, 19, 12,  4, 26,  8,
	      16,  7, 27, 20, 13,  2,
		  41, 52, 31, 37, 47, 55,
		  30, 40, 51, 45, 33, 48,
		  44, 49, 39, 56, 34, 53,
		  46, 42, 50, 36, 29, 32};

    keyShifts = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

    sBoxes[1] = {14,  4, 13,  1,  2, 15, 11,  8,
                  3, 10,  6, 12,  5,  9,  0,  7,
    			  0, 15,  7,  4, 14,  2, 13,  1,
                 10,  6, 12, 11,  9,  5,  3,  8,
    			  4,  1, 14,  8, 13,  6,  2, 11,
                 15, 12,  9,  7,  3, 10,  5,  0,
    			 15, 12,  8,  2,  4,  9,  1,  7,
                  5, 11,  3, 14, 10,  0,  6, 13};

    sBoxes[2] = {15,  1,  8, 14,  6, 11,  3,  4,
                  9,  7,  2, 13, 12,  0,  5, 10,
			      3, 13,  4,  7, 15,  2,  8, 14,
                 12,  0,  1, 10,  6,  9, 11,  5,
			      0, 14,  7, 11, 10,  4, 13,  1,
                  5,  8, 12,  6,  9,  3,  2, 15,
			     13,  8, 10,  1,  3, 15,  4,  2,
                 11,  6,  7, 12,  0,  5, 14,  9};

    sBoxes[3] = {10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
			13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
			13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
			 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12};

    sBoxes[4] = { 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
			13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
			10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
			 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14};

    sBoxes[5] = { 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
			14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
			 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
			11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3};

    sBoxes[6] = {12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
			10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
			 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
			 4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13};

    sBoxes[7] = { 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
			13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
			 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
			 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12};

    sBoxes[8] = {13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
			 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
			 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
			 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11};

}*/
