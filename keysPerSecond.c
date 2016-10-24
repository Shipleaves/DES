// Austin Shipley
// DES brute force decryption

/*
This program generates every key value from 0 to 2^37-1 and uses some rules
given by the instructor to expand the key to 56 bits and tries to decrypt the
 given ciphertext and match it with the known plaintext.

It makes extensive use of the uint64_t data type which stores unsigned 64 bit
integers. Its used these to store the key, the 64 bit block of text, and
various other variables and bitmasks.

This program has the ability to divide the workload and be run on several
different computers to speed up the search time tremendously.
This program is designed with speed in mind, as we have to try an enourmous
number of combinations.
*/

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <time.h>

// All of the necessary matrices and tables for DES.

// The initial permuatation matrix, applied immediately to the input text.
int IP[64] = {58, 50, 42, 34, 26, 18, 10, 2,
              60, 52, 44, 36, 28, 20, 12, 4,
              62, 54, 46, 38, 30, 22, 14, 6,
              64, 56, 48, 40, 32, 24, 16, 8,
              57, 49, 41, 33, 25, 17,  9, 1,
              59, 51, 43, 35, 27, 19, 11, 3,
              61, 53, 45, 37, 29, 21, 13, 5,
              63, 55, 47, 39, 31, 23, 15, 7};

// The inverse of IP matrix, applied as the very last step.
int IPinv[64] = {40, 8, 48, 16, 56, 24, 64, 32,
                 39, 7, 47, 15, 55, 23, 63, 31,
                 38, 6, 46, 14, 54, 22, 62, 30,
                 37, 5, 45, 13, 53, 21, 61, 29,
                 36, 4, 44, 12, 52, 20, 60, 28,
                 35, 3, 43, 11, 51, 19, 59, 27,
                 34, 2, 42, 10, 50, 18, 58, 26,
                 33, 1, 41,  9, 49, 17, 57, 25};

// The Expansion matrix. Takes a 32 bit input and expands it to be 48 bits.
// Applied in the Feistel function.
int E[48] = {32,  1,  2,  3,  4,  5,
              4,  5,  6,  7,  8,  9,
              8,  9, 10, 11, 12, 13,
             12, 13, 14, 15, 16, 17,
             16, 17, 18, 19, 20, 21,
             20, 21, 22, 23, 24, 25,
             24, 25, 26, 27, 28, 29,
             28, 29, 30, 31, 32,  1};

// The Permute matrix. Applied as the last step of the Feistel function.
// Shuffles around a 32 bit input.
int P[32]=   {16,  7, 20, 21,
              29, 12, 28, 17,
               1, 15, 23, 26,
               5, 18, 31, 10,
               2,  8, 24, 14,
              32, 27,  3,  9,
              19, 13, 30,  6,
              22, 11,  4, 25};

// PC1 has been modified because we do not include the parity bits in our 64 bit
// key. In fact we only generate a 56 bit key.
int PC1[56] =  {50, 43, 36, 29, 22, 15,  8,  1,
                51, 44, 37, 30, 23, 16,  9,  2,
                52, 45, 38, 31, 24, 17, 10,  3,
                53, 46, 39, 32, 56, 49, 42, 35,
                28, 21, 14,  7, 55, 48, 41, 34,
                27, 20, 13,  6, 54, 47, 40, 33,
                26, 19, 12,  5, 25, 18, 11,  4};

// Original PC matrix for use with 64 bit keys.
int PC64[56] = {57, 49, 41, 33, 25, 17,  9,
                 1, 58, 50, 42, 34, 26, 18,
                10,  2, 59, 51, 43, 35, 27,
                19, 11,  3, 60, 52, 44, 36,
                63, 55, 47, 39, 31, 23, 15,
                 7, 62, 54, 46, 38, 30, 22,
                14,  6, 61, 53, 45, 37, 29,
                21, 13,  5, 28, 20, 12,  4};

// PC2 matrix used in the generation of the 48 bit roundKeys from a 56 bit key.
int PC2[48] = {14, 17, 11, 24,  1,  5,
                3, 28, 15,  6, 21, 10,
               23, 19, 12,  4, 26,  8,
               16,  7, 27, 20, 13,  2,
               41, 52, 31, 37, 47, 55,
               30, 40, 51, 45, 33, 48,
               44, 49, 39, 56, 34, 53,
               46, 42, 50, 36, 29, 32};

// We shift the left and right halves of the key between every round when
// generating the roundKeys.
int keyShifts[16] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

// 8 different S-boxes, takes a 48 bit input and shrinks it to 32 bits.
// Used in the Feistel function.
int sboxes[8][64] = {
            {14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
			  0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
			  4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
			 15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13},

             {15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
			   3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
			   0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
			  13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9},

             {10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
			  13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
			  13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
			   1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12},

             { 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
			  13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
			  10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
			   3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14},

             { 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
			  14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
			   4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
			  11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3},

             {12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
			  10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
			   9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
			   4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13},

             { 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
			  13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
			   1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
			   6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12},

             {13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
			   1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
			   7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
			   2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11}
                     };


// Global array of bitmasks (more efficient than generating all 12 masks before each key is determined)
uint64_t keyGenBitMasks[12] = {
    0b1111100000000000000000000000000000000000000000000000000000000000,
    0b0000011000000000000000000000000000000000000000000000000000000000,
    0b0000000111110000000000000000000000000000000000000000000000000000,
    0b0000000000001100000000000000000000000000000000000000000000000000,
    0b0000000000000011111000000000000000000000000000000000000000000000,
    0b0000000000000000000110000000000000000000000000000000000000000000,
    0b0000000000000000000001111100000000000000000000000000000000000000,
    0b0000000000000000000000000011000000000000000000000000000000000000,
    0b0000000000000000000000000000110000000000000000000000000000000000,
    0b0000000000000000000000000000001100000000000000000000000000000000,
    0b0000000000000000000000000000000011000000000000000000000000000000,
    0b0000000000000000000000000000000000110000000000000000000000000000};

// Function signatures.
uint64_t generateKey(uint64_t key);
uint64_t decrypt(uint64_t input, uint64_t key);
uint64_t feistel(uint32_t half, uint64_t roundKey);
uint64_t* keySchedule(uint64_t key);
uint64_t permute(uint64_t input, int sizeOfInput, int* perm, int lenOfPerm);
uint32_t sBox(uint64_t input);
void printInBinary(uint64_t number, int numBits, int blockSize);
void BinToHex(uint64_t number, int numBits);
void BinTo64(uint64_t number, int numBits);

// Generates sequential keys and tries to decrypt the cipher text and match it
// with the known plaintext.
int main()
{
    // Keys for testing, searches 3651576 keys. Takes between 2 seconds to a
    // minute
    // The acutal key we are "searching" for 0001001100110100010101110111100110011011101111001101111111110001
    uint64_t startKey = 0b0001001100110100010101110111100110011011101111000000000000000000;
    uint64_t endKey =   0b0001001100110100010101110111100110011011101111001101111111111111;

    // text for testing, matches the key above.
    uint64_t knownPlainText =     0b0000000100100011010001010110011110001001101010111100110111101111;
    uint64_t matchingCipherText = 0b1000010111101000000100110101010000001111000010101011010000000101;

    uint64_t decryptedCipherText = 0;
    uint64_t key = 0;

    clock_t t = clock();
    // Start guessing keys and decrypting.
    for(key = startKey; key <= endKey; key++ )
    {
        decryptedCipherText = decrypt(matchingCipherText, key);

        // Break if we have succeeded.
        if(decryptedCipherText == knownPlainText)
            break;
    }
    t = clock() - t;

    unsigned long long numKeys = key - startKey;
    double time_taken = ((double)t) / CLOCKS_PER_SEC;
    double keysPerSec = ((double)numKeys) / time_taken;

    printf("It took %lf seconds to search %llu keys\n", time_taken, numKeys);
    printf("Thats %lf keyspersec!\n\n", keysPerSec);

    return 0;
}

uint64_t decrypt(uint64_t input, uint64_t key)
{
    // An array for the precomputed round keys, pass the key and numBits in key.
    uint64_t* roundKey = keySchedule(key);

    // Used for switching halves. right is a bitmask.
    uint32_t rightHalf = 0;
    uint64_t right = 0b0000000000000000000000000000000011111111111111111111111111111111;
    uint32_t leftHalf = 0;
    uint32_t temp = 0;

    // The round we are currently on
    int round = 0;

    // Apply the Initial Permutation matrix.
    input = permute(input, 64, IP, 64);

    // Split the input in half, in preperation for the feistel rounds.
    leftHalf = input >> 32;
    rightHalf = input & right;

    // Do the rounds in reverse order.
    // Unrolled this loop for(round = 15; round >= 0; round--)

        // Save the unchanged right half, R_(i-1)
        temp = rightHalf;

        // XOR the left half with the output of the Feistel function.
        // Go ahead and switch the halves by assiging this to the rightHalf
        // and assigning temp to leftHalf.
        rightHalf = leftHalf ^ feistel(rightHalf, roundKey[15]);
        leftHalf = temp;

        temp = rightHalf;
        rightHalf = leftHalf ^ feistel(rightHalf, roundKey[14]);
        leftHalf = temp;

        temp = rightHalf;
        rightHalf = leftHalf ^ feistel(rightHalf, roundKey[13]);
        leftHalf = temp;

        temp = rightHalf;
        rightHalf = leftHalf ^ feistel(rightHalf, roundKey[12]);
        leftHalf = temp;

        temp = rightHalf;
        rightHalf = leftHalf ^ feistel(rightHalf, roundKey[11]);
        leftHalf = temp;

        temp = rightHalf;
        rightHalf = leftHalf ^ feistel(rightHalf, roundKey[10]);
        leftHalf = temp;

        temp = rightHalf;
        rightHalf = leftHalf ^ feistel(rightHalf, roundKey[9]);
        leftHalf = temp;

        temp = rightHalf;
        rightHalf = leftHalf ^ feistel(rightHalf, roundKey[8]);
        leftHalf = temp;

        temp = rightHalf;
        rightHalf = leftHalf ^ feistel(rightHalf, roundKey[7]);
        leftHalf = temp;

        temp = rightHalf;
        rightHalf = leftHalf ^ feistel(rightHalf, roundKey[6]);
        leftHalf = temp;

        temp = rightHalf;
        rightHalf = leftHalf ^ feistel(rightHalf, roundKey[5]);
        leftHalf = temp;

        temp = rightHalf;
        rightHalf = leftHalf ^ feistel(rightHalf, roundKey[4]);
        leftHalf = temp;

        temp = rightHalf;
        rightHalf = leftHalf ^ feistel(rightHalf, roundKey[3]);
        leftHalf = temp;

        temp = rightHalf;
        rightHalf = leftHalf ^ feistel(rightHalf, roundKey[2]);
        leftHalf = temp;

        temp = rightHalf;
        rightHalf = leftHalf ^ feistel(rightHalf, roundKey[1]);
        leftHalf = temp;

        temp = rightHalf;
        rightHalf = leftHalf ^ feistel(rightHalf, roundKey[0]);
        leftHalf = temp;


    // Put the halves back together with the halves in the opposite places.
    // This is deliberate and necessary.
    input = rightHalf;
    input = input << 32;
    input = input | leftHalf;

    // Free the roundKey pointer, it was malloc'd in the keySchedule function.
    free(roundKey);

    // Apply the inverse of the Initial Permutation matrix.
    return permute(input, 64, IPinv, 64);
}

// The Feistel function.
// Expands the 32 bit half to 48 bits, XOR the result with the 48 bit round key,
// shrink the result to 32 bits with S-Boxes, and apply the P permutation.
uint64_t feistel(uint32_t half, uint64_t roundKey)
{
    uint64_t expandedHalf = permute(half, 32, E, 48);
    expandedHalf = expandedHalf ^ roundKey;
    half =  sBox(expandedHalf);

    return permute(half, 32, P, 32);
}

// Generates an array of all the 48 bit roundKeys from the given key.
uint64_t* keySchedule(uint64_t key)
{
    uint64_t* roundKeys;
    uint64_t permutedKey = 0;
    uint32_t leftHalf = 0;
    uint32_t rightHalf = 0;
    uint64_t right = 0b00000000000000000000000000001111111111111111111111111111;
    uint64_t mask =  0b1100000000000000000000000000;
    int i = 0, wrapAround = 0;

    // Allocate space for our roundKeys. We need 16 blocks of 48 bits,
    // But we don't have a 48 bit data type, so we must have 16, 64 bit blocks.
    roundKeys = (uint64_t*)malloc(128);

    // Apply the PC1 permutation and split the key into halves.
    permutedKey = permute(key, 64, PC1, 56);

    leftHalf = permutedKey >> 28;
    rightHalf = permutedKey & right;


    // Apply the keyShifts and PC2 permutation.
    // Unrolled this loop for(i=0; i<16; i++)

        // The bits that are pushed off the left get wrapped around to the right.
        wrapAround = leftHalf & mask;
        // Get the two leftmost bits, we need to shift them all the way to the
        // right, but we don't know if there will be 1 or 2 wraparound bits.
        // So we shift left by the number of keyShifts and then shift right
        // by 28 bits. (Faster than shifting by 28 - keyShifts[i]).
        wrapAround = wrapAround << keyShifts[0];
        wrapAround = wrapAround >> 28;
        leftHalf = leftHalf << keyShifts[0];
        // Deletes the shifted bit(s).
        leftHalf = leftHalf & right;
        // Adds the wrapAround bit(s).
        leftHalf = leftHalf | wrapAround;

        // Similarly for the rightHalf.
        wrapAround = rightHalf & mask;
        wrapAround = wrapAround << keyShifts[0];
        wrapAround = wrapAround >> 28;
        rightHalf = rightHalf << keyShifts[0];
        rightHalf = rightHalf & right;
        rightHalf = rightHalf | wrapAround;

        permutedKey = leftHalf;
        permutedKey = permutedKey << 28;
        permutedKey = permutedKey | rightHalf;
        roundKeys[0] = permute(permutedKey, 56, PC2, 48);
        // end first iteration.

        wrapAround = leftHalf & mask;
        wrapAround = wrapAround << keyShifts[1];
        wrapAround = wrapAround >> 28;
        leftHalf = leftHalf << keyShifts[1];
        leftHalf = leftHalf & right;
        leftHalf = leftHalf | wrapAround;
        wrapAround = rightHalf & mask;
        wrapAround = wrapAround << keyShifts[1];
        wrapAround = wrapAround >> 28;
        rightHalf = rightHalf << keyShifts[1];
        rightHalf = rightHalf & right;
        rightHalf = rightHalf | wrapAround;
        permutedKey = leftHalf;
        permutedKey = permutedKey << 28;
        permutedKey = permutedKey | rightHalf;
        roundKeys[1] = permute(permutedKey, 56, PC2, 48);

        wrapAround = leftHalf & mask;
        wrapAround = wrapAround << keyShifts[2];
        wrapAround = wrapAround >> 28;
        leftHalf = leftHalf << keyShifts[2];
        leftHalf = leftHalf & right;
        leftHalf = leftHalf | wrapAround;
        wrapAround = rightHalf & mask;
        wrapAround = wrapAround << keyShifts[2];
        wrapAround = wrapAround >> 28;
        rightHalf = rightHalf << keyShifts[2];
        rightHalf = rightHalf & right;
        rightHalf = rightHalf | wrapAround;
        permutedKey = leftHalf;
        permutedKey = permutedKey << 28;
        permutedKey = permutedKey | rightHalf;
        roundKeys[2] = permute(permutedKey, 56, PC2, 48);

        wrapAround = leftHalf & mask;
        wrapAround = wrapAround << keyShifts[3];
        wrapAround = wrapAround >> 28;
        leftHalf = leftHalf << keyShifts[3];
        leftHalf = leftHalf & right;
        leftHalf = leftHalf | wrapAround;
        wrapAround = rightHalf & mask;
        wrapAround = wrapAround << keyShifts[3];
        wrapAround = wrapAround >> 28;
        rightHalf = rightHalf << keyShifts[3];
        rightHalf = rightHalf & right;
        rightHalf = rightHalf | wrapAround;
        permutedKey = leftHalf;
        permutedKey = permutedKey << 28;
        permutedKey = permutedKey | rightHalf;
        roundKeys[3] = permute(permutedKey, 56, PC2, 48);

        wrapAround = leftHalf & mask;
        wrapAround = wrapAround << keyShifts[4];
        wrapAround = wrapAround >> 28;
        leftHalf = leftHalf << keyShifts[4];
        leftHalf = leftHalf & right;
        leftHalf = leftHalf | wrapAround;
        wrapAround = rightHalf & mask;
        wrapAround = wrapAround << keyShifts[4];
        wrapAround = wrapAround >> 28;
        rightHalf = rightHalf << keyShifts[4];
        rightHalf = rightHalf & right;
        rightHalf = rightHalf | wrapAround;
        permutedKey = leftHalf;
        permutedKey = permutedKey << 28;
        permutedKey = permutedKey | rightHalf;
        roundKeys[4] = permute(permutedKey, 56, PC2, 48);

        wrapAround = leftHalf & mask;
        wrapAround = wrapAround << keyShifts[5];
        wrapAround = wrapAround >> 28;
        leftHalf = leftHalf << keyShifts[5];
        leftHalf = leftHalf & right;
        leftHalf = leftHalf | wrapAround;
        wrapAround = rightHalf & mask;
        wrapAround = wrapAround << keyShifts[5];
        wrapAround = wrapAround >> 28;
        rightHalf = rightHalf << keyShifts[5];
        rightHalf = rightHalf & right;
        rightHalf = rightHalf | wrapAround;
        permutedKey = leftHalf;
        permutedKey = permutedKey << 28;
        permutedKey = permutedKey | rightHalf;
        roundKeys[5] = permute(permutedKey, 56, PC2, 48);

        wrapAround = leftHalf & mask;
        wrapAround = wrapAround << keyShifts[6];
        wrapAround = wrapAround >> 28;
        leftHalf = leftHalf << keyShifts[6];
        leftHalf = leftHalf & right;
        leftHalf = leftHalf | wrapAround;
        wrapAround = rightHalf & mask;
        wrapAround = wrapAround << keyShifts[6];
        wrapAround = wrapAround >> 28;
        rightHalf = rightHalf << keyShifts[6];
        rightHalf = rightHalf & right;
        rightHalf = rightHalf | wrapAround;
        permutedKey = leftHalf;
        permutedKey = permutedKey << 28;
        permutedKey = permutedKey | rightHalf;
        roundKeys[6] = permute(permutedKey, 56, PC2, 48);

        wrapAround = leftHalf & mask;
        wrapAround = wrapAround << keyShifts[7];
        wrapAround = wrapAround >> 28;
        leftHalf = leftHalf << keyShifts[7];
        leftHalf = leftHalf & right;
        leftHalf = leftHalf | wrapAround;
        wrapAround = rightHalf & mask;
        wrapAround = wrapAround << keyShifts[7];
        wrapAround = wrapAround >> 28;
        rightHalf = rightHalf << keyShifts[7];
        rightHalf = rightHalf & right;
        rightHalf = rightHalf | wrapAround;
        permutedKey = leftHalf;
        permutedKey = permutedKey << 28;
        permutedKey = permutedKey | rightHalf;
        roundKeys[7] = permute(permutedKey, 56, PC2, 48);

        wrapAround = leftHalf & mask;
        wrapAround = wrapAround << keyShifts[8];
        wrapAround = wrapAround >> 28;
        leftHalf = leftHalf << keyShifts[8];
        leftHalf = leftHalf & right;
        leftHalf = leftHalf | wrapAround;
        wrapAround = rightHalf & mask;
        wrapAround = wrapAround << keyShifts[8];
        wrapAround = wrapAround >> 28;
        rightHalf = rightHalf << keyShifts[8];
        rightHalf = rightHalf & right;
        rightHalf = rightHalf | wrapAround;
        permutedKey = leftHalf;
        permutedKey = permutedKey << 28;
        permutedKey = permutedKey | rightHalf;
        roundKeys[8] = permute(permutedKey, 56, PC2, 48);

        wrapAround = leftHalf & mask;
        wrapAround = wrapAround << keyShifts[9];
        wrapAround = wrapAround >> 28;
        leftHalf = leftHalf << keyShifts[9];
        leftHalf = leftHalf & right;
        leftHalf = leftHalf | wrapAround;
        wrapAround = rightHalf & mask;
        wrapAround = wrapAround << keyShifts[9];
        wrapAround = wrapAround >> 28;
        rightHalf = rightHalf << keyShifts[9];
        rightHalf = rightHalf & right;
        rightHalf = rightHalf | wrapAround;
        permutedKey = leftHalf;
        permutedKey = permutedKey << 28;
        permutedKey = permutedKey | rightHalf;
        roundKeys[9] = permute(permutedKey, 56, PC2, 48);

        wrapAround = leftHalf & mask;
        wrapAround = wrapAround << keyShifts[10];
        wrapAround = wrapAround >> 28;
        leftHalf = leftHalf << keyShifts[10];
        leftHalf = leftHalf & right;
        leftHalf = leftHalf | wrapAround;
        wrapAround = rightHalf & mask;
        wrapAround = wrapAround << keyShifts[10];
        wrapAround = wrapAround >> 28;
        rightHalf = rightHalf << keyShifts[10];
        rightHalf = rightHalf & right;
        rightHalf = rightHalf | wrapAround;
        permutedKey = leftHalf;
        permutedKey = permutedKey << 28;
        permutedKey = permutedKey | rightHalf;
        roundKeys[10] = permute(permutedKey, 56, PC2, 48);

        wrapAround = leftHalf & mask;
        wrapAround = wrapAround << keyShifts[11];
        wrapAround = wrapAround >> 28;
        leftHalf = leftHalf << keyShifts[11];
        leftHalf = leftHalf & right;
        leftHalf = leftHalf | wrapAround;
        wrapAround = rightHalf & mask;
        wrapAround = wrapAround << keyShifts[11];
        wrapAround = wrapAround >> 28;
        rightHalf = rightHalf << keyShifts[11];
        rightHalf = rightHalf & right;
        rightHalf = rightHalf | wrapAround;
        permutedKey = leftHalf;
        permutedKey = permutedKey << 28;
        permutedKey = permutedKey | rightHalf;
        roundKeys[11] = permute(permutedKey, 56, PC2, 48);

        wrapAround = leftHalf & mask;
        wrapAround = wrapAround << keyShifts[12];
        wrapAround = wrapAround >> 28;
        leftHalf = leftHalf << keyShifts[12];
        leftHalf = leftHalf & right;
        leftHalf = leftHalf | wrapAround;
        wrapAround = rightHalf & mask;
        wrapAround = wrapAround << keyShifts[12];
        wrapAround = wrapAround >> 28;
        rightHalf = rightHalf << keyShifts[12];
        rightHalf = rightHalf & right;
        rightHalf = rightHalf | wrapAround;
        permutedKey = leftHalf;
        permutedKey = permutedKey << 28;
        permutedKey = permutedKey | rightHalf;
        roundKeys[12] = permute(permutedKey, 56, PC2, 48);

        wrapAround = leftHalf & mask;
        wrapAround = wrapAround << keyShifts[13];
        wrapAround = wrapAround >> 28;
        leftHalf = leftHalf << keyShifts[13];
        leftHalf = leftHalf & right;
        leftHalf = leftHalf | wrapAround;
        wrapAround = rightHalf & mask;
        wrapAround = wrapAround << keyShifts[13];
        wrapAround = wrapAround >> 28;
        rightHalf = rightHalf << keyShifts[13];
        rightHalf = rightHalf & right;
        rightHalf = rightHalf | wrapAround;
        permutedKey = leftHalf;
        permutedKey = permutedKey << 28;
        permutedKey = permutedKey | rightHalf;
        roundKeys[13] = permute(permutedKey, 56, PC2, 48);

        wrapAround = leftHalf & mask;
        wrapAround = wrapAround << keyShifts[14];
        wrapAround = wrapAround >> 28;
        leftHalf = leftHalf << keyShifts[14];
        leftHalf = leftHalf & right;
        leftHalf = leftHalf | wrapAround;
        wrapAround = rightHalf & mask;
        wrapAround = wrapAround << keyShifts[14];
        wrapAround = wrapAround >> 28;
        rightHalf = rightHalf << keyShifts[14];
        rightHalf = rightHalf & right;
        rightHalf = rightHalf | wrapAround;
        permutedKey = leftHalf;
        permutedKey = permutedKey << 28;
        permutedKey = permutedKey | rightHalf;
        roundKeys[14] = permute(permutedKey, 56, PC2, 48);

        wrapAround = leftHalf & mask;
        wrapAround = wrapAround << keyShifts[15];
        wrapAround = wrapAround >> 28;
        leftHalf = leftHalf << keyShifts[15];
        leftHalf = leftHalf & right;
        leftHalf = leftHalf | wrapAround;
        wrapAround = rightHalf & mask;
        wrapAround = wrapAround << keyShifts[15];
        wrapAround = wrapAround >> 28;
        rightHalf = rightHalf << keyShifts[15];
        rightHalf = rightHalf & right;
        rightHalf = rightHalf | wrapAround;
        permutedKey = leftHalf;
        permutedKey = permutedKey << 28;
        permutedKey = permutedKey | rightHalf;
        roundKeys[15] = permute(permutedKey, 56, PC2, 48);
        // end for loop

    // Return the 16 roundKeys, each one 48 bits.
    return roundKeys;
}

// Applies the permutation array to the input. Used for applying the IP, IPinv,
// E, and P permutations.
// The perm arrays refer to the leftmost bit as the 1st.
uint64_t permute(uint64_t input, int sizeOfInput, int* perm, int lenOfPerm)
{
    uint64_t ans = 0;
    uint64_t temp = 0;
    uint64_t mask = 0;
    int i = 0;

    for(i=0; i<lenOfPerm; i++)
    {
        // Shift answer so the new bit has somewhere to go.
        ans = ans << 1;
        mask = 1;
        // This step is necessary because the 1st bit is the leftmost.
        mask = mask << (sizeOfInput-1);

        // Get the perm[i]th bit from ans
        mask = mask >> (perm[i]-1);
        temp = (input & mask);

        // Shift temp so the bit is at the rightmost position.
        // Add it to the end of ans.
        temp = temp >> (sizeOfInput - perm[i]);
        ans = ans | temp;
    }

    return ans;
}

// Applies all 8 Sboxes to the 48 bit input and returns a 32 bit output.
uint32_t sBox(uint64_t input)
{
    uint64_t ans = 0;
    uint64_t row = 0;
    uint64_t col = 0;
    // Masks to get the row and col for the sBox.
    uint64_t maskInner = 0b011110000000000000000000000000000000000000000000;
    uint64_t mask48 =    0b100000000000000000000000000000000000000000000000;
    uint64_t mask43 =    0b000001000000000000000000000000000000000000000000;
    int i = 0;

    // Unrolled this loop for(i=0; i<8; i++)

        // Get row and column and then shift input so it's ready for next time.
        row = ((input & mask48) >> 46) | ((input & mask43) >> 42);
        col = (input & maskInner) >> 43;
        input = input << 6;

        // Add the 4 bit number from sboxes to ans.
        ans =  ans | sboxes[0][row*16 + col];
        // end first iteration.

        // Shift the answer so we're ready to store the next 4 bits.
        // We didn't need to do it on the first iteration.
        ans = ans << 4;
        row = ((input & mask48) >> 46) | ((input & mask43) >> 42);
        col = (input & maskInner) >> 43;
        input = input << 6;
        ans =  ans | sboxes[1][row*16 + col];

        ans = ans << 4;
        row = ((input & mask48) >> 46) | ((input & mask43) >> 42);
        col = (input & maskInner) >> 43;
        input = input << 6;
        ans =  ans | sboxes[2][row*16 + col];

        ans = ans << 4;
        row = ((input & mask48) >> 46) | ((input & mask43) >> 42);
        col = (input & maskInner) >> 43;
        input = input << 6;
        ans =  ans | sboxes[3][row*16 + col];

        ans = ans << 4;
        row = ((input & mask48) >> 46) | ((input & mask43) >> 42);
        col = (input & maskInner) >> 43;
        input = input << 6;
        ans =  ans | sboxes[4][row*16 + col];

        ans = ans << 4;
        row = ((input & mask48) >> 46) | ((input & mask43) >> 42);
        col = (input & maskInner) >> 43;
        input = input << 6;
        ans =  ans | sboxes[5][row*16 + col];

        ans = ans << 4;
        row = ((input & mask48) >> 46) | ((input & mask43) >> 42);
        col = (input & maskInner) >> 43;
        input = input << 6;
        ans =  ans | sboxes[6][row*16 + col];

        // and we don't need to shift input on the last iteration.
        ans = ans << 4;
        row = ((input & mask48) >> 46) | ((input & mask43) >> 42);
        col = (input & maskInner) >> 43;
        ans =  ans | sboxes[7][row*16 + col];
        // end for loop.

    return ans;
}
