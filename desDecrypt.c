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
void hash(int number);
void BinTo64(uint64_t number, int numBits);

// Generates sequential keys and tries to decrypt the cipher text and match it
// with the known plaintext.
int main()
{
    // The program will try all keys between these these two (and including them).
    // We reassign them based on how many other computers we plan to have
    // running this program.
    // Our instructor has restricted to keySize to 36 bits, generateKey
    // takes a 36 bit argument and returns a 64 bit key.
    uint64_t startKey = 0;
    uint64_t endKey =   0b111111111111111111111111111111111111;
    int startingPoint, range;
    FILE *out;

    out = fopen("desDecrypt_output.txt", "w");

    printf("\n\nBe sure to check https://goo.gl/8d8PkY (the online google spreadsheet) for which segments have been searched already!\n\n");
    printf("What segment of the keyspace will you be starting at?\n");
    printf("Enter a number between 0 and 999 (inclusive)\n");
    do{
        scanf("%d", &startingPoint);
        if(startingPoint < 0 || startingPoint > 999)
            printf("Enter a valid number.\n");
    }while(startingPoint < 0 || startingPoint > 999);

    printf("\nHow many segments of the key space will you search?\nEach segment has ");
    printf("about 68,000,000 keys in it (there are 1,000 segments that need ");
    printf("to be searched).\nA computer that runs 10,000 keys per second ");
    printf("should take slightly less than 2 hours to search a segment.\n");
    printf("\nEnter a number greater than or equal to 1\n");
    do{
        scanf("%d", &range);
        if(range < 1 || range > 25)
            printf("Enter a valid number (25 and larger is too big to be valid).\n");
        if((startingPoint + range) > 999)
            printf("You entered a search that would take you passed the end of the key space.\n");
    }while(range < 1 || range > 25);

    uint64_t segment = endKey / 1000;
    startKey = segment * startingPoint;
    endKey = startKey + segment * range;

    //printf("%llu\n", (unsigned long long)segment);
    printf("startKey\n%llu\nendKey\n%llu\n", (unsigned long long)startKey, (unsigned long long)endKey);

    printf("\nSearching the segments %d through %d\n\n\n\n", startingPoint, startingPoint + range - 1);
    printf("\n");

    // Plain text and the matching cipher text that were given to us in the
    // assignment. Converted from radix64 to binary.
    uint64_t knownPlainText =     0b1100000111101100001000101001111101101101001101011110101111100000;
    uint64_t matchingCipherText = 0b0000001100111011101000101000001010001111001000001100010011100001;

    uint64_t decryptedCipherText = 0;
    uint64_t key = 0;

    clock_t t = clock();
    // Start guessing keys and decrypting.
    for(key = startKey; key <= endKey; key++ )
    {
        // Generate the 64 key bit given given 36 bits using the restrictions that
        // have been placed on the key space.
        decryptedCipherText = decrypt(matchingCipherText, generateKey(key));

        // Break if we have succeeded.
        if(decryptedCipherText == knownPlainText){
            fprintf(out, "The 36 bit key is %llu\n", (unsigned long long)key);
            fprintf(out, "The 64 bit key is %llu\n", (unsigned long long)generateKey(key));
            printf("YOU FOUND IT!\nThis program generates a file called ");
            printf("desDecrypt_output.txt that has the key saved in it. \nIf you see this ");
            printf("message then contact Austin Shipley as soon as you can ");
            printf("with the information your instance of the program found.\n\n");
            printf("Thanks so much for your help with this project! :)");
            return 0;
        }
    }
    t = clock() - t;

    unsigned long long numKeys = key - startKey;
    double time_taken = ((double)t) / CLOCKS_PER_SEC;
    double keysPerSec = ((double)numKeys) / time_taken;

    fclose(out);

    printf("The program has concluded, but we didn't find the key yet.\nYou searched the following segments.\n");
    while(range>0)
    {
        printf("Segment No. %d\n", startingPoint);
        printf("unique hash: ");
        hash(startingPoint++);
        --range;
        printf("\n");
    }
    printf("Please go to https://goo.gl/8d8PkY (an online google spreadsheet)\n");
    printf("and paste the above hashes into the appropriate rows to mark these ");
    printf("segments as searched \n(or just send Austin Shipley a picture of it at 352-638-0444 and he'll be more than happy to do it for you).\n\n");

    printf("Thanks for your contribution!\nI encourage you to start the program again with new, unsearched segments!\n\n");
    printf("It took %lf seconds to search %llu keys\n", time_taken, numKeys);
    printf("Thats %lf keys per sec!\n", keysPerSec);




    return 0;
}

// Takes a 36-bit input (current iteration of key being checked)
// Returns a corresponding key of size 64
uint64_t generateKey(uint64_t iteration) {
    // Shift iteration 28 bits left so it's most significant bits align with those of a 64-bit number
    uint64_t key = iteration << 28;

    // Break up 36 bit iteration input into blocks that can be moved based on key formula:
    // k_i = k_(32+i) for i: 1 to 5, 9 to 13, 17 to 21, 25 to 29
    // (All parity bits are left 0 as there value doesn't affect the outcome of DES)
    uint64_t bits1to5 =   keyGenBitMasks[0] & key;
    uint64_t bits6to7 =   keyGenBitMasks[1] & key;
    uint64_t bits8to12 =  keyGenBitMasks[2] & key;
    uint64_t bits13to14 = keyGenBitMasks[3] & key;
    uint64_t bits15to19 = keyGenBitMasks[4] & key;
    uint64_t bits20to21 = keyGenBitMasks[5] & key;
    uint64_t bits22to26 = keyGenBitMasks[6] & key;
    uint64_t bits27to28 = keyGenBitMasks[7] & key;
    uint64_t bits29to30 = keyGenBitMasks[8] & key;
    uint64_t bits31to32 = keyGenBitMasks[9] & key;
    uint64_t bits33to34 = keyGenBitMasks[10] & key;
    uint64_t bits35to36 = keyGenBitMasks[11] & key;

    return (bits1to5) | (bits6to7)| (bits8to12 >> 1) | (bits13to14 >> 1) | (bits15to19 >> 2) | (bits20to21 >> 2) | (bits22to26 >> 3) | (bits27to28 >> 3) | (bits1to5 >> 32) | (bits29to30 >> 9) | (bits8to12 >> 33) |

             (bits15to19 >> 34) | (bits22to26 >> 35) |
            (bits31to32 >> 15) | (bits33to34 >> 21) | (bits35to36 >> 27);
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

    // Apply the PC permutation and split the key into halves.
    permutedKey = permute(key, 64, PC64, 56);

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

// Prints the given number in binary, adds spaces to break the output up into
// blocks of blockSize.
void printInBinary(uint64_t number, int numBits, int blockSize)
{
    uint64_t num = number;
    uint64_t mask = 1;
    mask = mask << numBits-1;
    uint64_t digit;
    int i;

    for(i=0; i<numBits; i++)
    {
        if(i%blockSize == 0 && i != 0)
            printf(" ");
        digit = num & mask;
        digit = digit>>(numBits-1);
        num = num<<1;

        printf("%llu", (unsigned long long)digit);
    }
    printf("\n");
}

// Print the number in hexadecimal, numBits must be a multiple of 4 or the last
// char will be inaccurate.
void BinToHex(uint64_t number, int numBits)
{
    uint64_t num = number;
    uint64_t mask = 0b1111;
    uint64_t character;
    int i;

    mask = mask << (numBits-4);

    for(i=0; i<numBits; i+=4)
    {
        character = num & mask;
        character = character >> (numBits - (i+4));
        mask = mask >> 4;
        switch((int)character)
        {
            case 0:
                    printf("0");
                    break;
            case 1:
                    printf("1");
                    break;
            case 2:
                    printf("2");
                    break;
            case 3:
                    printf("3");
                    break;
            case 4:
                    printf("4");
                    break;
            case 5:
                    printf("5");
                    break;
            case 6:
                    printf("6");
                    break;
            case 7:
                    printf("7");
                    break;
            case 8:
                    printf("8");
                    break;
            case 9:
                    printf("9");
                    break;
            case 10:
                    printf("A");
                    break;
            case 11:
                    printf("B");
                    break;
            case 12:
                    printf("C");
	                break;
            case 13:
                    printf("D");
				    break;
            case 14:
                    printf("E");
                    break;
            case 15:
                    printf("F");
					break;
        }
    }
    printf("\n");
}

void hash(int number)
{
    srand(number+671);
    unsigned long hash = 5381;
    char *str = malloc(sizeof(char)*5);;
    int i;

    number = number * rand() % 1367;
    sprintf(str, "%d", number);

    while(i = *str++)
    {
        hash = ((hash << 5) + hash) + i;
    }

    free(str);
    printf("%lu\n", hash%4129);
}

// Print the number in base64. Inputs must be a multiple of 6 or the last char
// will be inaccurate.
void BinTo64(uint64_t number, int numBits)
{
    uint64_t num = number;
    uint64_t mask = 0b111111;
    uint64_t character;
    int i;

    mask = mask << (numBits-6);

    for(i=0; i<numBits; i+=6)
    {
        character = num & mask;
        character = character >> (numBits - (i+6));
        mask = mask >> 6;
        switch((int)(character+1))
        {
            case 1:
                    printf("A");
                    break;
            case 2:
                    printf("B");
                    break;
            case 3:
                    printf("C");
                    break;
            case 4:
                    printf("D");
                    break;
            case 5:
                    printf("E");
                    break;
            case 6:
                    printf("F");
                    break;
            case 7:
                    printf("G");
                    break;
            case 8:
                    printf("H");
                    break;
            case 9:
                    printf("I");
                    break;
            case 10:
                    printf("J");
                    break;
            case 11:
                    printf("K");
                    break;
            case 12:
                    printf("L");
	                break;
            case 13:
                    printf("M");
				    break;
            case 14:
                    printf("N");
                    break;
            case 15:
                    printf("O");
					break;
            case 16:
                    printf("P");
					break;
            case 17:
                    printf("Q");
					break;
            case 18:
                    printf("R");
					break;
            case 19:
                    printf("S");
					break;
            case 20:
                    printf("T");
					break;
            case 21:
                    printf("U");
					break;
            case 22:
                    printf("V");
					break;
            case 23:
                    printf("W");
					break;
            case 24:
                    printf("X");
					break;
            case 25:
                    printf("Y");
					break;
            case 26:
                    printf("Z");
					break;
            case 27:
                    printf("a");
					break;
            case 28:
                    printf("b");
					break;
            case 29:
                    printf("c");
					break;
            case 30:
                    printf("d");
					break;
            case 31:
                    printf("e");
                    break;
            case 32:
                    printf("f");
                    break;
            case 33:
                    printf("g");
					break;
            case 34:
                    printf("h");
					break;
            case 35:
                    printf("i");
					break;
            case 36:
                    printf("j");
					break;
            case 37:
                    printf("k");
					break;
            case 38:
                    printf("l");
					break;
            case 39:
                    printf("m");
					break;
            case 40:
                    printf("n");
					break;
            case 41:
                    printf("o");
					break;
            case 42:
                    printf("p");
					break;
            case 43:
                    printf("q");
					break;
            case 44:
                    printf("r");
					break;
            case 45:
                    printf("s");
					break;
            case 46:
                    printf("t");
					break;
            case 47:
                    printf("u");
					break;
            case 48:
                    printf("v");
					break;
            case 49:
                    printf("w");
					break;
            case 50:
                    printf("x");
					break;
            case 51:
                    printf("y");
					break;
            case 52:
                    printf("z");
					break;
            case 53:
                    printf("0");
					break;
            case 54:
                    printf("1");
					break;
            case 55:
                    printf("2");
					break;
            case 56:
                    printf("3");
					break;
            case 57:
                    printf("4");
					break;
            case 58:
                    printf("5");
					break;
            case 59:
                    printf("6");
					break;
            case 60:
                    printf("7");
					break;
            case 61:
                    printf("8");
					break;
            case 62:
                    printf("9");
					break;
            case 63:
                    printf("+");
					break;
            case 64:
                    printf("/");
                    break;
            default:
                    printf("invalid character\n");
                    break;
        }
    }
    printf("\n");
}
