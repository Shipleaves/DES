// Austin Shipley
// DES brute force decryption

/*
This program generates every key value from 0 to 2^56-1 (we don't use the
parity bits so we don't generate them and have modified PC1 to reflect this
change) and tries to decrypt the given ciphertext and match it with the known
plaintext.
It makes extensive use of the uint64_t data type which stores unsigned 64 bit
integers. Its used these to store the key, the 64 bit block of text, and
various other variables and bitmasks. Also used is the data type uint32_t.

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
int IP[64] = {58, 50, 42, 34, 26, 18, 10, 2,
              60, 52, 44, 36, 28, 20, 12, 4,
              62, 54, 46, 38, 30, 22, 14, 6,
              64, 56, 48, 40, 32, 24, 16, 8,
              57, 49, 41, 33, 25, 17,  9, 1,
              59, 51, 43, 35, 27, 19, 11, 3,
              61, 53, 45, 37, 29, 21, 13, 5,
              63, 55, 47, 39, 31, 23, 15, 7};

int IPinv[64] = {40, 8, 48, 16, 56, 24, 64, 32,
                 39, 7, 47, 15, 55, 23, 63, 31,
                 38, 6, 46, 14, 54, 22, 62, 30,
                 37, 5, 45, 13, 53, 21, 61, 29,
                 36, 4, 44, 12, 52, 20, 60, 28,
                 35, 3, 43, 11, 51, 19, 59, 27,
                 34, 2, 42, 10, 50, 18, 58, 26,
                 33, 1, 41,  9, 49, 17, 57, 25};


int E[48] = {32,  1,  2,  3,  4,  5,
              4,  5,  6,  7,  8,  9,
              8,  9, 10, 11, 12, 13,
             12, 13, 14, 15, 16, 17,
             16, 17, 18, 19, 20, 21,
             20, 21, 22, 23, 24, 25,
             24, 25, 26, 27, 28, 29,
             28, 29, 30, 31, 32,  1};

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

int PC2[48] = {14, 17, 11, 24,  1,  5,
                3, 28, 15,  6, 21, 10,
               23, 19, 12,  4, 26,  8,
               16,  7, 27, 20, 13,  2,
               41, 52, 31, 37, 47, 55,
               30, 40, 51, 45, 33, 48,
               44, 49, 39, 56, 34, 53,
               46, 42, 50, 36, 29, 32};

int keyShifts[16] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

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

// Function signatures.
uint64_t decrypt(uint64_t, uint64_t);
uint64_t feistel(uint32_t , uint64_t);
uint64_t* keySchedule(uint64_t, int);
uint64_t permute(uint64_t , int, int*, int);
uint32_t sBox(uint64_t);
void printInBinary(uint64_t, int, int);
void BinToHex(uint64_t, int);
void BinTo64(uint64_t, int);

// Generates sequential keys and tries to decrypt the cipher text and match it
// with the known plaintext.
int main()
{
    // The program will try all keys between these these two (and including them).
    // We reassign them based on how many other computers we plan to have
    // running this program.
    // endKey is 56 bits because we leave out the parity bits, so theres 8 less
    // bits to generate.
    // Keys for testing, takes about 20 seconds to run.
    //uint64_t startKey = 0b00010010011010010101101111001001101100000000000000000000;
    //uint64_t endKey =   0b00010010011010010101101111001001101101111011011111111111;
    uint64_t startKey = 0;
    uint64_t endKey =   0b11111111111111111111111111111111111111111111111111111111;
    uint64_t range = startKey - endKey;
    int numComputers, yourNum;
    FILE* out;

    out = fopen("output.txt", "w");

    printf("How many computers will be running this program?\n");
    scanf("%d", &numComputers);
    printf("What number are you? 0 through numComputers-1\n");
    scanf("%d", &yourNum);

    range = endKey / numComputers;
    startKey = range * yourNum;
    endKey = startKey + range;

    printf("Searching the range \n");
    BinToHex(startKey, 64);
    BinToHex(endKey, 64);
    printf("\n");

    // text for testing, matches the key from above.
    //uint64_t knownPlainText =     0b0000000100100011010001010110011110001001101010111100110111101111;
    //uint64_t matchingCipherText = 0b1000010111101000000100110101010000001111000010101011010000000101;
    // plaintext in radix64 wewin2016+ plus the four 0's for padding.
    // cipher text in radix64 Azuigo8gxOE minus the two 0's that were padded on.
    uint64_t knownPlainText =     0b1100000111101100001000101001111101101101001101011110101111100000;
    uint64_t matchingCipherText = 0b0000001100111011101000101000001010001111001000001100010011100001;
    uint64_t decryptedCipherText = 0;
    uint64_t key = 0;

    printf("trying decrypt\n");
    BinTo64(matchingCipherText, 64);
    printf("to get\n");
    BinTo64(knownPlainText, 64);
    printf("\n\n");

    clock_t t = clock();
    // Start guessing keys and decrypting.
    for(key = startKey; key <= endKey; key++ )
    {
        decryptedCipherText = decrypt(matchingCipherText, key);

        // Break if we have succeeded.
        if(decryptedCipherText == knownPlainText){
            printf("We did it!\n");
            break;
        }
    }
    t = clock() - t;

    unsigned long long numKeys = key - startKey;
    double time_taken = ((double)t) / CLOCKS_PER_SEC;
    double keysPerSec = ((double)numKeys) / time_taken;

    fprintf(out, "key %llu\n", (unsigned long long)key);
    fprintf(out, "It took %lf seconds to search %llu keys\n", time_taken, numKeys);
    fprintf(out, "Thats %lf keyspersec\n\n", keysPerSec);

    printf("The key I found was \n");
    BinToHex(key+1, 56);
    printInBinary(key+1, 56, 8);
    printf("\n");
    printf("What I found the plaintext to be \n");
    BinToHex(decryptedCipherText, 64);
    printf("What the plaintext is supposed to be \n");
    BinToHex(knownPlainText, 64);
}

uint64_t decrypt(uint64_t text, uint64_t key)
{
    //printf("decrypt\n");
    // An array for the precomputed round keys, pass the key and numBits in key.
    uint64_t* roundKey = keySchedule(key, 56);

    // Used for switching halves. right is a bitmask.
    uint32_t rightHalf = 0;
    uint64_t right = 0b0000000000000000000000000000000011111111111111111111111111111111;
    uint32_t leftHalf = 0;
    uint32_t temp = 0;

    // The round we are currently on
    int round = 0;

    // Apply the Initial Permutation matrix.
    text = permute(text, 64, IP, 64);

    // Split the text in half, in preperation for the feistel rounds.
    leftHalf = text >> 32;
    rightHalf = text & right;

    // Do the rounds in reverse order.
    for(round = 15; round >= 0; round--)
    {
        // Save the unchanged right half, R_(i-1)
        temp = rightHalf;

        // XOR the left half with the output of the Feistel function.
        // Go ahead and switch the halves by assiging this to the rightHalf
        // and assigning temp to leftHalf.
        rightHalf = leftHalf ^ feistel(rightHalf, roundKey[round]);
        leftHalf = temp;
    }

    // Put the halves back together with the halves in the opposite places.
    // This is deliberate.
    text = rightHalf;
    text = text << 32;
    text = text | leftHalf;

    // Free the roundKey pointer, it was malloc'd in the keySchedule function.
    free(roundKey);

    // Apply the inverse of the Initial Permutation matrix.
    return permute(text, 64, IPinv, 64);
}

// The Feistel function.
// Expands the 32 bit half to 48 bits, XOR the result with the 48 bit round key,
// shrink the result to 32 bits with S-Boxes, and apply the P permutation.
uint64_t feistel(uint32_t half, uint64_t roundKey)
{
    //printf("feistel\n");
    uint64_t expandedHalf = permute(half, 32, E, 48);
    expandedHalf = expandedHalf ^ roundKey;
    half =  sBox(expandedHalf);

    return permute(half, 32, P, 32);
}

// Generates an array of all the 48 bit roundKeys from the given key.
uint64_t* keySchedule(uint64_t key, int numBits)
{
    //printf("keySchedule\n");
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
    if(numBits == 64)
        permutedKey = permute(key, 64, PC64, 56);
    else
        permutedKey = permute(key, 56, PC1, 56);

    leftHalf = permutedKey >> 28;
    rightHalf = permutedKey & right;


    // Apply the keyShifts and PC2 permutation.
    for(i=0; i<16; i++)
    {
        // The bits that are pushed off the left get wrapped around to the right.
        wrapAround = leftHalf & mask;
        // Get the two leftmost bits, we need to shift them all the way to the
        // right, but we don't know if there will be 1 or 2 wraparound bits.
        // So we shift left by the number of keyShifts and then shift right
        // by 28 bits. (Faster than shifting by 28 - keyShifts[i] ).
        wrapAround = wrapAround << keyShifts[i];
        wrapAround = wrapAround >> 28;
        leftHalf = leftHalf << keyShifts[i];
        // Deletes the shifted bit(s).
        leftHalf = leftHalf & right;
        // Adds the wrapAround bit(s).
        leftHalf = leftHalf | wrapAround;

        wrapAround = rightHalf & mask;
        wrapAround = wrapAround << keyShifts[i];
        wrapAround = wrapAround >> 28;
        rightHalf = rightHalf << keyShifts[i];
        rightHalf = rightHalf & right;
        rightHalf = rightHalf | wrapAround;

        // Put the key back together so we can apply the PC2 perm.
        permutedKey = leftHalf;
        permutedKey = permutedKey << 28;
        permutedKey = permutedKey | rightHalf;
        roundKeys[i] = permute(permutedKey, 56, PC2, 48);
    }
    // Return the 16 roundKeys, each one 48 bits.
    return roundKeys;
}

// Applies the permutation array to the text.
// The perm arrays refer to the leftmost bit as the 1st.
uint64_t permute(uint64_t text, int sizeOfText, int* perm, int lenOfPerm)
{
    //printf("permute\n");
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
        mask = mask << (sizeOfText-1);

        // Get the perm[i]th bit from ans
        mask = mask >> (perm[i]-1);
        temp = (text & mask);

        // Shift temp so the bit is at the rightmost position.
        // Add it to the end of ans.
        temp = temp >> (sizeOfText - perm[i]);
        ans = ans | temp;
    }

    return ans;
}

// Applies all 8 Sboxes to the 48 bit input and returns a 32 bit output.
uint32_t sBox(uint64_t input)
{
    //printf("sbox\n");
    uint64_t ans = 0;
    uint64_t row = 0;
    uint64_t col = 0;
    // Masks to get the row and col for the sBox.
    uint64_t maskInner = 0b011110000000000000000000000000000000000000000000;
    uint64_t mask48 =    0b100000000000000000000000000000000000000000000000;
    uint64_t mask43 =    0b000001000000000000000000000000000000000000000000;
    int i = 0;

    for(i=0; i<8; i++)
    {
        // Shift the answer so we're ready to store the next 4 bits.
        ans = ans << 4;

        // Get row and column and then shift input so it's ready for next time.
        row = ((input & mask48) >> 46) | ((input & mask43) >> 42);
        col = (input & maskInner) >> 43;
        input = input << 6;

        // Add the 4 bit number from sboxes to ans.
        ans =  ans | sboxes[i][row*16 + col];
    }

    return ans;
}

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
