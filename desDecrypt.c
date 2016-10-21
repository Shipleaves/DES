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

// The program will try all keys between these these two (and including them).
// The function getKeyRange reassigns them based on how many other computers
// you plan to have running this program.
uint64_t startKey = 0b0;
uint64_t endKey 0b1111111111111111111111111111111111111111111111111111111111111111;

void getKeyRange(uint64_t , uint64_t);
uint64_t decrypt(uint64_t);
uint64_t feistel(uint32_t , uint64_t);
uint64_t switchHalves(uint64_t);
uint64_t* roundKeys(uint64_t);
uint64_t permute(uint64_t , uint64_t);

// Generates sequential keys and tries to decrypt the cipher text and match it
// with the known plaintext. Once the key is found, it will decrypt the rest of
// cipher text.
int main()
{

}

// Given the number of computers running the program and which number you are,
// assigns the most appropriate range of keys that you should try.
void getKeyRange(uint64_t numComputers, uint64_t yourNum)
{

}

// Starts the decryption process on the given text.
uint64_t decrypt(uint64_t text)
{

}

// The Feistel function. Expands the 32 bit half to 48 bits, XOR the result with
// the 48 bit round key, send the result throught the appropriate S-Box.
uint64_t feistel(uint32_t half, uint64_t roundKey)
{

}

// Swaps the two halves of the text in between rounds.
uint64_t switchHalves(uint64_t text)
{

}

// Generates an array of all the 48 bit roundKeys from the given key.
uint48_t* roundKeys(uint64_t key)
{

}

// Applies the passed permutation array to the text. Used for Initial
// Permuation, inverse Initial Permuatation, Expansion Permuation, and Sboxes.
uint64_t permute(uint64_t text, uint64_t perm)
{

}
