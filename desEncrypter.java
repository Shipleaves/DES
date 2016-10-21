
// Arup Guha
// 11/7/06
// Solution for CIS 3362 DES Project

// There are many weaknesses in this solution due to my laziness!
// All of the constants in the algorithm should be stored in final
// static variables, but I just wanted to read in the information
// from the files instead of hard-coding them.

// Also, the key should stay the same for encrypting one file, but
// the blocks must change. This hasn't been indicated clearly.

import java.io.*;
import java.util.*;

public class DES {

	private int[] key;
	private int[][] roundkeys;
	private int[] block;

	private static int[][][] stables;
	private static int[] IP;
	private static int[] IPInv;
	private static int[] E;
	private static int[] PC2;
	private static int[] P;
	private static int[] PC1;
	private static int[] keyshifts;

	// Reads all the information from the file I created based on the order
	// the values were stored in the file. My original posted file had some
	// errors in it, because some zeroes were stored as captial O's. I fixed
	// those issues in the file and have posted the corrected file with this
	// solution.
	public DES(int[] thekey) throws Exception {

		key = new int[64];
		stables = new int[8][4][16];
		IP = new int[64];
		IPInv = new int[64];
		E = new int[48];
		PC2 = new int[48];
		P = new int[32];
		PC1 = new int[56];
		keyshifts = new int[16];
		block = new int[64];

		// Sets the key to what was passed in.
		for (int i=0; i<64; i++)
			key[i] = thekey[i];

		Scanner fin = new Scanner(new File("destables.txt"));

		// Reads in the initial permutation matrix.
		for (int i=0; i<64; i++)
			IP[i] = fin.nextInt();

		// Reads in the inverse of the initial permutation matrix.
		for (int i=0; i<64; i++)
			IPInv[i] = fin.nextInt();

		// Expansion matrix used in each round.
		for (int i=0; i<48; i++)
			E[i] = fin.nextInt();

		// The permutation matrix P used in each round.
		for (int i=0; i<32; i++)
			P[i] = fin.nextInt();

		// Reads in the 8 S-boxes!
		for (int i=0; i<8; i++) {

			for (int j=0; j<64; j++) {
				stables[i][j/16][j%16] = fin.nextInt();
			}
		}

		// Reads in PC1, used for the key schedule.
		for (int i=0; i<56; i++)
			PC1[i] = fin.nextInt();

		// Reads in PC2 used for the round keys.
		for (int i=0; i<48; i++)
			PC2[i] = fin.nextInt();

		// Reads in the shifts used for the key between each round.
		for (int i=0; i<16; i++)
			keyshifts[i] = fin.nextInt();

		fin.close();
	}

	// Sets a block based on the string of bits. The string is guaranteed
	// to only have characters '0' and '1'.
	public void setBlock(String bits) {
		for (int i=0; i<64; i++)
			block[i] = (int)(bits.charAt(i)-'0');
	}

	// Prints out a block with spaces after every 8 characters on one line.
	public void print(FileWriter fout) throws Exception {
		for (int i=0; i<64; i++) {
			if (i%8 == 0) fout.write(" ");
			fout.write(""+block[i]);
		}

		fout.write("\n");
	}

	// Encrypts the current block.
	public void encrypt() {

		// Permute the block with the initial permutation.
		block = Permute(block, IP);

		// Run 16 rounds.
		for (int i=0; i<16; i++) {
			round(i);
		}

		// Supposed to switch halves at the end and invert the initial
		// permutation.
		switchHalves();
		block = Permute(block, IPInv);
	}

	// Switches the left half of the current block with the right half.
	public void switchHalves() {
		int[] temp = new int[32];

		// We're just doing a regular swap between 32 bits...

		for (int i=0; i<32; i++)
			temp[i] = block[i];

		for (int i=0; i<32; i++)
			block[i] = block[32+i];

		for (int i=32; i<64; i++)
			block[i] = temp[i-32];
	}

	// Permutes the bits in original according to perm and
	// returns this permutation of the original bits.
	public static int[] Permute(int[] original, int[] perm) {


		int[] ans = new int[original.length];

		// Note: We subtract 1 from perm[i] because in the tables, the
		// permutations are 1-based, instead of 0-based.
		for (int i=0; i< perm.length; i++)
			ans[i] = original[perm[i]-1];
		return ans;
	}

	// Takes the block of bits in whole from index start to index end,
	// inclusive and cyclicly left-shifts them by numbits number of bits.
	public static void leftShift(int[] whole, int start, int end, int numbits) {
		int size = end-start+1;
		int[] temp = new int[size];

		// Copy the bits into temp in their new order.
		for (int i=0; i<temp.length; i++)
			temp[i] = whole[start+(numbits+i)%size];

		// Copy them back into the original array in the order we stored them
		// in temp, with the appropriate offset, start.
		for (int i=0; i<temp.length; i++)
			whole[start+i] = temp[i];
	}

	public static void printArray(int[] array) {
		for (int i=0; i<array.length; i++) {
			if (i%8 == 0) System.out.print(" ");
			System.out.print(array[i]);
		}
		System.out.println();
	}

	// Runs round num of DES.
	public void round(int num) {
		int[] left = new int[32];
		int[] right = new int[32];

		// Copy in the left and right blocks into temporary arrays.
		for (int i=0; i<32; i++)
			left[i] = block[i];
		for (int i=0; i<32; i++)
			right[i] = block[32+i];

		// Expand the right block.
		int[] expanded = E(right);

		// This is the XOR we want.
		int[] xorans = XOR(expanded, roundkeys[num]);

		// Run the s-boxes on all the appropriate "blocks".
		int[] sboxout = Sboxes(xorans);

		// Permute the S-box output.
		int[] fout = Permute(sboxout, P);

		// Then do the necessary XOR.
		fout = XOR(fout, left);

		// Copy the blocks back into their proper place!
		for (int i=0; i<32; i++)
			block[i] = right[i];
		for (int i=0; i<32; i++)
			block[32+i] = fout[i];
	}

	// Expand the 32 bits and return the corresponding 48 bits.
	public static int[] E(int[] bits) {
		int[] ans = new int[48];

		// Our permutation function doesn't work for this, so it's coded here.
		for (int i=0; i<48; i++)
			ans[i] = bits[E[i]-1];
		return ans;
	}

	// Returns the XOR of the bit streams a and b.
	public static int[] XOR(int[] a, int[] b) {
		int[] ans = new int[a.length];
		for (int i=0; i<a.length; i++)
			ans[i] = (a[i]+b[i])%2;
		return ans;
	}

	// Returns the output of putting the 48 bit input through the
	// 8 S-boxes.
	public int[] Sboxes(int[] input) {
		int[] ans = new int[32];

		for (int i=0; i<8; i++) {

			// Just hard-coded this part. There doesn't seem to be a more
			// elegant way...
			int row = 2*input[6*i] + input[6*i+5];
			int col = 8*input[6*i+1]+4*input[6*i+2]+2*input[6*i+3]+input[6*i+4];

			int temp = stables[i][row][col];

			// We have to store the base-10 answer in binary, so we strip off the
			// bits one-by-one, in the usual manner from the least to most significant.
			for (int j=3; j>=0; j--) {
				ans[4*i+j] = temp%2;
				temp /= 2;
			}
		}
		return ans;

	}

	// Set up the keys for each round.
	public void setKeys() {
		roundkeys = new int[16][48];

		// Set the original key with PC1.
		key = Permute(key, PC1);

		// Go through and set the round keys using the process by which they
		// are supposed to be computed.
		for (int i=0; i<16; i++) {

			// Supposed to left-shift both halves by the appropriate amount,
			// based on the round.
			leftShift(key, 0, 27, keyshifts[i]);
			leftShift(key, 28, 55, keyshifts[i]);

			// Now, just copy in the (i+1)th round key.
			for (int j=0; j<48; j++) {
				roundkeys[i][j] = key[PC2[j]-1];
			}
		}
	}

	// Converts the string version of the key in HEX to binary which is
	// stored in an integer array of size 64...thus, the check bits are
	// included here.
	public static int[] getKey(String thekey) {
		int[] ans = new int[64];
		thekey = thekey.toLowerCase();

		// Go through all 16 characters.
		for (int i=0; i<16; i++) {
			int val = (int)(thekey.charAt(i));

			// We need to assign value separately if it is a digit or a letter.
			if ('0' <= val && val <= '9')
				val = val - '0';
			else
				val = val - 'a' + 10;

			// Peel off the binary bits as before...
			for (int j=3; j>=0; j--) {
				ans[4*i+j]=val%2;
				val /= 2;
			}
		}

		return ans;
	}

	public static void main(String[] args) throws Exception {


		Scanner stdin = new Scanner(System.in);


		// Get the necessary user information...
		System.out.println("Enter the input file.");
		String infilename = stdin.next();

		System.out.println("Enter the output file.");
		String outfilename = stdin.next();

		System.out.println("Enter the key in hex.");
		String key = stdin.next();

		Scanner fin = new Scanner(new File(infilename));
		FileWriter fout = new FileWriter(new File(outfilename));

		// Set up the keys.
		int[] mykey = getKey(key);
		DES code = new DES(mykey);
		code.setKeys();

		// Read in each block and process...
		while (fin.hasNext()) {
			String myblock = fin.next();

			// So we don't run into any errors!
			if (myblock == null) break;

			code.setBlock(myblock);
			code.encrypt();
			code.print(fout);
		}

		fout.close();
		fin.close();
	}

}
