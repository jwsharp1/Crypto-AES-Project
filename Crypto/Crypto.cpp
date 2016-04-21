/*--Authors:	Isaac Lopez and Jacob Sharp
----Class:		Cryptographic Algorithms and Protocols
----Semester:	Spring 2016
----Teacher:	Rida Bazzi	*/


/* PROGRAMMER NOTES SECTION

-shiftRows and invShift Rows tested and working.
-subBytes and invSubBytes tested and working
-entire program: 'theState' renamed to just 'state'
-the program currently only accepts messages of length 16 characters
-roundkey was copied from reference. I am trying to code it in a different way that isn't just a copy.
-added the invsBox table for the invSubBytes function

-discovered and marked issue with MixColumns

*/

#include <iostream>
using namespace std;

#define byte unsigned char
//typedef unsigned char byte;

//****************************************************************
//********************* Global Variables *************************
int Nb = 4;
int Nr, Nk = 0;
byte *keySchedule;
byte roundKey[240];
byte state[4][4] = { { 'a', 'b', 'c', 'd' },
						{ 'e', 'f', 'g', 'h' },
						{ 'i', 'j', 'k', 'l' },
						{ 'm', 'n', 'o', 'p' } };
//****************************************************************
//********************* Forward Declarations *********************
int sBoxLookup(int x);
void userInput();
void cipher(char *message);

// Transformations
void subBytes();
void shiftRows();
void mixColumns();
void addRoundKey();
void invShiftRows();
void invSubBytes();
void invMixColumns();
void invAddRoundKey();

// Arithmetic
// note addition is equal to bitwise xor so use ^
byte xtime(byte a);
byte x_nTime(byte a, int n);
byte multiply(byte a, byte b);

void expandKey(byte* key);
byte subWord(byte *input);
byte rotWord(byte *input);
byte rCon(int i);
//****************************************************************
//****************************************************************


//****************************************************************
//*********************** DEBUGGING ******************************
void statePrinter();
// ***************************************************************
//****************************************************************


int sBoxLookup(int x) {				//SBox is a hex table that is used in the SubBytes() transformation step
	int sBox[256] = {
		0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
		0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
		0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
		0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
		0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
		0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
		0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
		0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
		0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
		0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
		0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
		0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
		0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
		0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
		0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
		0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };
	return sBox[x];
}

int invsBoxLookup(int x) {
	int invsBox[256] = {
		0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
		0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
		0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
		0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
		0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
		0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
		0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
		0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
		0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
		0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
		0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
		0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
		0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
		0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
		0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
		0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };
	return invsBox[x];
}

// This function recieves the input message to be encoded and the user's private key.
void userInput() {
	char message[16];  // accept messages up to 16 characters long until CTR is implemented
	char key[32];

	cout << "Enter the message to be encoded:\n" << endl;
	cin.getline(message, 16, '\n');		// cin.getline() is used to avoid a buffer overflow attack. cin.getline() ignores characters that proceed the terminating character '\n'
	cout << "Enter your private key:\n" << endl;
	cin.getline(key, 16, '\n');

	cipher(message);  // send the message to the cipher code
}

// this function replaces the values in the state array with values from the S-Box table
void subBytes() {
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			state[i][j] = sBoxLookup(state[i][j]);
		}
	}
}

// this function shifts the rows of the state
void shiftRows() {
	byte tempRowVal;

	// SECOND ROW SHIFTS: shift the row one column to the left													___________
	tempRowVal = state[1][0];	// copy col 0 to temp														  0|__|__|__|__| NO SHIFT
	state[1][0] = state[1][1];	// move col 1 to 0 position									 shift 1 left ->  1|__|__|__|__| SECOND ROW SHIFT
	state[1][1] = state[1][2];	// move col 2 to 1 position									 shift 2 left ->  2|__|__|__|__| THIRD ROW SHIFT
	state[1][2] = state[1][3];	// move col 3 to 2 position									 shift 3 left ->  3|__|__|__|__| FOURTH ROW SHIFT
	state[1][3] = tempRowVal;	// wrap around; copy original col 0 to 3 position

								// THIRD ROW SHIFTS: shift the second row two columns to the left
	tempRowVal = state[2][0];	// copy col 0 to temp
	state[2][0] = state[2][2];	// copy col 2 to col 0
	state[2][2] = tempRowVal;	// copy tempRowVal to col 2
	tempRowVal = state[2][1];	// copy col 1 to temp
	state[2][1] = state[2][3];	// copy col 3 to col 1
	state[2][3] = tempRowVal;	// copy the temp to col 3

								// FOURTH ROW SHIFTS: shifts the row values three columns to the left (equivalent to shifting right by 1)
	tempRowVal = state[3][0];	// copy col 0 to temp
	state[3][0] = state[3][3];	// copy col 3 to col 0
	state[3][3] = state[3][2];	// copy col 2 to col 3
	state[3][2] = state[3][1];	// copy col 1 to col 2
	state[3][1] = tempRowVal;;	// copy temp to col 1
}

void mixColumns()
{
	byte polynomialA[4][4] = { { 0x02, 0x03, 0x01, 0x01 },
	{ 0x01, 0x02, 0x03, 0x01 },
	{ 0x01, 0x01, 0x02, 0x03 },
	{ 0x03, 0x01, 0x01, 0x02 } };
	byte newColumnVals[4];

	for (int c = 0; c < 4; c++)
	{	//c is column index

		//calculate the matrix multiplication of the 2d array and column c from the state
		for (int i = 0; i < 4; i++)
		{	//i is index of row for the 2d array
			byte sumOfProducts = 0x00;
			for (int j = 0; j < 4; j++)
			{	//j is the column
				sumOfProducts = sumOfProducts ^ multiply(polynomialA[i][j], state[j][c]);		// <-- ISSUE: the result of this is always ""
			}
			newColumnVals[i] = sumOfProducts;
		}
		//store calculated values in column c of the state
		for (int i = 0; i < 4; i++)
		{
			state[i][c] = newColumnVals[i];
		}
		//loop runs again on every column of the state
	}
}

// stealy the code from reference.cpp
void addRoundKey(int round)
{
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			state[j][i] ^= roundKey[round * Nb * 4 + i * Nb + j];
		}
	}

	//for (int c = 0; c < Nb; c++) {
	//	state[0][c] = state[0][c] ^ 
	//}
}

// this function reverts the shifts performed by the shiftRows() step
void invShiftRows() {
	byte tempRowVal;

	// SECOND ROW SHIFTS: shift the row one column to the right													___________
	tempRowVal = state[1][0];	// copy col 0 to temp														  0|__|__|__|__| NO SHIFT
	state[1][0] = state[1][3];	// move col 3 to 0 position									shift 1 right ->  1|__|__|__|__| SECOND ROW SHIFT
	state[1][3] = state[1][2];	// move col 2 to 3 position									shift 2 right ->  2|__|__|__|__| THIRD ROW SHIFT
	state[1][2] = state[1][1];	// move col 1 to 2 position									shift 3 right ->  3|__|__|__|__| FOURTH ROW SHIFT
	state[1][1] = tempRowVal;	// copy original col 0 to 1 position

	// THIRD ROW SHIFTS: shift the second row two columns to the right
	tempRowVal = state[2][0];	// copy col 0 to temp
	state[2][0] = state[2][2];	// copy col 2 to col 0
	state[2][2] = tempRowVal;	// copy tempRowVal to col 2
	tempRowVal = state[2][1];	// copy col 1 to temp
	state[2][1] = state[2][3];	// copy col 3 to col 1
	state[2][3] = tempRowVal;	// copy the temp to col 3

	// FOURTH ROW SHIFTS: shifts the row values three columns to the right (equivalent to shifting left by 1)
	tempRowVal = state[3][0];	// copy col 0 to temp
	state[3][0] = state[3][1];	// copy col 1 to col 0
	state[3][1] = state[3][2];	// copy col 2 to col 1
	state[3][2] = state[3][3];	// copy col 3 to col 2
	state[3][3] = tempRowVal;;	// copy temp to col 3
}

// this function is the inverse of SubBytes; it replaces values in the state with values from the inverse S-Box table
void invSubBytes()
{
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			state[i][j] = invsBoxLookup(state[i][j]);
		}
	}
}

void invMixColumns()
{
	byte invPolynomialA[4][4] = { { 0x0e, 0x0b, 0x0d, 0x09 },
								  { 0x09, 0x0e, 0x0b, 0x0d },
								  { 0x0d, 0x09, 0x0e, 0x0b },
								  { 0x0b, 0x0d, 0x09, 0x0e } };
	byte newColumnVals[4];

	for (int c = 0; c < 4; c++)
	{	//c is column index
		
		//calculate the matrix multiplication of the 2d array and column c from the state
		for (int i = 0; i < 4; i++)
		{	//i is index of row for the 2d array
			byte sumOfProducts = 0x00;
			for (int j = 0; j < 4; j++)
			{	//j is the column
				sumOfProducts = sumOfProducts ^ multiply(invPolynomialA[i][j], state[j][c]);
			}
			newColumnVals[i] = sumOfProducts;
		}
		//store calculated values in column c of the state
		for (int i = 0; i < 4; i++)
		{
			state[i][c] = newColumnVals[i];
		}
		//loop runs again on every column of the state
	}
}

void invAddRoundKey(int round)
{

}

//multiplies the polynomial representation of a by the polynomial x
byte xtime(byte a)
{
	//check to see if first bit is 1
	if ((a & 0x80) == 0x80)
	{ //first bit is one
		byte b = 0x1b;
		a = a << 1; //left shift by 1
		return a ^ b;
	}
	else
	{ //first bit is zero
		return a;
	}
}

//multiplies the polynomial representation of a by the polynomial x^n
byte x_nTime(byte a, int n)
{
	if (n == 0)
	{ //base case
		return a;
	}
	else
	{
		return x_nTime(xtime(a), n - 1);
	}
}

byte multiply(byte a, byte b)
{
	byte sumOfProducts = 0x00;
	int n = 7;
	for (byte i = 0x80; i > 0x00;)
	{
		if ((i & a) == i)
		{ //check to see if the polynomial of power n has a coeffcient of 1
			sumOfProducts = sumOfProducts ^ x_nTime(a, n);
		}
		i = i >> 1;
		n--;
	}

	return NULL;
}

//void expandKey(byte* key)
//{
//	keySchedule = new byte[Nb*(Nk + 1)];
//
//	for (int i = 0; i < Nk; i++)
//	{
//
//	}
//}

//*byte subWord(byte *input)
//{
//	byte *output = new byte[4];
//	for (int i = 0; i < 4; i++)
//	{
//		*output[i] = sBox(input[i]);
//	}
//	return output;
//}
//
//*byte rotWord(byte *input)
//{
//	byte *output = new byte[4];
//	byte temp = *input[0];
//	for (int i = 0; i < 3; i++)
//	{
//		*output[i] = *output[i + 1];
//	}
//	*output[3] = temp;
//	return output;
//}
//
//*byte rCon(int i)
//{
//	byte *output = { 0x00, 0x00, 0x00, 0x00 };
//	byte temp = 0x01;
//	for (int j = 1; j < i; j++)
//	{
//		temp = temp << 1;
//	}
//	*output[0] = temp;
//	return output;
//}

void cipher(char *message) {
	
	// convert the input message to unsigned chars
	byte *unsignedMsg = (byte*)message;

	// copy the unsigned message into the state array
	for (int r = 0; r < 4; r++) {
		for (int c = 0; c < Nb; c++) {
			state[r][c] = unsignedMsg[r + 4*c];
		}
	}

	
}

void main() {
	userInput();

	// run these debug commands
	statePrinter(); // prints a-p
	mixColumns(); // mix columns
	statePrinter(); // blank output
}

// calling this function will print the state array
void statePrinter() {
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			cout << state[i][j] << " ";
		}
		cout << endl;
	}
}