/**************************/
/* Emanuele Bellini, 2012 */
/**************************/

// tbbc.cpp : main function
//

//#ifdef WIN32
  //  #include "stdafx.h" // works for Visual C++ 2010
//#endif

#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <iomanip> // to use the function setw()
#include <bitset> // to use the Bitset class
#include <math.h>
#include <sstream> // used in ucharToString() to convert from unsigned char to string

#include "tbbc.h" //definition of the class TBBC
#include "tbbcAES_128m8s.h"   //definition of the class TBBCAES
#include "tbbcBUNNY_24m24k.h" //definition of the class TBBCBUNNY

using namespace std;


//instantiation of a TBBC, first create a type, then an instance of that type

typedef TBBCAES<128,10> AES_128_10 ; // define a type AES 
                                     // which is an instance of TBBCAES
                                     // 128 is key size
                                     // 10 is number of rounds
typedef TBBCAES<192,12> AES_192_12 ; // define a type AES 
typedef TBBCAES<256,14> AES_256_14 ; // define a type AES
typedef TBBCAES<64,5> AES_64_10 ; // define a type AES

typedef TBBCBUNNY<6,5> BUNNY_5 ; // define a type BUNNY

typedef TBBC<16,32,3,3> TBBC_16_32_3_3 ; // define a type TBBC

int main(int argc, char* argv[]) {
	cout << "|---------------------------------------|\n"
	     << "|---------------------------------------|\n"
	     << "|------------ Welcome to... ------------|\n"
	     << "|---------------------------------------|\n"
	     << "|----______---__-------__------___------|\n"
	     << "|---|__  __|-|| \\-----|| \\----//  \\-----|\n"
	     << "|------||----||_/-----||_/---||---------|\n"
	     << "|------||----|| \\-----|| \\---||---------|\n"
	     << "|------||----||  \\----||  \\--||---------|\n"
	     << "|-----/__\\ . ||__/- . ||__/ . \\___/ . --|\n"
	     << "|---------------------------------------|\n"
	     << "|--- TRANSLATION-BASED BLOCK CIPHERS ---|\n"
	     << "|---------------------------------------|\n"
       << "|---------------------------------------|\n\n" ;

	////////////////////////////////////////////////////////////////////////////

	//AES_128_10 instantiation
	AES_128_10 aes_128_10 ;

  AES_128_10::msgType m128 ;
  AES_128_10::keyType k128 ;
  AES_128_10::msgType c128 ;

	cout << "----------------------------------------------------" << endl ;
	cout << "AES-128\n"
       << "PARAMETERS: |m|=128 |k|=128 |n|=10" << endl ;
	k128 = hexTo<bitset<128> >("2b7e151628aed2a6abf7158809cf4f3c") ;
	m128 = hexTo<bitset<128> >("6bc1bee22e409f96e93d7e117393172a") ;
	//k128 = hexTo<bitset<128> >("00000000000000000000000000000000") ;

	cout << "       k = " << bitsetToHex(k128) << endl ;
	c128 = aes_128_10.encode(m128,k128) ;
	cout << "       m = " << bitsetToHex(m128) << endl ;
	cout << "Enc(m,k) = " << bitsetToHex(c128) << endl ;
	cout << "Dec(c,k) = " << bitsetToHex(aes_128_10.decode(c128,k128)) << endl ;

	////////////////////////////////////////////////////////////////////////////

	AES_192_12 aes_192_12 ;

  AES_192_12::msgType m192 ;
  AES_192_12::keyType k192 ;
  AES_192_12::msgType c192 ;

	cout << "----------------------------------------------------" << endl ;
	cout << "AES-192\n"
       << "PARAMETERS: |m|=128 |k|=192 |n|=12" << endl ;
	m128 = hexTo<bitset<128> >("6bc1bee22e409f96e93d7e117393172a") ;
	k192 = hexTo<bitset<192> >("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b") ;
	//k192 = hexTo<bitset<192> >("000102030405060708090a0b0c0d0e0f1011121314151617") ;
	cout << "       k = " << bitsetToHex(k192) << endl ;
	c128 = aes_192_12.encode(m128,k192) ;
	cout << "       m = " << bitsetToHex(m128) << endl ;
	cout << "Enc(m,k) = " << bitsetToHex(c128) << endl ;
	cout << "Dec(c,k) = " << bitsetToHex(aes_192_12.decode(c128,k192)) << endl ;

	////////////////////////////////////////////////////////////////////////////

	AES_256_14 aes_256_14 ;

  AES_256_14::msgType m256 ;
  AES_256_14::keyType k256 ;
  AES_256_14::msgType c256 ;

	cout << "----------------------------------------------------" << endl ;
	cout << "AES-256\n"
       << "PARAMETERS: |m|=128 |k|=256 |n|=14" << endl ;
	m256 = hexTo<bitset<128> >("6bc1bee22e409f96e93d7e117393172a") ;
	//k256 = hexTo<bitset<256> >("0000000000000000000000000000000000000000000000000000000000000000") ;
	k256 = hexTo<bitset<256> >("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4") ;
	cout << "       k = " << bitsetToHex(k256) << endl ;
	c256 = aes_256_14.encode(m256,k256) ;
	cout << "       m = " << bitsetToHex(m256) << endl ;
	cout << "Enc(m,k) = " << bitsetToHex(c256) << endl ;
	cout << "Dec(c,k) = " << bitsetToHex(aes_256_14.decode(c256,k256)) << endl ;

	////////////////////////////////////////////////////////////////////////////


	return 0 ;
}

