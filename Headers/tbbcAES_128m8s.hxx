/**************************/
/* Emanuele Bellini, 2012 */
/**************************/
////////////////////////////////////////
////////METHODS//FOR//AES//CLASS////////
////////////////////////////////////////

////////////////
//CONSTRUCTORS//
////////////////

/*!
Allocate the space needed to fill a vector containing all the round keys.
*/
template <unsigned nb_key, unsigned nround, unsigned sboxid>
inline
TBBCAES<nb_key, nround, sboxid>::TBBCAES(){
  rk.resize(nround+1) ; // allocates memory for the round keys
  rcon[0]  = bitset<32> (string("10001101000000000000000000000000"));
  rcon[1]  = bitset<32> (string("00000001000000000000000000000000"));
  rcon[2]  = bitset<32> (string("00000010000000000000000000000000"));
  rcon[3]  = bitset<32> (string("00000100000000000000000000000000"));
  rcon[4]  = bitset<32> (string("00001000000000000000000000000000"));
  rcon[5]  = bitset<32> (string("00010000000000000000000000000000"));
  rcon[6]  = bitset<32> (string("00100000000000000000000000000000"));
  rcon[7]  = bitset<32> (string("01000000000000000000000000000000"));
  rcon[8]  = bitset<32> (string("10000000000000000000000000000000"));
  rcon[9]  = bitset<32> (string("00011011000000000000000000000000"));
  rcon[10] = bitset<32> (string("00110110000000000000000000000000"));
  rcon[11] = bitset<32> (string("01101100000000000000000000000000"));
  rcon[12] = bitset<32> (string("11011000000000000000000000000000"));
}

//////////////////////////////////
///////ENCODING//FUNCTIONS////////
//////////////////////////////////

//! Encoding function designed for AES block cipher.
/*!
- INPUT: a message m of type msgType (a bitset of dimension N) and 
         a key k of type keyType (a bitset of dimension M).

- OUTPUT: an (encrypted) message c of the same type as m.
*/
template <unsigned nb_key, unsigned nround, unsigned sboxid>
inline
typename TBBCAES<nb_key, nround, sboxid>::msgType
TBBCAES<nb_key, nround, sboxid>::encode( msgType m, keyType k ) {
  msgType c ;
  c = m ;

  keySchedule(k) ; //use TBBCAES keyschedule

  //Round 0, a-tipical
  c = this->addRoundKey(c,rk[0]) ;
  //cout << "state at round: 0 --> " << bitsetToHex(c) << endl ;

  //TYPICAL rounds
  for (unsigned i = 1 ; i < nround ; ++i){
    //AES sBox
    c = sBox(c) ;
    //cout << "state after sBox: --> " << bitsetToHex(c) << endl ;

    // AES mixing layer
    c = shiftRows(c) ;
    c = mixColumns(c) ;
    //cout << "state after mixL: --> " << bitsetToHex(c) << endl ;

    //AES add round key
    c = this->addRoundKey(c,rk[i]) ;
    //cout << "state at round: " << i <<  " --> " << bitsetToHex(c) << endl ;
  }
  //AES sBox
  c = sBox(c) ;
  //cout << "state after sBox: --> " << bitsetToHex(c) << endl ;

  // AES mixing layer - ATYPICAL (no mixColumns)
  c = shiftRows(c) ;
  //cout << "state after mixL: --> " << bitsetToHex(c) << endl ;

  //AES add round key
  c = this->addRoundKey(c,rk[nround]) ;
  //cout << "state at round: " << nround << " --> " << bitsetToHex(c) << endl ;

  return c ;
}

//! Decoding function designed for AES block cipher.
/*!
- INPUT: a message m of type msgType (a bitset of dimension N) and 
         a key k of type keyType (a bitset of dimension M).

- OUTPUT: an (encrypted) message c of the same type as m.
*/
template <unsigned nb_key, unsigned nround, unsigned sboxid>
inline
typename TBBCAES<nb_key, nround, sboxid>::msgType
TBBCAES<nb_key, nround, sboxid>::decode( msgType m, keyType k ) {
  msgType c ;
  c = m ;
  keySchedule(k) ; //use TBBCAES keyschedule

  //Round 0, a-tipical (no mixColumns Inverse)
  c = this->addRoundKey(c,rk[nround]) ;

  // AES mixing layer - ATYPICAL (no mixColumns)
  c = shiftRowsInv(c) ;

  //AES sBox
  c = sBoxInverse(c) ;

  //TYPICAL rounds
  for (unsigned i = nround - 1 ; i > 0 ; --i){
    //AES add round key
    c = this->addRoundKey(c,rk[i]) ;

    // AES mixing layer
    c = mixColumnsInv(c) ;
    c = shiftRowsInv(c) ;

    //AES sBox
    c = sBoxInverse(c) ;
  }

  //AES add round key
  c = this->addRoundKey(c,rk[0]) ;

  return c ;
}

//////////////////////////////////////////////////
///////////////AES KEY-SCHEDULE///////////////////
//////////////////////////////////////////////////

//! Key-Schedule STEP - AES style.
/*!
- INPUT: a master key k of type keyType.

- OUTPUT: return a pointer to a vector of msgType 
          (this elements are the round key, 
          which must be the same length/type as the message).
*/
template <unsigned nb_key, unsigned nround, unsigned sboxid>
inline
void
TBBCAES<nb_key, nround, sboxid>::keySchedule(keyType k) {
  //AES128 needs 11 round keys
  //AES128 needs 13 round keys
  //AES128 needs 15 round keys
  //nround is the number of rounds without counting the first whitening
  unsigned int n, b ;
  unsigned nk ; // number of 32-bit words in the cipher key (4,6,8)
  unsigned nb ; // number of words in the state (4)
  sboxType temp ;

  unsigned icon = 1 ; // index to count the costant rcon for each round
  b = (nround+1)*16 ; // 16 bytes * 11,13,15 rounds = 176,208,240
  n = nb_key / 8 ; // nb_sbox=8 is the sbox size
  //if      ( nb_key == 128 ) n = 16 ;
  //else if ( nb_key == 192 ) n = 24 ;
  //else if ( nb_key == 256 ) n = 32 ;
  nk = nb_key / 32 ; // 4, 6, 8
  nb = 4 ;

  //number of 32-bit-words generated
  unsigned nword = (nround+1) * nb ;// (nround+1) * 4

  //i.e.: nrow round keys at a time are filled
  //unsigned ncol = nb_msg/nb_sbox ;
  //unsigned nrow = nb_msg/nb_sbox + 1 ;

  vector<wordType> w ; // w will contains 32 bits words

  w.resize(nword) ; // initialize a vector of nword elements of type sboxType, 
                    // set to 00...0

  //CREATE w, a vector of nwords words
  //put the key bits in the first 16 words
  for (unsigned i = 0 ; i < nk ; ++i) {
    w[i] = this->extractWord(i*8*4,k) ;
    //cout << "w[" << i << "] = "<< bitsetToHex(w[i]) << endl ;
  }

  for (unsigned i = nk ; i < nword ; ++i){
    w[i] = w[i-1] ;
    if ( i % nk == 0){
      //Rotate the word w[i] 8 bits to the left
      w[i] = rotLeft(w[i],8) ;
      //Apply the sBoxes to w[i]
      for (unsigned j = 0 ; j < 4 ; ++j){
        // extract nb_sbox bits starting from left to right
        temp = this->extractFromWordToSboxType( j*8, w[i]) ; 
        // elaborate the nb_sbox bits extracted
        temp = sbox(1,temp) ; 
        // put temp in the position j*8 of the message w[i]
        w[i] = this->copyIntoWord(w[i],j*8,temp) ; 
      }
      //Exor rcon[i]
      w[i] = w[i] ^ rcon[icon] ;
      ++icon ;
    }
    else if (nk > 6 && (i % nk == 4)) {
      //Apply the sBoxes to w[i]
      for (unsigned j = 0 ; j < 4 ; ++j){
        // extract nb_sbox bits starting from left to right
        temp = this->extractFromWordToSboxType( j*8, w[i]) ; 
        // elaborate the nb_sbox bits extracted
        temp = sbox(1,temp) ; 
        // put temp in the position j*8 of the message w[i]
        w[i] = this->copyIntoWord(w[i],j*8,temp) ; 
      }
    }
    //Exor w[i-nk]
    w[i] = w[i] ^ w[i-nk] ;
    //cout << "w[" << i << "] = "<< bitsetToHex(w[i]) << endl ;
  }

  //CREATE the ROUND KEYS
  for (unsigned i = 0 ; i <= nround ; ++i) {
    for (unsigned j = 0 ; j < 4 ; ++j) {
      rk[i] = this->copyIntoRoundKey(rk[i], j*32, w[i*4+j]) ;
    }
    //cout << "rk[" << i << "] = " << bitsetToHex(rk[i]) << endl ;
  }
  return ;
}

///////////////////////////////
//////TBBC Add Round Key//////
///////////////////////////////
/*!
Add round key STEP.

Sum with a round key k, which must be the same length of the message m.

- INPUT: a message m of type msgType, and a round key k of type msgType 
         (the type must be the same as the message, 
         otherwise they can't be added together)

- OUTPUT: the exor of m and k
*/
template <unsigned nb_key, unsigned nround, unsigned sboxid>
inline
typename TBBCAES<nb_key, nround, sboxid>::msgType
TBBCAES<nb_key, nround, sboxid>::addRoundKey (msgType m, msgType k){
  return m ^ k;
}

//////////////////////////////////
////////LINEAR//FUNCTIONS/////////
//////////////////////////////////

//! ShiftRows STEP.
/*!
It is AES shift rows. Works for msgType of 128 bits, grouped in a 4x4 matrix of 16 bytes.

- INPUT: a message m of type msgType.

- OUTPUT: the message m elaborated by the shiftrow step.
*/
template <unsigned nb_key, unsigned nround, unsigned sboxid>
inline
typename TBBCAES<nb_key, nround, sboxid>::msgType
TBBCAES<nb_key, nround, sboxid>::shiftRows (msgType m ) const {
  // Shift second row
  MoveBits(m, 112, 80, 8) ;
  MoveBits(m, 80, 48, 8) ;
  MoveBits(m, 48, 16, 8) ;
  // Shift third row
  MoveBits(m, 104, 40, 8) ;
  MoveBits(m, 72, 8, 8) ;
  // Shift fourth row
  MoveBits(m, 32, 0, 8) ;
  MoveBits(m, 64, 32, 8) ;
  MoveBits(m, 96, 64, 8) ;
  return m ;
}

//! ShiftRows Inverse STEP.
/*!
Does the opposite operation as the ShiftRows.
*/
template <unsigned nb_key, unsigned nround, unsigned sboxid>
inline
typename TBBCAES<nb_key, nround, sboxid>::msgType
TBBCAES<nb_key, nround, sboxid>::shiftRowsInv (msgType m ) const {
  // Shift second row
  MoveBits(m, 16, 48, 8) ;
  MoveBits(m, 80, 48, 8) ;
  MoveBits(m, 112, 80, 8) ;
  // Shift third row
  MoveBits(m, 104, 40, 8) ;
  MoveBits(m, 72, 8, 8) ;
  // Shift fourth row
  MoveBits(m, 96, 64, 8) ;
  MoveBits(m, 64, 32, 8) ;
  MoveBits(m, 32, 0, 8) ;
  return m ;
}

//!MixColumns STEP.
/*!
It is AES mix columns step. It works for 128 bits messages. 
Takes 4 bytes at a time and creates a polynomial in \f$ F_2^8 \f$; 
this is then multiplied by another polynomial in the same field.

- INPUT: a message m of type msgType.

- OUTPUT: the message m elaborated by the mix columns step.
*/
template <unsigned nb_key, unsigned nround, unsigned sboxid>
inline
typename TBBCAES<nb_key, nround, sboxid>::msgType
TBBCAES<nb_key, nround, sboxid>::mixColumns (msgType m ) const {
  unsigned char col[4] ;
  msgType c ;
  string msgStr = bitsetToHex(m) ;
  string tmp ;

  for (unsigned i = 0 ; i < 4 ; ++i){ //for each column do
    tmp.assign(msgStr,i*8,8) ;    // put in tmp a column as a string
    stringToUchar(tmp,col) ;    // put in col a column as unsigned char
    gmix_column(col) ;        // mix the column
                    // put in tmp the column mixed
    tmp.assign("") ;
    for (unsigned j = 0 ; j < sizeof(col) ; ++j)
      tmp.append(ucharToString(col[j])) ;
                    //replace the msg
    msgStr.replace(i*8,8,tmp) ;
  }
  return msgType (hexTo<bitset<128> >(msgStr)) ;
}

//! MixColumns Inverse STEP.
/*!
Inverse of the mix columns step.
*/
template <unsigned nb_key, unsigned nround, unsigned sboxid>
inline
typename TBBCAES<nb_key, nround, sboxid>::msgType
TBBCAES<nb_key, nround, sboxid>::mixColumnsInv (msgType m ) const {
  unsigned char col[4] ;
  string  msgStr = bitsetToHex(m) ;
  string tmp ;

  for (unsigned i = 0 ; i < 4 ; ++i){ //for each column do
    tmp.assign(msgStr,i*8,8) ;        // put in tmp a column as a string
    stringToUchar(tmp,col) ;          // put in col a column as unsigned char
    gmix_columnInv(col) ;             // mix the column
                                      // put in tmp the column mixed
    tmp.assign("") ;
    for (unsigned j = 0 ; j < sizeof(col) ; ++j)
      tmp.append(ucharToString(col[j])) ;

    msgStr.replace(i*8,8,tmp) ;       //replace the msg
  }
  return msgType (hexTo<bitset<128 > >(msgStr)) ;
}

//!Mixing Layer STEP.
/*!
Combinations of the ShiftRows and the MixColumns steps.

- INPUT: a message m of type msgType.

- OUTPUT: the message m elaborated by shift rows and mix columns steps.
*/
template <unsigned nb_key, unsigned nround, unsigned sboxid>
inline
typename TBBCAES<nb_key, nround, sboxid>::msgType
TBBCAES<nb_key, nround, sboxid>::mixingLayer (msgType m ) {
  msgType c ;
  c = m ;
  c = shiftRows(c) ;
  c = mixColumns(c) ;
  return c ;
}

//!Mixing Layer Inverse STEP.
/*!
Combinations of the MixColumnsInverse and the ShiftRowsInverse steps.

- INPUT: a message m of type msgType.

- OUTPUT: the message m elaborated by the inverse of mix columns and then the inverse of shift rows steps.
*/
template <unsigned nb_key, unsigned nround, unsigned sboxid>
inline
typename TBBCAES<nb_key, nround, sboxid>::msgType
TBBCAES<nb_key, nround, sboxid>::mixingLayerInverse (msgType m ) {
  msgType c ;
  c = m ;
  c = mixColumnsInv(c) ;
  c = shiftRowsInv(c) ;
  return c ;
}

////////////////////////////////
///////AES Nonlinear Step///////
////////////////////////////////

//! AES S-box STEP.
/*!
This function receives a message and 
              applies the sboxes as many times as needed 
(it uses alwayas the same sbox table):

  m = (m_1, m_2, ..., m_3)  ===>  (sbox_1(m_1), sbox_2(m_2), ..., sbox_r(m_r))

- INPUT: a message m of type msgType.

- OUTPUT: the message m elaborated by the sbox.
*/
template <unsigned nb_key, unsigned nround, unsigned sboxid>
inline
typename TBBCAES<nb_key, nround, sboxid>::msgType
TBBCAES<nb_key, nround, sboxid>::sBox (msgType m){
  msgType c ;
  c = m ;
  sboxType s ;

  unsigned n = 16 ; // nb_msg / nb_sbox ;
  for (unsigned i = 0 ; i < n ; ++i){
    s = this->extractBlock(i,m) ; // extract nb_sbox bits starting from left to right
    //For AES
    s = sbox(1,s) ; // elaborate the nb_sbox bits extracted
    c = this->insertBlock(c,i,s) ; // put nb_bit bits in the position i*nb_sbox of the message c
  }
  return c;
}

//! AES S-box Inverse STEP.
template <unsigned nb_key, unsigned nround, unsigned sboxid>
inline
typename TBBCAES<nb_key, nround, sboxid>::msgType
TBBCAES<nb_key, nround, sboxid>::sBoxInverse (msgType m){
  msgType c ;
  c = m ;
  sboxType s ;

  unsigned n = 16 ; // nb_msg / nb_sbox ;
  for (unsigned i = 0 ; i < n ; ++i){
    s = this->extractBlock(i,m) ; // extract nb_sbox bits starting from left to right
    //For AES
    s = sboxInverse(1,s) ; // elaborate the nb_sbox bits extracted
    c = this->insertBlock(c,i,s) ; // put nb_bit bits in the position i*nb_sbox of the message c
  }
  return c;
}

//! S-box table
/*!
This function works with 8 bits.

- INPUT: an element x of type sboxType.

- OUTPUT: an element of type sboxType elaborated by the sbox.

Note: the parameter nbox is not used, but has to be inserted.
*/
template <unsigned nb_key, unsigned nround, unsigned sboxid>
inline
typename TBBCAES<nb_key, nround, sboxid>::sboxType
TBBCAES<nb_key, nround, sboxid>::sbox(unsigned nbox, sboxType x) {
  static int AES_sbox_table [2][256] = {
    { // ORIGINAL AES SBOX
       99,124,119,123,242,107,111,197, 48,  1,103, 43,254,215,171,118,
      202,130,201,125,250, 89, 71,240,173,212,162,175,156,164,114,192,
      183,253,147, 38, 54, 63,247,204, 52,165,229,241,113,216, 49, 21,
        4,199, 35,195, 24,150,  5,154,  7, 18,128,226,235, 39,178,117,
        9,131, 44, 26, 27,110, 90,160, 82, 59,214,179, 41,227, 47,132,
       83,209,  0,237, 32,252,177, 91,106,203,190, 57, 74, 76, 88,207,
      208,239,170,251, 67, 77, 51,133, 69,249,  2,127, 80, 60,159,168,
       81,163, 64,143,146,157, 56,245,188,182,218, 33, 16,255,243,210,
      205, 12, 19,236, 95,151, 68, 23,196,167,126, 61,100, 93, 25,115,
       96,129, 79,220, 34, 42,144,136, 70,238,184, 20,222, 94, 11,219,
      224, 50, 58, 10, 73,  6, 36, 92,194,211,172, 98,145,149,228,121,
      231,200, 55,109,141,213, 78,169,108, 86,244,234,101,122,174,  8,
      186,120, 37, 46, 28,166,180,198,232,221,116, 31, 75,189,139,138,
      112, 62,181,102, 72,  3,246, 14, 97, 53, 87,185,134,193, 29,158,
      225,248,152, 17,105,217,142,148,155, 30,135,233,206, 85, 40,223,
      140,161,137, 13,191,230, 66,104, 65,153, 45, 15,176, 84,187, 22 
    },
    { // EQUIVALENT SBOX-1
      0x28,0x12,0x80,0x0e,0x8d,0x5f,0x8f,0x2f,0xc6,0x2b,0xe0,0x7e,0xb0,0xe8,0x92,0xa0,
      0xcd,0xd0,0x27,0x64,0x0f,0xae,0xc3,0x9a,0x56,0x81,0x08,0x9f,0x61,0x46,0x98,0x3c,
      0xe5,0xc1,0xf7,0xf9,0x87,0x5c,0xbe,0x38,0xfb,0x14,0x71,0x84,0x0c,0x75,0xb9,0xbf,
      0x6c,0x8c,0x0d,0xab,0x97,0x86,0x99,0xf0,0x25,0x1a,0xa3,0x79,0xb4,0x1b,0xdb,0xcc,
      0xaa,0x02,0xd4,0x0b,0x1c,0x3e,0x7a,0xc5,0x35,0xb2,0xd2,0x5b,0xb7,0x06,0x2d,0x6d,
      0x29,0xf1,0xa9,0x11,0x78,0x03,0x4a,0x7f,0xd3,0x00,0x4d,0x49,0x3f,0x10,0x1e,0x01,
      0x70,0x65,0x22,0x76,0x04,0x69,0x55,0xd1,0x31,0x4e,0x39,0x7b,0xfd,0xaf,0x82,0xc7,
      0x45,0xfc,0x95,0xcf,0x9c,0xef,0x6f,0x62,0x40,0x59,0xee,0xbb,0xbd,0x1f,0xc8,0xb8,
      0x32,0x52,0x6b,0x94,0xf4,0x3a,0x21,0xd5,0xc4,0xdf,0x36,0xa6,0x77,0x89,0x34,0x50,
      0xce,0xe6,0x13,0x91,0x8a,0xb6,0x44,0xa2,0x0a,0x90,0x6a,0x5d,0x54,0x2a,0xf8,0x7d,
      0xfa,0x26,0xec,0x17,0xf2,0xf3,0x67,0x8e,0x1d,0xa7,0xd9,0xad,0x37,0xd6,0xf5,0xb1,
      0xd8,0xca,0xd7,0x43,0x57,0xe2,0x24,0x23,0xfe,0xde,0x47,0x30,0x18,0xa4,0xb3,0xe4,
      0xa5,0x96,0xdd,0x66,0x4c,0xeb,0xda,0x48,0xc9,0xe7,0xc2,0xba,0x60,0x3b,0x74,0xa8,
      0x9b,0xcb,0x83,0x4f,0x2c,0x20,0xff,0xa1,0x53,0x2e,0x7c,0xed,0x4b,0x41,0xbc,0x15,
      0x8b,0xc0,0x51,0x93,0x9d,0x5a,0x9e,0x88,0x73,0x09,0x85,0x33,0xf6,0x42,0xe1,0x6e,
      0x58,0x05,0x07,0xe3,0x16,0xb5,0xac,0x63,0x3d,0xe9,0xdc,0x72,0x5e,0x68,0x19,0xea
    }
  } ;
  return sboxType ( AES_sbox_table[sboxid][x.to_ulong()] );
}

//! Inverse of the sbox
/*!
This function works with 8 bits.

- INPUT: an element x of type sboxType.

- OUTPUT: an element of type sboxType elaborated by the inverse of the sbox function.

Note: the parameter nbox is not used, but has to be inserted.
*/
template <unsigned nb_key, unsigned nround, unsigned sboxid>
inline
typename TBBCAES<nb_key, nround, sboxid>::sboxType
TBBCAES<nb_key, nround, sboxid>::sboxInverse(unsigned nbox, sboxType x) {
  static int AES_sbox_Inv_table [2][256] = {
    { // ORIGINAL AES SBOX
     82,  9,106,213, 48, 54,165, 56,191, 64,163,158,129,243,215,251,
    124,227, 57,130,155, 47,255,135, 52,142, 67, 68,196,222,233,203,
     84,123,148, 50,166,194, 35, 61,238, 76,149, 11, 66,250,195, 78,
      8, 46,161,102, 40,217, 36,178,118, 91,162, 73,109,139,209, 37,
    114,248,246,100,134,104,152, 22,212,164, 92,204, 93,101,182,146,
    108,112, 72, 80,253,237,185,218, 94, 21, 70, 87,167,141,157,132,
    144,216,171,  0,140,188,211, 10,247,228, 88,  5,184,179, 69,  6,
    208, 44, 30,143,202, 63, 15,  2,193,175,189,  3,  1, 19,138,107,
     58,145, 17, 65, 79,103,220,234,151,242,207,206,240,180,230,115,
    150,172,116, 34,231,173, 53,133,226,249, 55,232, 28,117,223,110,
     71,241, 26,113, 29, 41,197,137,111,183, 98, 14,170, 24,190, 27,
    252, 86, 62, 75,198,210,121, 32,154,219,192,254,120,205, 90,244,
     31,221,168, 51,136,  7,199, 49,177, 18, 16, 89, 39,128,236, 95,
     96, 81,127,169, 25,181, 74, 13, 45,229,122,159,147,201,156,239,
    160,224, 59, 77,174, 42,245,176,200,235,187, 60,131, 83,153, 97,
     23, 43,  4,126,186,119,214, 38,225,105, 20, 99, 85, 33, 12,125
    },
    { // EQUIVALENT SBOX-1
    0x59, 0x5f, 0x41, 0x55, 0x64, 0xf1, 0x4d, 0xf2, 0x1a, 0xe9, 0x98, 0x43, 0x2c, 0x32, 0x03, 0x14,
    0x5d, 0x53, 0x01, 0x92, 0x29, 0xdf, 0xf4, 0xa3, 0xbc, 0xfe, 0x39, 0x3d, 0x44, 0xa8, 0x5e, 0x7d,
    0xd5, 0x86, 0x62, 0xb7, 0xb6, 0x38, 0xa1, 0x12, 0x00, 0x50, 0x9d, 0x09, 0xd4, 0x4e, 0xd9, 0x07,
    0xbb, 0x68, 0x80, 0xeb, 0x8e, 0x48, 0x8a, 0xac, 0x27, 0x6a, 0x85, 0xcd, 0x1f, 0xf8, 0x45, 0x5c,
    0x78, 0xdd, 0xed, 0xb3, 0x96, 0x70, 0x1d, 0xba, 0xc7, 0x5b, 0x56, 0xdc, 0xc4, 0x5a, 0x69, 0xd3,
    0x8f, 0xe2, 0x81, 0xd8, 0x9c, 0x66, 0x18, 0xb4, 0xf0, 0x79, 0xe5, 0x4b, 0x25, 0x9b, 0xfc, 0x05,
    0xcc, 0x1c, 0x77, 0xf7, 0x13, 0x61, 0xc3, 0xa6, 0xfd, 0x65, 0x9a, 0x82, 0x30, 0x4f, 0xef, 0x76,
    0x60, 0x2a, 0xfb, 0xe8, 0xce, 0x2d, 0x63, 0x8c, 0x54, 0x3b, 0x46, 0x6b, 0xda, 0x9f, 0x0b, 0x57,
    0x02, 0x19, 0x6e, 0xd2, 0x2b, 0xea, 0x35, 0x24, 0xe7, 0x8d, 0x94, 0xe0, 0x31, 0x04, 0xa7, 0x06,
    0x99, 0x93, 0x0e, 0xe3, 0x83, 0x72, 0xc1, 0x34, 0x1e, 0x36, 0x17, 0xd0, 0x74, 0xe4, 0xe6, 0x1b,
    0x0f, 0xd7, 0x97, 0x3a, 0xbd, 0xc0, 0x8b, 0xa9, 0xcf, 0x52, 0x40, 0x33, 0xf6, 0xab, 0x15, 0x6d,
    0x0c, 0xaf, 0x49, 0xbe, 0x3c, 0xf5, 0x95, 0x4c, 0x7f, 0x2e, 0xcb, 0x7b, 0xde, 0x7c, 0x26, 0x2f,
    0xe1, 0x21, 0xca, 0x16, 0x88, 0x47, 0x08, 0x6f, 0x7e, 0xc8, 0xb1, 0xd1, 0x3f, 0x10, 0x90, 0x73,
    0x11, 0x67, 0x4a, 0x58, 0x42, 0x87, 0xad, 0xb2, 0xb0, 0xaa, 0xc6, 0x3e, 0xfa, 0xc2, 0xb9, 0x89,
    0x0a, 0xee, 0xb5, 0xf3, 0xbf, 0x20, 0x91, 0xc9, 0x0d, 0xf9, 0xff, 0xc5, 0xa2, 0xdb, 0x7a, 0x75,
    0x37, 0x51, 0xa4, 0xa5, 0x84, 0xae, 0xec, 0x22, 0x9e, 0x23, 0xa0, 0x28, 0x71, 0x6c, 0xb8, 0xd6
    }
  } ;
  return sboxType ( AES_sbox_Inv_table[sboxid][x.to_ulong()] );
}

