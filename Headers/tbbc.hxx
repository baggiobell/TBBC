/**************************/
/* Emanuele Bellini, 2012 */
/**************************/

////////////////////////////////////////////////////
//////VIRTUAL//METHODS//OF//THE//BASE//CLASS////////
////////////////////////////////////////////////////

////////////////
//CONSTRUCTORS//
////////////////

/*!
Allocate the space needed to fill a vector containing all the round keys.
*/
template <unsigned nb_msg, unsigned nb_key, unsigned nb_sbox, unsigned nround, unsigned sboxid>
inline
TBBC<nb_msg, nb_key, nb_sbox, nround, sboxid>::TBBC(){
  rk.resize(nround+1) ; // allocates memory for the round keys
}


/////////////////////////////////////////////////
////////////////MISC//FUNCTIONS//////////////////
/////////////////////////////////////////////////

//!Print to the terminal the current parameters of the block cipher.
template <unsigned nb_msg, unsigned nb_key, unsigned nb_sbox, unsigned nround, unsigned sboxid>
inline
void
TBBC<nb_msg, nb_key, nb_sbox, nround, sboxid>::printParameter() {
  std::cout << "-------------------------------\n" ;
  std::cout << "|  TBBC's PARAMETERS are:  " << setw (5) <<            "|\n" ;
  std::cout << "|       S-box size:      "   << setw (5) << nb_sbox << "|\n" ;
  std::cout << "|       Message size:    "   << setw (5) << nb_msg  << "|\n" ;
  std::cout << "|       Key size:        "   << setw (5) << nb_key  << "|\n" ;
  std::cout << "|       Number of Rounds:"   << setw (5) << nround  << "|\n" ;
  std::cout << "-------------------------------\n" ;
}

/*!
Extracts nb_sbox from a msgType x, i.e. extracts the block number nblk 
(block 0 is the rightmost) from x.
*/
/*!
Extracts nb_sbox bits in position [nblk*nb_sbox..nblk*nb_sbox + nb_sbox-1] 
from a string of type msgType and insert them in a string of type sboxType.

Exits from program if the position pos is negative or greater 
then the size of msgType minus the size of sboxType.
*/
template <unsigned nb_msg, unsigned nb_key, unsigned nb_sbox, unsigned nround, unsigned sboxid>
inline
typename TBBC<nb_msg, nb_key, nb_sbox, nround, sboxid>::sboxType
TBBC<nb_msg, nb_key, nb_sbox, nround, sboxid>::extractBlock( unsigned nblk, msgType x ) {
  sboxType y ;
  for ( unsigned i = 0 ; i < nb_sbox ; ++i) y[i] = x[i+nblk*nb_sbox] ;
  return y ;
}

/*!
Extracts nb_sbox from a keyType x, i.e. extracts the block number nblk 
(block 0 is the rightmost) from x.
*/
/*!
Extracts nb_sbox bits in position [nblk*nb_sbox..nblk*nb_sbox + nb_sbox-1] 
from a string of type keyType and insert them in a string of type sboxType.

Exits from program if the position pos is negative or greater 
then the size of keyType minus the size of sboxType.
*/
template <unsigned nb_msg, unsigned nb_key, unsigned nb_sbox, unsigned nround, unsigned sboxid>
inline
typename TBBC<nb_msg, nb_key, nb_sbox, nround, sboxid>::sboxType
TBBC<nb_msg, nb_key, nb_sbox, nround, sboxid>::extractKeyBlock( unsigned nblk, keyType x ) {
  sboxType y ;
  for ( unsigned i = 0 ; i < nb_sbox ; ++i) y[i] = x[i+nblk*nb_sbox] ;
  return y ;
}

/*! Extracts from word of type wordType nb_sbox bits and return 
them as an sboxType.
*/
template <unsigned nb_msg, unsigned nb_key, unsigned nb_sbox, unsigned nround, unsigned sboxid>
inline
typename TBBC<nb_msg, nb_key, nb_sbox, nround, sboxid>::sboxType
TBBC<nb_msg, nb_key, nb_sbox, nround, sboxid>::extractFromWordToSboxType( unsigned pos, wordType x ) {
  sboxType y ;
  ASSERT( pos <= (x.size() - y.size()) && pos >= 0,
    "Error: trying to extract from a position which is not allowed!" ) ;
  // this is because x[0] refers to the rightmost bit
  pos = x.size() - pos - y.size() ; 
  // std::copy( x.begin() + pos, x.begin() + pos + y.size(), y.begin() ) ;
  for ( unsigned i = 0 ; i < y.size() ; ++i) y[i] = x[i+pos] ;
  return y ;
}

/*! 
Copies the bitset x in m in the block nblk of m 
(to copy a string fitting the sbox size into a message).
*/
/*!
- INPUT: a message m of type msgType, 
         the position pos where to start the copy, 
         the part x of the message to be copied of type sboxType.

- OUTPUT: the new copy of m.
*/
template <unsigned nb_msg, unsigned nb_key, unsigned nb_sbox, unsigned nround, unsigned sboxid>
inline
typename TBBC<nb_msg, nb_key, nb_sbox, nround, sboxid>::msgType
TBBC<nb_msg, nb_key, nb_sbox, nround, sboxid>::insertBlock( msgType m, unsigned nblk, sboxType x ) {
  for (unsigned i = 0 ; i < nb_sbox ; ++i ) m[i+nblk*nb_sbox] = x[i] ;
  return m;
}

//!Copies the bitset x in m at position pos (to copy a word into a key).
/*!
- INPUT: a key m of type keyType, the position pos where to start the copy, 
         the part x of the message to be copied of type wordType.

- OUTPUT: the new copy of m.
*/
template <unsigned nb_msg, unsigned nb_key, unsigned nb_sbox, unsigned nround, unsigned sboxid>
inline
typename TBBC<nb_msg, nb_key, nb_sbox, nround, sboxid>::msgType
TBBC<nb_msg, nb_key, nb_sbox, nround, sboxid>::copyIntoRoundKey(msgType m, unsigned pos, wordType x){
  // this is because x[0] refers to the rightmost bit
  pos = m.size() - pos - x.size() ; 
  for (unsigned i = 0 ; i < x.size() ; ++i ) m[i+pos] = x[i] ;
  return m;
}

//! Copies the bitset x in m at position pos (to copy a word into a message).
/*!
- INPUT: a message m of type msgType, 
         the position pos where to start the copy, 
         the part x of the message to be copied of type wordType.

- OUTPUT: the new copy of m.
*/

template <unsigned nb_msg, unsigned nb_key, unsigned nb_sbox, unsigned nround, unsigned sboxid>
inline
typename TBBC<nb_msg, nb_key, nb_sbox, nround, sboxid>::wordType
TBBC<nb_msg, nb_key, nb_sbox, nround, sboxid>::copyIntoWord(wordType m, unsigned pos, sboxType x){
  // this is because x[0] refers to the rightmost bit
  pos = m.size() - pos - x.size() ; 
  for (unsigned i = 0 ; i < x.size() ; ++i ) m[i+pos] = x[i] ;
  return m;
}

//! Extract a word of 32 bits from a keyType element.
/*!
- INPUT: a key x, and the position pos which indicates 
         where the extraction has to be made.

- OUTPUT: a string y of 32 bits.
*/
template <unsigned nb_msg, unsigned nb_key, unsigned nb_sbox, unsigned nround, unsigned sboxid>
inline
typename TBBC<nb_msg, nb_key, nb_sbox, nround, sboxid>::wordType
TBBC<nb_msg, nb_key, nb_sbox, nround, sboxid>::extractWord( unsigned pos, keyType x ) {
  wordType y ;
  ASSERT( pos <= (x.size() - y.size()) && pos >= 0,
    "Error: trying to extract from a position which is not allowed!" ) ;
  // this is because x[0] refers to the rightmost bit
  pos = x.size() - pos - y.size() ; 
  // std::copy( x.begin() + pos, x.begin() + pos + y.size(), y.begin() ) ;
  for ( unsigned i = 0 ; i < y.size() ; ++i) y[i] = x[i+pos] ;
  return y ;
}


//////////////////////////////////
///////ENCODING//FUNCTIONS////////
//////////////////////////////////

//!Encoding function for TBBC block cipher.
/*!
- INPUT: a message m of type msgType (a bitset of dimension N) and 
         a key k of type keyType (a bitset of dimension M).

- OUTPUT: an (encrypted) message c of the same type as m.
*/
template <unsigned nb_msg, unsigned nb_key, unsigned nb_sbox, unsigned nround, unsigned sboxid>
inline
typename TBBC<nb_msg, nb_key, nb_sbox, nround, sboxid>::msgType
TBBC<nb_msg, nb_key, nb_sbox, nround, sboxid>::encode( msgType m, keyType k ) {
  msgType c ;
  c = m ;

  keySchedule(k) ;

  //Round 0, a-tipical
  c = addRoundKey(c,rk[0]) ;
  //cout << "state at round: 0 --> " << bitsetToHex(c) << endl ;
  //Tipical rounds
  for (unsigned i = 1 ; i <= nround ; ++i){
    c = sBox(c) ;
    //cout << "state after sBox: --> " << bitsetToHex(c) << endl ;
    c = mixingLayer(c) ;
    //cout << "state after mixL: --> " << bitsetToHex(c) << endl ;
    c = addRoundKey(c,rk[i]) ;
    //cout << "state at round: " << i <<  " --> " << bitsetToHex(c) << endl ;
  }

  return c ;
}


//!Decoding function for TBBC block cipher.
/*!
- INPUT: a message m of type msgType (a bitset of dimension N) and 
         a key k of type keyType (a bitset of dimension M).

- OUTPUT: an (decrypted) message c of the same type as m.
*/
template <unsigned nb_msg, unsigned nb_key, unsigned nb_sbox, unsigned nround, unsigned sboxid>
inline
typename TBBC<nb_msg, nb_key, nb_sbox, nround, sboxid>::msgType
TBBC<nb_msg, nb_key, nb_sbox, nround, sboxid>::decode (msgType m, keyType k) {
  msgType c ;
  c = m ;

  keySchedule(k) ;

  keySchedule(k) ;
  //Tipical rounds
  for (unsigned i = nround ; i > 0 ; --i){
    c = addRoundKey(c,rk[i]) ;
    c = mixingLayerInverse(c) ;
    c = sBoxInverse(c) ;
  }
  //Round 0, a-tipical
  c = addRoundKey(c,rk[0]) ;

  return c ;
}

//////////////////////////////////////////////
///////////////KEY-SCHEDULE///////////////////
//////////////////////////////////////////////

//!Key-Schedule STEP - Bunny's style.
/*!
Empty function
*/
template <unsigned nb_msg, unsigned nb_key, unsigned nb_sbox, unsigned nround, unsigned sboxid>
inline
void TBBC<nb_msg, nb_key, nb_sbox, nround, sboxid>::keySchedule(keyType k) {

}



///////////////////////////////
////// TBBC Add Round Key//////
///////////////////////////////

//!Add round key STEP.
/*!
Identity function
*/
template <unsigned nb_msg, unsigned nb_key, unsigned nb_sbox, unsigned nround, unsigned sboxid>
inline
typename TBBC<nb_msg, nb_key, nb_sbox, nround, sboxid>::msgType
TBBC<nb_msg, nb_key, nb_sbox, nround, sboxid>::addRoundKey (msgType m, msgType k){
  return m ;
  //return m ^ k;
}

////////////////////////////////
////// TBBC Nonlinear Step//////
////////////////////////////////

//!TBBC S-box STEP.
/*!
Identity function
*/
template <unsigned nb_msg, unsigned nb_key, unsigned nb_sbox, unsigned nround, unsigned sboxid>
inline
typename TBBC<nb_msg, nb_key, nb_sbox, nround, sboxid>::msgType
TBBC<nb_msg, nb_key, nb_sbox, nround, sboxid>::sBox (msgType m){
  msgType  c = m ;

  return c;
}

//!TBBC S-box Inverse STEP.
/*!
Identity function
*/
template <unsigned nb_msg, unsigned nb_key, unsigned nb_sbox, unsigned nround, unsigned sboxid>
inline
typename TBBC<nb_msg, nb_key, nb_sbox, nround, sboxid>::msgType
TBBC<nb_msg, nb_key, nb_sbox, nround, sboxid>::sBoxInverse (msgType m){
  msgType  c = m ;

  return c;
}

//! S-box table
/*!
Identity function
*/
template <unsigned nb_msg, unsigned nb_key, unsigned nb_sbox, unsigned nround, unsigned sboxid>
inline
typename TBBC<nb_msg, nb_key, nb_sbox, nround, sboxid>::sboxType
TBBC<nb_msg, nb_key, nb_sbox, nround, sboxid>::sbox(unsigned nbox, sboxType x) {

  return x ;
}

//! Inverse of the sbox
/*!
Identity function
*/
template <unsigned nb_msg, unsigned nb_key, unsigned nb_sbox, unsigned nround, unsigned sboxid>
inline
typename TBBC<nb_msg, nb_key, nb_sbox, nround, sboxid>::sboxType
TBBC<nb_msg, nb_key, nb_sbox, nround, sboxid>::sboxInverse(unsigned nbox, sboxType x) {

  return x ;
}
////////////////////////////////
//////// TBBC Linear Step///////
////////////////////////////////

//!TBBC Mixing Layer STEP.
/*!
Identity function
*/
template <unsigned nb_msg, unsigned nb_key, unsigned nb_sbox, unsigned nround, unsigned sboxid>
inline
typename TBBC<nb_msg, nb_key, nb_sbox, nround, sboxid>::msgType
TBBC<nb_msg, nb_key, nb_sbox, nround, sboxid>::mixingLayer (msgType m){
  msgType  c = m ;

  return c;
}

//!TBBC Mixing Layer Inverse STEP.
/*!
Identity function
*/
template <unsigned nb_msg, unsigned nb_key, unsigned nb_sbox, unsigned nround, unsigned sboxid>
inline
typename TBBC<nb_msg, nb_key, nb_sbox, nround, sboxid>::msgType
TBBC<nb_msg, nb_key, nb_sbox, nround, sboxid>::mixingLayerInverse (msgType m){
  msgType  c = m ;

  return c;

}

