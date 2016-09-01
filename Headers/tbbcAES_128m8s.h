/**************************/
/* Emanuele Bellini, 2012 */
/**************************/

#include "tbbc.h"

//!TBBCAES CLASS
/*!
This class inherits the methods from TBBC class, 
and specifies the virtual methods which are different from TBBC's.

TBBCAES allows to instantiate a block cipher as AES working on 128 bits, 
with a master key of nb_key bits, whose s-box take input of 8 bits, 
and with nround rounds.
*/
template <unsigned nb_key, unsigned nround>
class TBBCAES : public TBBC<128,nb_key,8,nround> {
public:

  typedef TBBC<128,nb_key,8,nround> TBBC128_8 ;

  typedef typename TBBC128_8::msgType      msgType ;
  typedef typename TBBC128_8::keyType      keyType ;
  typedef typename TBBC128_8::sboxType     sboxType ;
  typedef typename TBBC128_8::wordType     wordType ;
  typedef typename TBBC128_8::roundkeyType roundkeyType ;

private:
  //! Contains the round keys
  roundkeyType rk;
  bitset<32> rcon[16] ; // Constant assigned to each keyschedule round

public:
  // CONSTRUCTORS
  TBBCAES() ;

  // CODING FUNCTIONS
  virtual msgType encode(msgType m, keyType k) ;
  virtual msgType decode(msgType m, keyType k) ;

private:
// if private can not be tested in main!!

  // SBOX

  virtual msgType sBox        ( msgType m ) ; // sBox based on sbox
  virtual msgType sBoxInverse ( msgType m )  ; // sBox based on sbox

  virtual sboxType sbox       ( unsigned nbox, sboxType x ) ;
  virtual sboxType sboxInverse( unsigned nbox, sboxType x ) ;

  // MIXING LAYER
  virtual msgType mixingLayer        ( msgType m )  ;
  virtual msgType mixingLayerInverse ( msgType m )  ;

  msgType shiftRows     ( msgType m ) const ;
  msgType shiftRowsInv  ( msgType m ) const ;
  msgType mixColumns    ( msgType m ) const ;
  msgType mixColumnsInv ( msgType m ) const ;

  // ADD ROUND KEY
  virtual msgType addRoundKey (msgType m, msgType k) ;

  // KEY SCHEDULE
  virtual void keySchedule(keyType k) ;

} ;

#include "tbbcAES_128m8s.hxx"
