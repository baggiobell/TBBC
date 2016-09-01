# COMPILE AND RUN WITH

cd Source
g++ -I ../Headers/ tbbc.cpp
./a.out

------------------------------------------------------------------------------

# FILES

/Source
-> tbbc.cpp
   // main

/Headers
-> tbbc.h
-> tbbc.hxx
   // define a class TBBC which implements an identity cipher

-> tbbcAES_128m8s.h
-> tbbcAES_128m8s.hxx
   // define a class which implement AES
   // - message length is fixed to 128
   // - key values can be multiple of 32 and is fixed at type definition
   // - sbox size is fixed to 8
   // - the number of rounds is fixed at type definition

-> tbbcBUNNY_24m24k.h
-> tbbcBUNNY_24m24k.hxx
   // define a class which implement BUNNY (a toy cipher) 
   // with 24 bits messages and 6 bit sbox
   // define a class which implement BUNNY
   // - message length is fixed to 24
   // - key length is fixed to  24
   // - sbox size is fixed at type definition
   // - the number of rounds is fixed at type definition

-> myFunctions.h
   // defines common functions

------------------------------------------------------------------------------

# INSTRUCTION

To define a new Translation Based Block Cipher, define the new classes in a
.h and .hxx file.
By inheriting the class TBBC, TBBCAES or TBBCBUNNY
you can define only some of the needed function, 
e.g. the sbox() and its inverse.

See headers files as an example.

//----------------------------------------------------------------------------

CLASSES SCHEME

class TBBC {
  public:
    typedef bitset<nb_msg>       msgType ;
    typedef bitset<nb_key>       keyType ;
    typedef bitset<nb_sbox>     sboxType ;
    typedef bitset<nb_sbox*4>     wordType ;
    typedef vector<msgType> roundkeyType ;
    roundkeyType rk;
    TBBC() ;
    void printParameter() ;
    virtual msgType encode( msgType m, keyType k ) ;
    virtual msgType decode( msgType m, keyType k ) ;
  protected:
    virtual sboxType sbox( unsigned nbox, sboxType x ) ; 
    virtual sboxType sboxInverse( unsigned nbox, sboxType x ) ;
    virtual msgType sBox (msgType m) ; // sBox based on sbox
    virtual msgType sBoxInverse (msgType m)  ; // sBox based on sbox
    virtual msgType mixingLayer (msgType m ) ;
    virtual msgType mixingLayerInverse (msgType m ) ;
    virtual msgType addRoundKey (msgType m, msgType k) ;
    virtual void keySchedule(keyType k) ;
  public:
    sboxType extractBlock           ( unsigned nblk, msgType x ) ;
    sboxType extractKeyBlock        ( unsigned nblk, keyType x ) ;
    sboxType extractFromWordToSboxType ( unsigned pos, wordType x ) ;
    msgType  insertBlock            ( msgType m, unsigned nblk, sboxType x ) ;
    msgType  copyIntoRoundKey       ( msgType m, unsigned pos, wordType x) ;
    wordType copyIntoWord           ( wordType m, unsigned pos, sboxType x) ;
    wordType extractWord            ( unsigned pos, keyType x ) ;
} ;

class TBBCAES : public TBBC<128,nb_key,8,nround> {
public:
  typedef TBBC<128,nb_key,8,nround> TBBC128_8 ;
  typedef typename TBBC128_8::msgType      msgType ;
  typedef typename TBBC128_8::keyType      keyType ;
  typedef typename TBBC128_8::sboxType     sboxType ;
  typedef typename TBBC128_8::wordType     wordType ;
  typedef typename TBBC128_8::roundkeyType roundkeyType ;
private:
  roundkeyType rk;
  bitset<32> rcon[16] ; // Constant assigned to each keyschedule round
public:
  TBBCAES() ;
  virtual msgType encode(msgType m, keyType k) ;
  virtual msgType decode(msgType m, keyType k) ;
private:
  virtual msgType sBox        ( msgType m ) ; // sBox based on sbox
  virtual msgType sBoxInverse ( msgType m )  ; // sBox based on sbox
  virtual sboxType sbox       ( unsigned nbox, sboxType x ) ;
  virtual sboxType sboxInverse( unsigned nbox, sboxType x ) ;
  virtual msgType mixingLayer        ( msgType m )  ;
  virtual msgType mixingLayerInverse ( msgType m )  ;
  msgType shiftRows     ( msgType m ) const ;
  msgType shiftRowsInv  ( msgType m ) const ;
  msgType mixColumns    ( msgType m ) const ;
  msgType mixColumnsInv ( msgType m ) const ;
  virtual msgType addRoundKey (msgType m, msgType k) ;
  virtual void keySchedule(keyType k) ;
} ;

class TBBCBUNNY : public TBBC<24,24,nb_sbox,nround> {
public:
  typedef TBBC<24,24,nb_sbox,nround> TBBC2424 ;
  typedef typename TBBC2424::msgType      msgType ;
  typedef typename TBBC2424::keyType      keyType ;
  typedef typename TBBC2424::sboxType     sboxType ;
  typedef typename TBBC2424::wordType     wordType ;
  typedef typename TBBC2424::roundkeyType roundkeyType ;
  roundkeyType rk;
  TBBCBUNNY() ;
  virtual msgType encode(msgType m, keyType k) ;
  virtual msgType decode(msgType m, keyType k) ;
private:
  virtual sboxType sbox( unsigned nbox, sboxType x ) ;
  virtual sboxType sboxInverse( unsigned nbox, sboxType x ) ;
  virtual msgType mixingLayer (msgType m ) ;
  virtual msgType mixingLayerInverse (msgType m ) ;
  virtual msgType addRoundKey (msgType m, msgType k) ;
  virtual void keySchedule(keyType k) ;
} ;


