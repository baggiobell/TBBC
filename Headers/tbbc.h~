/**************************/
/* Emanuele Bellini, 2012 */
/**************************/

#ifndef TBBC_H
#define TBBC_H

#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <iomanip> // to use the function setw()
#include <bitset> // to use the bitset class
#include <vector>

#include <math.h>

#include <sstream>

#include "myFunctions.h"


#ifndef ASSERT1
  #include <sstream>
  #define ASSERT1(COND,MSG)                                     \
    if ( !(COND) ) {                                            \
      std::ostringstream ost ;                                  \
      ost << "\n--------------------------------------------"   \
          << "\nfile: " << __FILE__                             \
          << "\nline: " << __LINE__                             \
          << '\n' << MSG << '\n'                                \
          << "\n--------------------------------------------" ; \
      throw std::runtime_error(ost.str()) ;                     \
    }
#endif

#ifndef ASSERT
  #define ASSERT(COND,MSG)                                       \
    if ( !(COND) ) {                                             \
      cerr << "\n--------------------------------------------"   \
           << "\nfile: " << __FILE__                             \
           << "\nline: " << __LINE__                             \
           << '\n' << MSG << '\n'                                \
           << "\n--------------------------------------------" ; \
      exit(1) ;                                                  \
    }
#endif


using namespace std;

//! TBBC CLASS
/*!
This class allows to instantiate a block cipher working on nb_msg bits, 
with a master key of nb_key bits, whose s-boxes take input of nb_sbox bits, 
and with nround rounds.
*/
template <unsigned nb_msg, unsigned nb_key, unsigned nb_sbox, unsigned nround>
class TBBC {
  public:
    /*! Is the type of a message string (eg, bitset<128>, bitset<24>, etc..) */
    typedef bitset<nb_msg>       msgType ;
    /* ! Is the type of a key string (eg, bitset<256>, bitset<128>, etc..) */
    typedef bitset<nb_key>       keyType ;

    /*! Is the type of a message string which is input into the sBox 
       (e.g., bitset<8>, bitset<6>, etc..) */
    typedef bitset<nb_sbox>     sboxType ;
    /*! Is the type of a word string, 
        used in the keyschedule or in the mixing layer 
       (e.g., bitset<128*4>, etc..)*/
    typedef bitset<nb_sbox*4>     wordType ;
    /*! Is the type of the vector containing the round keys */
    typedef vector<msgType> roundkeyType ;

    //! Contains the round keys
    roundkeyType rk;

    // CONSTRUCTORS
    TBBC() ;

    // Print functions
    void printParameter() ;

    // CODING FUNCTIONS
    virtual msgType encode( msgType m, keyType k ) ;
    virtual msgType decode( msgType m, keyType k ) ;

  protected:

    //se le metto protected non posso testarle??

    // ROUND FUNCTIONS
    // Sbox
    //   virtual ... " = 0 " means declared as pure virtual, 
    //   i.e. it will always be declared in class inheriting from this class
    // EX:
    // virtual sboxType sbox( unsigned nbox, sboxType x ) = 0 ; 
    virtual sboxType sbox( unsigned nbox, sboxType x ) ; 
    virtual sboxType sboxInverse( unsigned nbox, sboxType x ) ;

    virtual msgType sBox (msgType m) ; // sBox based on sbox
    virtual msgType sBoxInverse (msgType m)  ; // sBox based on sbox

    // Mixing layer
    virtual msgType mixingLayer (msgType m ) ;
    virtual msgType mixingLayerInverse (msgType m ) ;

    //Add round key
    virtual msgType addRoundKey (msgType m, msgType k) ;


    // KEY SCHEDULE
    virtual void keySchedule(keyType k) ;

  public:
    // MISC FUNCTIONS
    sboxType extractBlock           ( unsigned nblk, msgType x ) ;
    sboxType extractKeyBlock        ( unsigned nblk, keyType x ) ;
    sboxType extractFromWordToSboxType ( unsigned pos, wordType x ) ;
    msgType  insertBlock            ( msgType m, unsigned nblk, sboxType x ) ;
    msgType  copyIntoRoundKey       ( msgType m, unsigned pos, wordType x) ;
    wordType copyIntoWord           ( wordType m, unsigned pos, sboxType x) ;
    wordType extractWord            ( unsigned pos, keyType x ) ;
} ;

#include "tbbc.hxx"

#endif

