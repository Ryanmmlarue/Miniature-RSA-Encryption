// 
// file: mirsa_lib.h 
// description:
//    This is the interface for the miniature RSA library, mirsa_lib.
// author: CS@RIT.EDU
// since: 2020
//
// // // // // // // // // // // // // // // // // // // // // // // // 

#ifndef MIRSA_LIB_H
#define MIRSA_LIB_H

// system headers required by functions in this interface.

#include <stdint.h>     // uint64_t typedef
#include <stdbool.h>    // bool type
#include <limits.h>

#ifdef __APPLE__
// The compiler ignores this unless you're compiling on a Mac...
// macos has a different typedef for uint64_t, and
// a redefinition provides compilation compatibility.
#undef uint64_t
#define uint64_t    unsigned long int
#endif // __APPLE__


/// key_t is a typedef for struct key_s, a (key, nonce) pair.

typedef struct key_s {
    uint64_t key;           ///< public or private key, depending on instance
    uint64_t nonce;         ///< nonce portion of the key value
} key_t;


/// mr_verbose( bool value ) sets a flag to print diagnostic information.
/// Verbose content prints to stdout.
/// @param value boolean value; false turns verbose off. true turns verbose on.
/// @return old value of verbose

bool mr_verbose( bool value );


/// mr_make_keys makes public and private key values and key files.
/// Product of p and q defines the maximum length of an encryptable message.
/// make keys and create key files or fail if (p, q) cannot work.
///
/// @param p prime number for key generation
/// @param q prime number for key generation
/// @param user string that will be the 'user' in 'user.pub' file name
///
/// @return true for success, false if keyset construction failed
///
/// @pre user must be a non-NULL, NUL-terminated C string.
/// @pre the product p * q must be less than or equal to ULONG_MAX
///
/// @post on success, function created the files 'user.pub' and 'user.pvt'
/// @post on failure, preexisting files 'user.pub' and 'user.pvt' are unchanged
///
/// @see limits.h for the maximum

bool mr_make_keys( uint64_t p, uint64_t q, const char * user );


/// mr_read_keyfile reads a keypair from the specified file.
/// The result is a key structure on the heap or NULL on failure.
///
/// The caller is responsible for freeing the key object when finished.
///
/// @param file_name the string file name of a miRSA key file
///
/// @return a pointer to a heap-allocated key object or NULL on error
///
/// @pre The file name must be a non-NULL, NUL-terminated C string.
/// @pre The file name must end either in '.pvt' or '.pub'

key_t * mr_read_keyfile( const char * file_name );


/// mr_encrypt( p, pubkey) uses pubkey to encrypt the message encoded in p.
/// Encrypt the encoded message, p, using public key pair pubkey(e, n).
///
/// @param p an unsigned long value representing an encoded message
/// @param pubkey a pointer to a pubkey
/// @return encrypted cipher, c, representing p, or 0 for failure to encrypt
///
/// @pre The value of p must be less than the nonce, n, to succeed, and
///      a value of p >= n produces a value of 0.
///
/// Output "error: mr_encrypt: ..." to stderr to report an error.
/// an example error could be that the code doesn't fit into uint64_t.
///
/// Encryption uses the GNU extensions for checking numerical overflow.
/// @see https://gcc.gnu.org/onlinedocs/gcc/Integer-Overflow-Builtins.html

uint64_t mr_encrypt( uint64_t p, const key_t * pubkey);


/// mr_decrypt( c, pvtkey)
/// Decrypt the encrypted cipher, c, using the private key pair pvtkey(d, n).
///
/// @param c an unsigned long value representing an encrypted cipher
/// @param pvtkey a pointer to a pvtkey
/// @return decrypted value, p, that represents c
///
/// @pre c must have been created using the corresponding public key.
/// @pre c must be less than the nonce, n, in the pvtkey object.
///
/// Output "error: mr_decrypt: ..." to stderr to report an error.
///
/// Uses GNU extensions for checking numerical overflow.
/// @see https://gcc.gnu.org/onlinedocs/gcc/Integer-Overflow-Builtins.html

uint64_t mr_decrypt( uint64_t c, const key_t * pvtkey);


/// mr_encode( const char * st) converts string to an unsigned long code.
/// mr_encode uses a simple, left-to-right encoding.
/// mr_encode simply converts the string to a hexadecimal 'string' that
/// has two hexadecimal 'digits' per character, and
/// returns that string as an unsigned long integer.
///
/// @param st a NUL-terminated, string to encode
/// @return an unsigned long value representing the string as a number
///
/// @pre st is non-NULL and NUL-terminated
///
/// Output "error: mr_encode: ..." to stderr to report an error.
/// an example error could be that the code doesn't fit in uint64_t.

uint64_t mr_encode( const char * st);


/// mr_decode( code) converts an unsigned code to string.
/// mr_decode simply converts the code back to its original string.
///
/// The caller is responsible for freeing the string object when finished.
///
/// @param code an unsigned, encoded value previously produced by mr_encode
/// @return a pointer to the resulting C string, a heap-allocated value
///
/// @pre code is an unsigned, encoded value previously produced by mr_encode
///
/// Output "error: mr_decode: ..." to stderr to report an error.
/// an example error could be an overflow processing the code.

char * mr_decode( uint64_t code);


#endif // MIRSA_LIB_H

// // // // // // // // // // // // // // // // // // // // // // // //
// Revisions:
// See 'git log' in repo named miRSA

