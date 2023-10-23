#ifndef __AES_ECB_H__
#define __AES_ECB_H__

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;

#include <cstdlib>
using std::exit;

#include "cryptopp/cryptlib.h"
using CryptoPP::Exception;

#include "cryptopp/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;

#include "cryptopp/aes.h"
using CryptoPP::AES;

#include "cryptopp/modes.h"
using CryptoPP::ECB_Mode;
using CryptoPP::SecByteBlock;
using CryptoPP::byte;

class ECB{
public:
    ECB(){}

    string encrypt(const string &plain, string skey){
        string cipher;
        SecByteBlock key(reinterpret_cast<const CryptoPP::byte*>(&skey[0]), skey.size());
        ECB_Mode< AES >::Encryption e;
        e.SetKey(key, key.size());
        StringSource s(plain, true, 
            new StreamTransformationFilter(e,
                new StringSink(cipher)
            )    
        ); 
        return cipher;
    }

    string decrypt(const string &cipher, string skey){
        string recovered;
        SecByteBlock key(reinterpret_cast<const CryptoPP::byte*>(&skey[0]), skey.size());
        ECB_Mode< AES >::Decryption d;
        d.SetKey(key, key.size());
        StringSource s(cipher, true, 
            new StreamTransformationFilter(d,
                new StringSink(recovered)
            )
        ); 
        return recovered;
    }
};
#endif
