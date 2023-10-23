#ifndef __AES_XTS_H__
#define __AES_XTS_H__
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

#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "cryptopp/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;

#include "cryptopp/aes.h"
using CryptoPP::AES;

#include "cryptopp/xts.h"
using CryptoPP::XTS_Mode;

#include <assert.h>
using CryptoPP::byte;
using CryptoPP::SecByteBlock;

class XTS_alter{
public:
    XTS_alter(){}
    string encrypt(const string &plain, string skey, string siv){
        string cipher;
        SecByteBlock key(reinterpret_cast<const CryptoPP::byte*>(&skey[0]), skey.size());
        CryptoPP::byte iv[AES::BLOCKSIZE];

        memcpy(iv, siv.c_str(), sizeof(iv)); 
        XTS_Mode< AES >::Encryption e;
        e.SetKeyWithIV(key, key.size(), iv);
        StringSource s(plain, true, 
            new StreamTransformationFilter(e,
                new StringSink(cipher)
            )    
        ); 
        return cipher;
    }
    string decrypt(const string &cipher, string skey, string siv){
        string recovered;
        SecByteBlock key(reinterpret_cast<const CryptoPP::byte*>(&skey[0]), skey.size());
        CryptoPP::byte iv[AES::BLOCKSIZE];

        memcpy(iv, siv.c_str(), sizeof(iv)); 
        XTS_Mode< AES >::Decryption d;
        d.SetKeyWithIV(key, key.size(), iv);
        StringSource s(cipher, true, 
            new StreamTransformationFilter(d,
                new StringSink(recovered)
            )    
        ); 
        return recovered;
    }
};
#endif