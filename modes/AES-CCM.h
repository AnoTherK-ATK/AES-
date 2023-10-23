#ifndef __AES_CCM_H__
#define __AES_CCM_H__

#include <iostream>
using std::cout;
using std::cerr;

#include <string>
using std::string;

#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

using CryptoPP::byte;
using CryptoPP::SecByteBlock;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "cryptopp/cryptlib.h"
using CryptoPP::BufferedTransformation;
using CryptoPP::AuthenticatedSymmetricCipher;

#include "cryptopp/filters.h"
using CryptoPP::Redirector;
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::AuthenticatedDecryptionFilter;

#include "cryptopp/aes.h"
using CryptoPP::AES;

#include "cryptopp/ccm.h"
using CryptoPP::CCM;

#include <assert.h>

class CCM_alter{
public:
    CCM_alter(){}
    string encrypt(const string &plain, string skey, string siv){
        string cipher;
        SecByteBlock key(reinterpret_cast<const CryptoPP::byte*>(&skey[0]), skey.size());
        CryptoPP::byte iv[AES::BLOCKSIZE];

        memcpy(iv, siv.c_str(), sizeof(iv)); 
        CCM< AES, 8 >::Encryption e;
        e.SetKeyWithIV(key, key.size(), iv);
        e.SpecifyDataLengths( 0, plain.size(), 0 );
        StringSource s(plain, true, 
            new AuthenticatedEncryptionFilter(e,
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
        CCM< AES, 8 >::Decryption d;
        d.SetKeyWithIV(key, key.size(), iv);
        d.SpecifyDataLengths( 0, cipher.size() - 8, 0 );
        AuthenticatedDecryptionFilter df(d,
            new StringSink(recovered)
        );
        StringSource s(cipher, true, 
            new Redirector(df)
        );
        return recovered;
    }
};

#endif
