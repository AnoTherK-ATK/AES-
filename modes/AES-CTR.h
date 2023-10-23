#ifndef __AES_CTR_H__
#define __AES_CTR_H__
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

#include "cryptopp/ccm.h"
using CryptoPP::CTR_Mode;

#include <assert.h>
using CryptoPP::byte;
using CryptoPP::SecByteBlock;

class CTR{
public:
	CTR(){}
	string encrypt(const string &plain, string skey, string siv){
		string cipher;
		SecByteBlock key(reinterpret_cast<const CryptoPP::byte*>(&skey[0]), skey.size());
		SecByteBlock iv(reinterpret_cast<const CryptoPP::byte*>(&siv[0]), siv.size());
		CTR_Mode< AES >::Encryption e;
		e.SetKeyWithIV(key, key.size(), iv, iv.size());
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
		SecByteBlock iv(reinterpret_cast<const CryptoPP::byte*>(&siv[0]), siv.size());
		CTR_Mode< AES >::Decryption d;
		d.SetKeyWithIV(key, key.size(), iv, iv.size());
		StringSource s(cipher, true, 
			new StreamTransformationFilter(d,
				new StringSink(recovered)
			)    
		); 
		return recovered;
	}
};
#endif
