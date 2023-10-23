#ifndef __AES_GCM_H__
#define __AES_GCM_H__
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
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::AuthenticatedDecryptionFilter;

#include "cryptopp/aes.h"
using CryptoPP::AES;

#include "cryptopp/gcm.h"
using CryptoPP::GCM;

#include "cryptopp/secblock.h"
using CryptoPP::SecByteBlock;

class GCM_alter{
public:
	GCM_alter(){}
	string encrypt(const string &plain, string skey, string siv){
		string cipher;
		SecByteBlock key(reinterpret_cast<const CryptoPP::byte*>(&skey[0]), skey.size());
		SecByteBlock iv(reinterpret_cast<const CryptoPP::byte*>(&siv[0]), siv.size());
		GCM< AES >::Encryption e;
		e.SetKeyWithIV(key, key.size(), iv, iv.size());
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
		SecByteBlock iv(reinterpret_cast<const CryptoPP::byte*>(&siv[0]), siv.size());
		GCM< AES >::Decryption d;
		d.SetKeyWithIV(key, key.size(), iv, iv.size());
		StringSource s(cipher, true, 
			new AuthenticatedDecryptionFilter(d,
				new StringSink(recovered)
			)    
		); 
		return recovered;
	}
};

#endif
