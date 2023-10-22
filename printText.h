#ifndef __printText_H__
#define __printText_H__
#include <iostream>
#include <string>
using namespace std;

#include "cryptopp/base64.h"
using CryptoPP::Base64Encoder;
using CryptoPP::Base64Decoder;

#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "cryptopp/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;

#include "cryptopp/modes.h"
using CryptoPP::CBC_Mode;

#include "cryptopp/secblock.h"
using CryptoPP::SecByteBlock;

string printHex(const string &str){
	string encoded;
	encoded.clear();
	StringSource(str, true, 
			new HexEncoder(
				new StringSink(encoded)
			) // StreamTransformationFilter      
		);
	return encoded;
}

string printHex(const CryptoPP::byte *str){
	string encoded;
	encoded.clear();
	StringSource(str, sizeof(str), true, 
			new HexEncoder(
				new StringSink(encoded)
			) // StreamTransformationFilter      
		);
	return encoded;
}

string printHex(const SecByteBlock &str){
	string encoded;
	encoded.clear();
	StringSource(str, str.size(), true, 
			new HexEncoder(
				new StringSink(encoded)
			) // StreamTransformationFilter      
		);
	return encoded;
}

string printBase64(const string &str){
	string encoded;
	encoded.clear();
	StringSource(str, true, 
			new Base64Encoder(
				new StringSink(encoded)
			) // StreamTransformationFilter      
		);
	return encoded;
}

string printBase64(const CryptoPP::byte *str){
	string encoded;
	encoded.clear();
	StringSource(str, sizeof(str), true, 
			new Base64Encoder(
				new StringSink(encoded)
			) // StreamTransformationFilter      
		);
	return encoded;
}

string printBase64(const SecByteBlock &str){
	string encoded;
	encoded.clear();
	StringSource(str, str.size(), true, 
			new Base64Encoder(
				new StringSink(encoded)
			) // StreamTransformationFilter      
		);
	return encoded;
}

#endif