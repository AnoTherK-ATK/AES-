//C internal library
#include <bits/stdc++.h>

using std::wcin;
using std::wcout;
using std::wcerr;
using std::endl;
#include <string>
using std::string;
using std::wstring;
#include <cstdlib>
using std::exit;
#include <assert.h>

//Cryptopp Librari
#include <cryptopp/files.h>
using CryptoPP::FileSource;
using CryptoPP::FileSink;
using CryptoPP::BufferedTransformation;

#include "cryptopp/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::Redirector; // string to bytes

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::byte;

#include "cryptopp/cryptlib.h"
using CryptoPP::Exception;

// convert string
// Hex <---> Binary
#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

// Base64 <---> Binary
#include "cryptopp/base64.h"
using CryptoPP::Base64Encoder;
using CryptoPP::Base64Decoder;

// Block cipher
#include "cryptopp/des.h"
using CryptoPP::DES;
#include "cryptopp/aes.h"
using CryptoPP::AES;

//Mode of operations
#include "cryptopp/modes.h" //ECB, CBC, CBC-CTS, CFB, OFB, CTR
using CryptoPP::ECB_Mode;
using CryptoPP::CBC_Mode;
using CryptoPP::CFB_Mode;
using CryptoPP::OFB_Mode;
using CryptoPP::CTR_Mode;
#include "cryptopp/xts.h"
using CryptoPP::XTS;
#include "cryptopp/ccm.h"
using CryptoPP::CCM;
#include "cryptopp/gcm.h"
using CryptoPP::GCM;
//Ref: more here https://www.cryptopp.com/wiki/AEAD_Comparison

#include "textProcess.h"
#include "modes/AES-ECB.h"

/* Set utf8 support for windows*/
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#else
#endif
/* Convert string <--> utf8*/
#include <locale>
using std::wstring_convert;
#include <codecvt>
using  std::codecvt_utf8;
wstring string_to_wstring (const std::string& str);
string wstring_to_string (const std::wstring& str);

#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#endif

using namespace std;
using namespace CryptoPP;

wstring string_to_wstring(const string& str);
string wstring_to_string(const wstring& str);

SecByteBlock key(AES::DEFAULT_KEYLENGTH);
CryptoPP::byte iv[AES::BLOCKSIZE];

void randomKeyIV(){
    AutoSeededRandomPool prng;
    prng.GenerateBlock(key, key.size());
    prng.GenerateBlock(iv, sizeof(iv));
}

void inputKeyIV(){
    wcout << L"Please enter the key (Base64):\n";
    wstring keywstr;
    wcin >> keywstr;
    wcin.ignore();
    string keystr = wstring_to_string(keywstr);
    keystr = Base64Decode(keystr);
    key = SecByteBlock(reinterpret_cast<const CryptoPP::byte*>(&keystr[0]), keystr.size());
    wcout << L"Please enter the iv (Base64):\n";
    wstring ivwstr;
    wcin >> ivwstr;
    wcin.ignore();
    string ivstr = wstring_to_string(ivwstr);
    ivstr = Base64Decode(ivstr);
    memcpy(iv, ivstr.c_str(), sizeof(iv));
}

wstring inputPlainMenu(){
    wcout   << "Choose the input method:\n"
            << "1. From file;\n"
            << "2. From console;\n"
            << "Please enter your number?\n";
    int mode;
    wcin >> mode;
    wcin.ignore();
    switch (mode)
    {
        case 1: {
            wcout << L"Please enter the file name?\n";
            wstring filename;
            wcin >> filename;
            wcin.ignore();
            wifstream in( wstring_to_string(filename) );
            wstring filetext;
            in >> filetext;
            return filetext;
            break;
        }
        case 2:{
            wcout << L"Please enter the plain text:\n";
            //wcin.ignore();
            wstring text;
            getline(wcin, text);
            return text;
            break;
        }

        default:{
            wcout << L"Invalid input, Please try again\n";
            return inputPlainMenu();
            break;
        }
    }
}

wstring inputCipherMenu(){
    wcout   << "Choose the input method:\n"
            << "1. From file;\n"
            << "2. From console;\n"
            << "Please enter your number?\n";
    int mode;
    wcin >> mode;
    wcin.ignore();
    switch (mode)
    {
        case 1: {
            wcout << L"Please enter the file name?\n";
            wstring filename;
            wcin >> filename;
            wcin.ignore();
            wifstream in( wstring_to_string(filename) );
            wstring filetext;
            in >> filetext;
            return filetext;
            break;
        }
        case 2:{
            wcout << L"Please enter the ciphertext (Base64):\n";

            wstring text;
            wcin >> text;
            wcin.ignore();
            return text;
            break;
        }

        default:{
            wcout << L"Invalid input, Please try again\n";
            return inputCipherMenu();
            break;
        }
    }
}

void encECB(wstring& plain, string& skey){
    ECB ecb;
    string cipher = ecb.encrypt(wstring_to_string(plain), hexDecode(skey));
    //wcout << L"cipher text: " << string_to_wstring(cipher) << endl;
    wcout << L"ciphertext (Hex): " << string_to_wstring(printHex(cipher)) << endl;
    wcout << L"ciphertext (Base64): " << string_to_wstring(printBase64(cipher)) << endl;
}

void decECB(string& cipher, string& skey){
    ECB ecb;
    cipher = Base64Decode(cipher);
    string plain = ecb.decrypt(cipher, hexDecode(skey));
    wcout << L"plain text: " << string_to_wstring(plain) << endl;
}


void encMenu(){
    wstring plain = inputPlainMenu();
    wcout   << "Choose the mode:\n"
            << "1. ECB;\n"
            << "2. CBC;\n"
            << "3. CFB;\n"
            << "4. OFB;\n"
            << "5. CTR;\n"
            << "6. XTS;\n"
            << "7. CCM;\n"
            << "8. GCM;\n"
            << "Please enter your number?\n";
    int mode;
    wcin >> mode;
    wcin.ignore();
    wcout << L"Would you like to enter key or generate random key?\n"
            << "1. Enter key;\n"
            << "2. Generate random key;\n"
            << "Please enter your number?\n";
    int keymode;
    wcin >> keymode;
    wcin.ignore();
    switch(keymode){
        case 1:{
            wcout << L"Please enter the key (Base64):\n";
            inputKeyIV();
            break;
        }
        case 2:{
            randomKeyIV();
            wcout << L"key (Hex): " << string_to_wstring(printHex(key)) << endl;
            wcout << L"iv (Hex): " << string_to_wstring(printHex(iv)) << endl;
            wcout << L"key (Base64): " << string_to_wstring(printBase64(key));
            wcout << L"iv (Base64): " << string_to_wstring(printBase64(iv));
            break;
        }
        default:
            wcout << L"Invalid input\n";
            break;
    }
    string skey = printHex(key);
    string siv = printHex(iv);
    switch(mode){
        case 1:{
            encECB(plain, skey);
            break;
        }
        default:
            wcout << L"Invalid input\n";
            break;
    }
}



void decMenu(){
    wstring cipher = inputCipherMenu();
    wcout   << "Choose the mode:\n"
            << "1. ECB;\n"
            << "2. CBC;\n"
            << "3. CFB;\n"
            << "4. OFB;\n"
            << "5. CTR;\n"
            << "6. XTS;\n"
            << "7. CCM;\n"
            << "8. GCM;\n"
            << "Please enter your number?\n";
    int mode;
    wcin >> mode;
    wcin.ignore();
    string cipherstr = wstring_to_string(cipher);
    cipherstr = Base64Decode(cipherstr);
    inputKeyIV();
    string skey = printHex(key);
    string siv = printHex(iv);
    switch(mode){
        case 1:{
            decECB(cipherstr, skey);
            break;
        }
        default:
            wcout << L"Invalid input\n";
            break;
    }
}

int main(int argc, char* argv[])
{
    #ifdef __linux__
    setlocale(LC_ALL, "");
    #elif _WIN32
    _setmode(_fileno(stdin), _O_U16TEXT);
    _setmode(_fileno(stdout), _O_U16TEXT);
    #endif

    int aescipher;
    wcout << L"Would you like to encryption or decryption message:\n"
          << "1. key and iv generation;\n"
          << "2. encryption;\n"
          << "3. decryption;\n"
          << "Please enter your number?\n";
    wcin >> aescipher;
    wcin.ignore();

    switch (aescipher) {
        case 1: {
            randomKeyIV();
            wcout << L"key (Hex): " << string_to_wstring(printHex(key)) << endl;
            wcout << L"iv (Hex): " << string_to_wstring(printHex(iv)) << endl;
            wcout << L"key (Base64): " << string_to_wstring(printBase64(key));
            wcout << L"iv (Base64): " << string_to_wstring(printBase64(iv));
            break;
        }
        case 2: {
            encMenu();
            break;
        }
        case 3: {
            // Decryption logic here
            decMenu();
            break;
        }
        default:
            cout << "Invalid input\n";
            break;
    }
    return 0;
}

wstring string_to_wstring(const string& str) {
    wstring_convert<codecvt_utf8<wchar_t>> towstring;
    return towstring.from_bytes(str);
}

string wstring_to_string(const wstring& str) {
    wstring_convert<codecvt_utf8<wchar_t>> tostring;
    return tostring.to_bytes(str);
}
