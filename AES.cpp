//C internal library
#include <bits/stdc++.h>
#include <chrono>
using std::chrono::high_resolution_clock;
using std::chrono::duration_cast;
using std::chrono::duration;

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
#include "modes/AES-CBC.h"
#include "modes/AES-CFB.h"
#include "modes/AES-OFB.h"
#include "modes/AES-CTR.h"
#include "modes/AES-XTS.h"
#include "modes/AES-CCM.h"
#include "modes/AES-GCM.h"

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

AutoSeededRandomPool prng;
SecByteBlock key(AES::DEFAULT_KEYLENGTH);
SecByteBlock iv(AES::DEFAULT_KEYLENGTH);
int IOMode;
void randomKeyIV(){
    
    prng.GenerateBlock(key, key.size());
    prng.GenerateBlock(iv, key.size());
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
    iv = SecByteBlock(reinterpret_cast<const CryptoPP::byte*>(&ivstr[0]), ivstr.size());
}

wstring inputPlainMenu(){
    wcout   << "Choose the input method:\n"
            << "1. From file;\n"
            << "2. From console;\n"
            << "Please enter your number?\n";
    int mode;
    wcin >> mode;
    IOMode = mode;
    wcin.ignore();
    switch (mode)
    {
        case 1: {
            string str;
            FileSource file("plain.txt", true, new StringSink(str));
            wstring wstr = string_to_wstring(str);
            //wcout << L"plain text: " << wstr << endl;
            return wstr;
            break;
        }
        case 2:{
            wcout << L"Please enter the plain text:\n";
            wcin.ignore();
            wstring text;
            getline(wcin, text);
            //wcin.ignore();
            wcout << L"plain text: " << text << endl;
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
    IOMode = mode;
    wcin.ignore();
    switch (mode)
    {
        case 1: {
            wifstream in( "cipher.txt",ios::binary );
            wstring filetext;
            in >> filetext;
            //wcout << L"cipher text: " << filetext << endl;
            return filetext;
            break;
        }
        case 2:{
            wcout << L"Please enter the ciphertext (Base64):\n";
            //wcin.ignore();
            wstring text;
            wcin >> text;
            wcin.ignore();
            wcout << L"cipher text: " << text << endl;
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

string encECB(wstring& plain, string& skey){
    ECB ecb;
    string cipher = ecb.encrypt(wstring_to_string(plain), hexDecode(skey));
    return printBase64(cipher);
}

string decECB(string& cipher, string& skey){
    ECB ecb;
    cipher = (cipher);
    string plain = ecb.decrypt(cipher, hexDecode(skey));
    return plain;
}

string encCBC(wstring& plain, string& skey, string& siv){
    CBC cbc;
    string cipher = cbc.encrypt(wstring_to_string(plain), hexDecode(skey), hexDecode(siv));
    return printBase64(cipher);
}

string decCBC(string& cipher, string& skey, string& siv){
    CBC cbc;
    cipher = (cipher);
    string plain = cbc.decrypt(cipher, hexDecode(skey), hexDecode(siv));
    return plain;
}

string encOFB(wstring& plain, string& skey, string& siv){
    OFB ofb;
    string cipher = ofb.encrypt(wstring_to_string(plain), hexDecode(skey), hexDecode(siv));
    return printBase64(cipher);
}

string decOFB(string& cipher, string& skey, string& siv){
    OFB ofb;
    cipher = (cipher);
    string plain = ofb.decrypt(cipher, hexDecode(skey), hexDecode(siv));
    return plain;
}

string encCFB(wstring& plain, string& skey, string& siv){
    CFB cfb;
    string cipher = cfb.encrypt(wstring_to_string(plain), hexDecode(skey), hexDecode(siv));
    return printBase64(cipher);
}

string decCFB(string& cipher, string& skey, string& siv){
    CFB cfb;
    cipher = (cipher);
    string plain = cfb.decrypt(cipher, hexDecode(skey), hexDecode(siv));
    return plain;
}

string encCTR(wstring& plain, string& skey, string& siv){
    CTR ctr;
    string cipher = ctr.encrypt(wstring_to_string(plain), hexDecode(skey), hexDecode(siv));
    return printBase64(cipher);
}

string decCTR(string& cipher, string& skey, string& siv){
    CTR ctr;
    cipher = (cipher);
    string plain = ctr.decrypt(cipher, hexDecode(skey), hexDecode(siv));
    return plain;
}

string encXTS(wstring& plain, string& skey, string& siv){
    XTS_alter xts;
    string cipher = xts.encrypt(wstring_to_string(plain), skey, siv);
    return printBase64(cipher);
}

string decXTS(string& cipher, string& skey, string& siv){
    XTS_alter xts;
    cipher = (cipher);
    string plain = xts.decrypt(cipher, skey, siv);
    return plain;
}

string encCCM(wstring& plain, string& skey, string& siv){
    CCM_alter ccm;
    string cipher = ccm.encrypt(wstring_to_string(plain), skey, siv);
    return printBase64(cipher);
}

string decCCM(string& cipher, string& skey, string& siv){
    CCM_alter ccm;
    cipher = (cipher);
    string plain = ccm.decrypt(cipher, skey, siv);
    return plain;
}

string encGCM(wstring& plain, string& skey, string& siv){
    GCM_alter gcm;
    string cipher = gcm.encrypt(wstring_to_string(plain), skey, siv);
    return printBase64(cipher);
}

string decGCM(string& cipher, string& skey, string& siv){
    GCM_alter gcm;
    cipher = (cipher);
    string plain = gcm.decrypt(cipher, skey, siv);
    return plain;
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
    string cipher;
    auto start = std::chrono::high_resolution_clock::now();
    for(int i = 0; i < 1000; i++){
        switch(mode){
            case 1:{
                cipher = encECB(plain, skey);
                break;
            }
            case 2:{
                cipher = encCBC(plain, skey, siv);
                break;
            }
            case 3:{
                cipher = encCFB(plain, skey, siv);
                break;
            }
            case 4:{
                cipher = encOFB(plain, skey, siv);
                break;
            }
            case 5:{
                cipher = encCTR(plain, skey, siv);
                break;
            }
            case 6:{
                cipher = encXTS(plain, skey, siv);
                break;
            }
            case 7:{
                cipher = encCCM(plain, skey, siv);
                break;
            }
            case 8:{
                cipher = encGCM(plain, skey, siv);
                break;
            }
            default:
                wcout << L"Invalid input\n";
                break;
        }
    }
    auto stop = std::chrono::high_resolution_clock::now();
    duration<double, std::milli> duration = stop - start;
    switch (IOMode)
    {
    case 1:{
        wofstream out( "cipher.txt");
        out << string_to_wstring(cipher);
        wcout << L"ciphertext was written to cipher.txt" << endl;
        break;
    }
    case 2:{
        wcout << L"ciphertext (Base64): " << string_to_wstring(cipher) << endl;
        break;
    }
    default:
        break;
    }
    wcout << fixed << setprecision(3) << L"Average time: " << duration.count() << L" microseconds" << endl;
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
    string plain;
    auto start = std::chrono::high_resolution_clock::now();
    switch(mode){
        case 1:{
            plain = decECB(cipherstr, skey);
            break;
        }
        case 2:{
            plain = decCBC(cipherstr, skey, siv);
            break;
        }
        case 3:{
            plain = decCFB(cipherstr, skey, siv);
            break;
        }
        case 4:{
            plain = decOFB(cipherstr, skey, siv);
            break;
        }
        case 5:{
            plain = decCTR(cipherstr, skey, siv);
            break;
        }
        case 6:{
            plain = decXTS(cipherstr, skey, siv);
            break;
        }
        case 7:{
            plain = decCCM(cipherstr, skey, siv);
            break;
        }
        case 8:{
            plain = decGCM(cipherstr, skey, siv);
            break;
        }
        default:
            wcout << L"Invalid input\n";
            break;
    }
    auto stop = std::chrono::high_resolution_clock::now();
    duration<double, std::milli> duration = stop - start;
    switch (IOMode)
    {
    case 1:{
        wofstream out( "plain.txt");
        out << string_to_wstring(plain);
        wcout << L"plain text was written to cipher.txt" << endl;
        break;
    }
    case 2:{
        wcout << L"plain text: " << string_to_wstring(plain) << endl;
        break;
    }
    default:
        break;
    }
   
    wcout << fixed << setprecision(3) << L"Average time: " << duration.count() << L" microseconds" << endl;
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
            wcout << L"iv size: " << iv.size() << endl;
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
