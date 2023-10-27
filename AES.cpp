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

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#undef WIN32_LEAN_AND_MEAN
#endif
/* Convert string <--> utf8*/
#include <locale>
using std::wstring_convert;
#include <codecvt>
using  std::codecvt_utf8;
wstring  string_to_wstring(const std::string& str);
string wstring_to_string (const std::wstring& str);


using namespace std;
using namespace CryptoPP;


AutoSeededRandomPool prng;
SecByteBlock key(AES::DEFAULT_KEYLENGTH);
SecByteBlock iv(AES::DEFAULT_KEYLENGTH);
int IOMode;
void randomKeyIV(){
    
    prng.GenerateBlock(key, key.size());
    prng.GenerateBlock(iv, key.size());
}

void inputKeyIV(){
    cout << "Please enter the key (Base64):\n";
    string keystr;
    cin >> keystr;
    cin.ignore();
    keystr = Base64Decode(keystr);
    key = SecByteBlock(reinterpret_cast<const CryptoPP::byte*>(&keystr[0]), keystr.size());

    cout << "Please enter the iv (Base64):\n";
    string ivstr;
    cin >> ivstr;
    cin.ignore();
    ivstr = Base64Decode(ivstr);
    iv = SecByteBlock(reinterpret_cast<const CryptoPP::byte*>(&ivstr[0]), ivstr.size());
}

string inputPlainMenu(){
    cout   << "Choose the input method:\n"
            << "1. From file;\n"
            << "2. From console;\n"
            << "Please enter your number?\n";
    int mode;
    cin >> mode;
    IOMode = mode;
    cin.ignore();
    switch (mode)
    {
        case 1: {
            string str;
            string filename;
            cout << "Please enter the plain text file name:\n";
            cin >> filename;
            FileSource(filename.c_str(), true, new StringSink(str));
            //wstring wstr = (str);
            //wcout << "plain text: " << wstr << endl;
            return str;
            break;
        }
        case 2:{
            cout << "Please enter the plain text:\n";
            //cin.ignore();
            string text;
            getline(cin, text);
            //wcin.ignore();
            cout << "plain text: " << text << endl;
            return text;
            break;
        }

        default:{
            cout << "Invalid input, Please try again\n";
            return inputPlainMenu();
            break;
        }
    }
}

string inputCipherMenu(){
    cout   << "Choose the input method:\n"
            << "1. From file;\n"
            << "2. From console;\n"
            << "Please enter your number?\n";
    int mode;
    cin >> mode;
    IOMode = mode;
    cin.ignore();
    switch (mode)
    {
        case 1: {
            string str;
            string filename;
            cout << "Please enter the ciphertext file name:\n";
            cin >> filename;
            FileSource(filename.c_str(), true, new StringSink(str));
            //wcout << "cipher text: " << filetext << endl;
            return str;
            break;
        }
        case 2:{
            cout << "Please enter the ciphertext (Base64):\n";
            //wcin.ignore();
            string text;
            cin >> text;
            cin.ignore();
            cout << "cipher text: " << text << endl;
            return text;
            break;
        }

        default:{
            cout << "Invalid input, Please try again\n";
            return inputCipherMenu();
            break;
        }
    }
}

template <class T>
string encTemplate(string& plain, string& skey, string& siv){
    T mode;
    string cipher = mode.encrypt(plain, hexDecode(skey), hexDecode(siv));
    return printBase64(cipher);
}

template <class T>
string decTemplate(string& cipher, string& skey, string& siv){
    T mode;
    string plain = mode.decrypt(cipher, hexDecode(skey), hexDecode(siv));
    return plain;
}

void encMenu(){
    string plain = inputPlainMenu();
    cout   << "Choose the mode:\n"
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
    cin >> mode;
    cin.ignore();
    cout << "Would you like to enter key or generate random key?\n"
            << "1. Enter key;\n"
            << "2. Generate random key;\n"
            << "Please enter your number?\n";
    int keymode;
    cin >> keymode;
    cin.ignore();
    switch(keymode){
        case 1:{
            inputKeyIV();
            break;
        }
        case 2:{
            randomKeyIV();
            cout << "key (Hex): " << (printHex(key)) << endl;
            cout << "iv (Hex): " << (printHex(iv)) << endl;
            cout << "key (Base64): " << (printBase64(key));
            cout << "iv (Base64): " << (printBase64(iv));
            break;
        }
        default:
            wcout << "Invalid input\n";
            break;
    }
    string skey = printHex(key);
    string siv = printHex(iv);
    string cipher;
    auto start = std::chrono::high_resolution_clock::now();
    for(int i = 0; i < 10000; i++){
        switch(mode){
            case 1:{
                cipher = encTemplate<ECB>(plain, skey, siv);
                break;
            }
            case 2:{
                cipher = encTemplate<CBC>(plain, skey, siv);
                break;
            }
            case 3:{
                cipher = encTemplate<CFB>(plain, skey, siv);
                break;
            }
            case 4:{
                cipher = encTemplate<OFB>(plain, skey, siv);
                break;
            }
            case 5:{
                cipher = encTemplate<CTR>(plain, skey, siv);
                break;
            }
            case 6:{
                cipher = encTemplate<XTS_alter>(plain, skey, siv);
                break;
            }
            case 7:{
                cipher = encTemplate<CCM_alter>(plain, skey, siv);
                break;
            }
            case 8:{
                cipher = encTemplate<GCM_alter>(plain, skey, siv);
                break;
            }
            default:
                wcout << "Invalid input\n";
                break;
        }
    }
    auto stop = std::chrono::high_resolution_clock::now();
    duration<double, std::milli> duration = (stop - start)/10000.0;
    switch (IOMode)
    {
    case 1:{
        string filename;
        cout << "Please enter the ciphertext file name to be saved:\n";
        cin >> filename;
        StringSource(cipher, true, new FileSink(filename.c_str(), sizeof(key)));
        cout << "ciphertext was written to " << filename << endl;
        break;
    }
    case 2:{
        cout << "ciphertext (Base64): " << (cipher) << endl;
        break;
    }
    default:
        break;
    }
    cout << fixed << setprecision(3) << "Average time: " << duration.count() << " ms" << endl;
}



void decMenu(){
    string cipher = inputCipherMenu();
    cout   << "Choose the mode:\n"
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
    cin >> mode;
    cin.ignore();
    string cipherstr = (cipher);
    cipherstr = Base64Decode(cipherstr);
    inputKeyIV();
    string skey = printHex(key);
    string siv = printHex(iv);
    string plain;
    auto start = std::chrono::high_resolution_clock::now();
    for(int i = 0; i < 10000; i++){
        switch(mode){
            case 1:{
                plain = decTemplate<ECB>(cipherstr, skey, siv);
                break;
            }
            case 2:{
                plain = decTemplate<CBC>(cipherstr, skey, siv);
                break;
            }
            case 3:{
                plain = decTemplate<CFB>(cipherstr, skey, siv);
                break;
            }
            case 4:{
                plain = decTemplate<OFB>(cipherstr, skey, siv);
                break;
            }
            case 5:{
                plain = decTemplate<CTR>(cipherstr, skey, siv);
                break;
            }
            case 6:{
                plain = decTemplate<XTS_alter>(cipherstr, skey, siv);
                break;
            }
            case 7:{
                plain = decTemplate<CCM_alter>(cipherstr, skey, siv);
                break;
            }
            case 8:{
                plain = decTemplate<GCM_alter>(cipherstr, skey, siv);
                break;
            }
            default:
                wcout << "Invalid input\n";
                break;
        }
    }
    auto stop = std::chrono::high_resolution_clock::now();
    duration<double, std::milli> duration = (stop - start)/10000.0;
    switch (IOMode)
    {
    case 1:{
        string filename;
        cout << "Please enter the plain text file name to be saved:\n";
        cin >> filename;
        StringSource(plain, true, new FileSink(filename.c_str(), sizeof(key)));
        cout << "plain text was written to " << filename << endl;
        break;
    }
    case 2:{
        cout << "plain text: " << (plain) << endl;
        break;
    }
    default:
        break;
    }
   
    cout << fixed << setprecision(3) << "Average time: " << duration.count() << " ms" << endl;
}

int main(int argc, char* argv[])
{
    #ifdef __linux__
    std::locale::global(std::locale("C.UTF-8"));
    #endif
  
    #ifdef _WIN32
    // Set console code page to UTF-8 on Windows
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    #endif

    int aescipher;
    cout << "Would you like to encryption or decryption message:\n"
          << "1. key and iv generation;\n"
          << "2. encryption;\n"
          << "3. decryption;\n"
          << "Please enter your number?\n";
    cin >> aescipher;
    cin.ignore();

    switch (aescipher) {
        case 1: {
            randomKeyIV();
            cout << "key (Hex): " << (printHex(key)) << endl;
            cout << "iv (Hex): " << (printHex(iv)) << endl;
            cout << "key (Base64): " << (printBase64(key));
            cout << "iv (Base64): " << (printBase64(iv));
            cout << "iv size: " << iv.size() << endl;
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
