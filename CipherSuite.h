//
// Created by danny on 7/28/24.
//

#ifndef CIPHERSUITE_H
#define CIPHERSUITE_H
#include <wolfssl/options.h>
#include <iostream>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <filesystem>
#include <string>
#include <wolfssl/wolfcrypt/types.h>
#include <cstring>

class CipherSuite {
    Aes aes;
    byte iv[16];

public:
    byte* cipher;
    size_t cipher_size;
    byte authTag[16];
    size_t authTagSz;
    byte authIn[16] = {0};
    size_t authInSz;
    WC_RNG rng;
    // Constructor
    CipherSuite();
    // CipherFunctions
    void initializeCipherSuite();
    void encryptAES(byte key[], const std::string& input_path);
    void decryptAES(byte key[], byte* cipher, size_t ciphSzs,  byte* authTag, size_t authTagSz,byte* authIn, size_t authInSz);
    void keyGenerator(ecc_key& key);
    void pskEngine();

};

#endif //CIPHERSUITE_H
