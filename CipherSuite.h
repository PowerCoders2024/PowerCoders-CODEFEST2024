
// CipherSuite.h
#ifndef CIPHERSUITE_H
#define CIPHERSUITE_H

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/types.h>
#include <iostream>
#include <filesystem>
#include <string>
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

    CipherSuite();
    void encryptAES(byte key[], const std::string &input_path, const std::string &output_path);
    void decryptAES(byte key[], const std::string &input_path, const std::string &output_path);
    void keyGenerator(ecc_key &key);
};

#endif // CIPHERSUITE_H