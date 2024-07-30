#ifndef CIPHERSUITE_H
#define CIPHERSUITE_H

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/types.h>
#include <iostream>
#include <filesystem>
#include <string>
#include <vector>
#include <mutex>
#include <condition_variable>

class CipherSuite {
public:
    Aes aes;
    byte iv[16];
    byte authIn[16] = {0};
    WC_RNG rng;

    CipherSuite();
    void encryptAES(byte key[], const std::string &input_path, const std::string &output_path);
    void decryptAES(byte key[], const std::string &input_path, const std::string &output_path);
    void keyGenerator(ecc_key &key);
};

#endif // CIPHERSUITE_H
