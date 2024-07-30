
// CryptoUser.h
#ifndef CRYPTOUSER_H
#define CRYPTOUSER_H

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/types.h>
#include <iostream>
#include <filesystem>
#include <string>
#include <cstring>
#include "../CipherSuite.h"



class CryptoUser {
    ecc_key priv, pub;
public:
    byte keySession[AES_256_KEY_SIZE];
    word32 keySessionSz = AES_256_KEY_SIZE;
    CipherSuite cipher_suite;

    CryptoUser();
    ecc_key getPub() const;
    void setKeySession(ecc_key userPub);
    void encryptMessage(byte key[], const std::string &input_path, byte** cipher, size_t* cipher_size, byte** authTag, size_t* authTagSz, byte** authIn, size_t* authInSz);
    void decryptMessage(byte key[], byte* cipher, size_t ciphSzs, byte* authTag, size_t authTagSz, byte* authIn, size_t authInSz, const std::string &output_path);
};

#endif // CRYPTOUSER_H