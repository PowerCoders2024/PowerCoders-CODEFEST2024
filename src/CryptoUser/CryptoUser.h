#ifndef CRYPTOUSER_H
#define CRYPTOUSER_H

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/types.h>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <string>

#include "../CipherSuite.h"

class CryptoUser {

public:
	CipherSuite cipher_suite = CipherSuite();
	CryptoUser();
	void encryptMessage(byte key[], const std::string &input_path, const std::string &output_path);
	void decryptMessage(byte key[], const std::string &input_path, const std::string &output_path);
	static std::string readFile(std::string filePath);
	void derivePBKDF2Key(const byte* passwordSeed, size_t passwordSeedLen, const byte* saltSeed, size_t saltSeedLen, byte* output, size_t outputLen, int iterations);
	static byte pskKey[16];
    static const std::string& getPrime();
    static const std::string& getSeed();

private:
    static std::string prime;
    static std::string seed;

};
#endif	// CRYPTOUSER_H