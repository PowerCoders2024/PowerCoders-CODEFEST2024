#ifndef CIPHERSUITE_H
#define CIPHERSUITE_H

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/types.h>

#include <condition_variable>
#include <filesystem>
#include <iostream>
#include <mutex>
#include <string>
#include <vector>

class CipherSuite {
public:
	Aes aes;
	byte iv[16];
	byte authIn[16] = {0};
	WC_RNG rng;
	static byte pskKey[16];

	CipherSuite();
	void encryptAES(byte key[], const std::string &input_path, const std::string &output_path);
	void decryptAES(byte key[], const std::string &input_path, const std::string &output_path);
	void keyGenerator(ecc_key &key);
	static int PSKKeyGenerator(byte *pskKey, int keySize);
	void initializeCipherSuite();
};

#endif	// CIPHERSUITE_H
