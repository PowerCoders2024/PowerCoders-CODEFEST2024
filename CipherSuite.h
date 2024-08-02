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
#include <fstream>

#define THREAD_POOL_SIZE 5
#define AUTH_TAG_SIZE 16
#define IV_SIZE 16
#define AUTH_IN_SIZE 16

class CipherSuite {
public:
	Aes aes;
	byte iv[IV_SIZE];
	byte authIn[AUTH_IN_SIZE] = {0};
	WC_RNG rng;
	static byte pskKey[16];

	std::ifstream infile;
	std::ofstream outfile;
	size_t block_size;
	size_t last_block_size;

	struct thread_params {
		bool encrypt_mode;
		int active_threads;
		std::mutex sync_mtx;
		std::mutex thread_pool_control;
		std::condition_variable cv_thread_pool;
		std::condition_variable cv_sync;
		int mtx_count;
		std::vector<std::thread> threads;

		thread_params() {};
	};
	thread_params t_params;

	CipherSuite() {
		std::cout << "Initializing RNG..." << std::endl;
		wc_InitRng(&this->rng);
	};

	size_t initStreams(const std::string& input_path, const std::string& output_path);
	void computeBlockSizes(int file_size);
	void performOperation(bool encrypt_mode, byte key[], const std::string& input_path, const std::string& output_path);
	void runThreads(byte* key);
	void keyGenerator(ecc_key& key);
	static int PSKKeyGenerator(byte* pskKey, int keySize);
	void initializeCipherSuite();
};

#endif	// CIPHERSUITE_H
