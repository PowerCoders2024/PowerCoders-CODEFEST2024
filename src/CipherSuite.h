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
#include <thread>
#include <string>
#include <vector>
#include <fstream>


#define THREAD_POOL_SIZE 10
#define MAX_LOAD_SIZE ((long)2800000000 / THREAD_POOL_SIZE)	 // 2.8GB - Max size of concurrent file processing buffers
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
	size_t file_size;
	// TODO hacer privados métodos y atributos
	struct thread_params {
		bool encrypt_mode;
		int threads_to_run;
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
	CipherSuite(const std::string &input_path, const std::string &output_path);
	void computeBlockSize(size_t& block_size, size_t& trailing_size);
	void initStreams(const std::string& input_path, const std::string& output_path);
	void performOperation(bool encrypt_mode, byte key[], const std::string& input_path, const std::string& output_path);
	void runThreads(byte* key);
	void computeNumThreads();
	
};

#endif	// CIPHERSUITE_H
