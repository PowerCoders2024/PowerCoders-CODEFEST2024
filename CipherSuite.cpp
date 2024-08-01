#include "CipherSuite.h"

#include <condition_variable>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <thread>
#include <vector>

#define THREAD_POOL_SIZE 100
#define AUTH_TAG_SIZE 16
#define IV_SIZE 16

CipherSuite::CipherSuite() {
	/* std::cout << "cipher init" << std::endl;

	byte ivGen[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
					0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
	std::memcpy(this->iv, ivGen, IV_SIZE); */

	wc_InitRng(&this->rng);
}

void CipherSuite::initializeCipherSuite() {
	// Inicialización del constructor
	std::cout << "cipher init" << std::endl;

	// TODO: Cambiar el IV por uno generado aleatoriamente
	byte ivGen[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
	std::memcpy(this->iv, ivGen, 16);
	// wc_Initng(&this->rng);
}

void CipherSuite::keyGenerator(ecc_key& key) {
	wc_ecc_init(&key);
	wc_ecc_set_rng(&key, &this->rng);
	wc_ecc_make_key(&this->rng, 8, &key);  // Danny cambio de 32 a 8
}

void encrypt_block(CipherSuite& cipherSuite, byte* key, byte* buffer, byte* cipher_block, byte* iv, byte* authTag,
				   const size_t& read_size, int& thread_id, std::mutex& mtx, std::condition_variable& cv,
				   int& active_threads) {
	{
		std::unique_lock<std::mutex> lock(mtx);
		cv.wait(lock, [&] { return active_threads < THREAD_POOL_SIZE; });
		++active_threads;
	}

	/* std::cout << "Encrypting thread #" << thread_id << ":..." << std::endl; */
	Aes aes;
	wc_AesInit(&aes, NULL, 0);
	wc_AesGcmSetKey(&aes, key, 32);

	wc_RNG_GenerateBlock(&cipherSuite.rng, iv, IV_SIZE);

	int ret = wc_AesGcmEncrypt(&aes, cipher_block, buffer, read_size, iv, IV_SIZE, authTag, AUTH_TAG_SIZE,
							   cipherSuite.authIn, sizeof(cipherSuite.authIn));
	if (ret != 0) {
		std::cout << "Encryption error: " << ret << std::endl;
	}
	/* std::cout << "Encrypted thread #" << thread_id << std::endl; */

	{
		std::lock_guard<std::mutex> lock(mtx);
		--active_threads;
		cv.notify_all();
	}
}

void decrypt_block(CipherSuite& cipherSuite, byte* key, byte* buffer, byte* decrypted_block, byte* iv, byte* authTag,
				   const size_t& read_size, int& thread_id, std::mutex& mtx, std::condition_variable& cv,
				   int& active_threads) {
	{
		std::unique_lock<std::mutex> lock(mtx);
		cv.wait(lock, [&] { return active_threads < THREAD_POOL_SIZE; });
		++active_threads;
	}

	/* std::cout << "Decrypting thread #" << thread_id << ":..." << std::endl; */
	Aes aes;
	wc_AesInit(&aes, NULL, 0);
	wc_AesGcmSetKey(&aes, key, 32);

	int ret = wc_AesGcmDecrypt(&aes, decrypted_block, buffer, read_size, iv, IV_SIZE, authTag, AUTH_TAG_SIZE,
							   cipherSuite.authIn, sizeof(cipherSuite.authIn));
	if (ret != 0) {
		std::cout << "Decryption error: " << ret << std::endl;
	}
	/* std::cout << "Decrypted thread #" << thread_id << std::endl; */

	{
		std::lock_guard<std::mutex> lock(mtx);
		--active_threads;
		cv.notify_all();
	}
}

void CipherSuite::encryptAES(byte key[], const std::string& input_path, const std::string& output_path) {
	wc_AesInit(&this->aes, NULL, 0);
	wc_AesGcmSetKey(&this->aes, key, 32);

	std::filesystem::path p(input_path);
	unsigned long file_size = std::filesystem::file_size(p);
	size_t block_size = file_size / THREAD_POOL_SIZE;

	size_t last_block_size = file_size - block_size * (THREAD_POOL_SIZE - 1);
	std::ifstream infile(input_path, std::ios::binary);
	std::ofstream outfile(output_path, std::ios::binary | std::ios::trunc);

	if (!infile.is_open() || !outfile.is_open()) {
		std::cout << "Error opening files." << std::endl;
		return;
	}

	std::mutex mtx;
	std::condition_variable cv;
	int active_threads = 0;
	const int max_threads = THREAD_POOL_SIZE;
	std::vector<std::thread> threads;

	for (int i = 0; i < THREAD_POOL_SIZE; i++) {
		size_t current_block_size = (i == THREAD_POOL_SIZE - 1) ? last_block_size : block_size;

		std::vector<byte> buffer(current_block_size);

		std::array<byte, IV_SIZE> iv;
		std::array<byte, AUTH_TAG_SIZE> authTag;

		infile.read(reinterpret_cast<char*>(buffer.data()), current_block_size);
		const size_t read_size = infile.gcount();

		if (read_size == 0) break;	// No more data to read

		std::vector<byte> cipher_block(read_size);

		threads.emplace_back(encrypt_block, std::ref(*this), key, buffer.data(), cipher_block.data(), iv.data(),
							 authTag.data(), std::ref(read_size), std::ref(i), std::ref(mtx), std::ref(cv),
							 std::ref(active_threads));

		for (auto& t : threads) {
			if (t.joinable()) {
				t.join();
			}
		}

		outfile.write(reinterpret_cast<const char*>(iv.data()), iv.size());
		outfile.write(reinterpret_cast<const char*>(authTag.data()), authTag.size());
		outfile.write(reinterpret_cast<const char*>(cipher_block.data()), read_size);
	}

	for (auto& t : threads) {
		if (t.joinable()) {
			t.join();
		}
	}

	infile.close();
	outfile.close();
}

void CipherSuite::decryptAES(byte key[], const std::string& input_path, const std::string& output_path) {
	wc_AesInit(&this->aes, NULL, 0);
	wc_AesGcmSetKey(&this->aes, key, 32);

	std::filesystem::path p(input_path);
	unsigned long file_size = std::filesystem::file_size(p);
	size_t block_size = (file_size - THREAD_POOL_SIZE * (IV_SIZE + AUTH_TAG_SIZE)) / THREAD_POOL_SIZE;

	size_t last_block_size =
		(file_size - THREAD_POOL_SIZE * (IV_SIZE + AUTH_TAG_SIZE)) - block_size * (THREAD_POOL_SIZE - 1);

	std::ifstream infile(input_path, std::ios::binary);
	std::ofstream outfile(output_path, std::ios::binary | std::ios::trunc);

	if (!infile.is_open() || !outfile.is_open()) {
		std::cout << "Error opening files." << std::endl;
		return;
	}

	std::mutex mtx;
	std::condition_variable cv;
	int active_threads = 0;
	const int max_threads = THREAD_POOL_SIZE;
	std::vector<std::thread> threads;

	for (int i = 0; i < THREAD_POOL_SIZE; i++) {
		size_t current_block_size = (i == THREAD_POOL_SIZE - 1) ? last_block_size : block_size;

		std::vector<byte> buffer(current_block_size);
		std::vector<byte> decrypted_block(current_block_size);
		std::array<byte, IV_SIZE> iv;
		std::array<byte, AUTH_TAG_SIZE> authTag;

		/* void decrypt_block(CipherSuite& cipherSuite, byte* key, byte* buffer,
						   byte* decrypted_block, byte* iv, byte* authTag,
						   const size_t& read_size, int& thread_id, std::mutex& mtx,
						   std::condition_variable& cv, int& active_threads)  */
		infile.read(reinterpret_cast<char*>(iv.data()), IV_SIZE);
		infile.read(reinterpret_cast<char*>(authTag.data()), AUTH_TAG_SIZE);
		infile.read(reinterpret_cast<char*>(buffer.data()), current_block_size);

		const size_t read_size = buffer.size();
		if (read_size == 0) break;	// No more data to read

		threads.emplace_back(decrypt_block, std::ref(*this), key, buffer.data(), decrypted_block.data(), iv.data(),
							 authTag.data(), std::ref(read_size), std::ref(i), std::ref(mtx), std::ref(cv),
							 std::ref(active_threads));

		for (auto& t : threads) {
			if (t.joinable()) {
				t.join();
			}
		}

		outfile.write(reinterpret_cast<const char*>(decrypted_block.data()), read_size);
	}

	for (auto& t : threads) {
		if (t.joinable()) {
			t.join();
		}
	}

	infile.close();
	outfile.close();
}

int CipherSuite::PSKKeyGenerator(byte* pskKey, int keySize) {
	WC_RNG rng;

	int ret = wc_InitRng(&rng);
	if (ret != 0) {
		printf("Error initializing RNG: %d\n", ret);
		return ret;
	}

	ret = wc_RNG_GenerateBlock(&rng, pskKey, keySize);
	if (ret != 0) {
		printf("Error generating PSK key: %d\n", ret);
		wc_FreeRng(&rng);
		return ret;
	}

	wc_FreeRng(&rng);
	return 0;  // Éxito
}