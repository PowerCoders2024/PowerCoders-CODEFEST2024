#include "CipherSuite.h"

#include <condition_variable>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <thread>
#include <vector>

void CipherSuite::initializeCipherSuite() {
	// Inicialización del constructor
	std::cout << "cipher init" << std::endl;

	// TODO: Cambiar el IV por uno generado aleatoriamente
	byte ivGen[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
	std::memcpy(this->iv, ivGen, 16);
}

void CipherSuite::keyGenerator(ecc_key& key) {
	wc_ecc_init(&key);
	wc_ecc_set_rng(&key, &this->rng);
	wc_ecc_make_key(&this->rng, 8, &key);  // Danny cambio de 32 a 8
}

void operate_block(CipherSuite* cipherSuite, bool encrypt_mode, byte* key, std::vector<byte> buffer,
				   std::array<byte, IV_SIZE> iv_vector, std::array<byte, AUTH_TAG_SIZE> authTag_vector,
				   const size_t read_size, int thread_id, std::ofstream& outfile, std::mutex& sync_mtx,
				   std::mutex& thread_pool_control, int active_threads, int& mtx_count,
				   std::condition_variable& cv_thread_pool, std::condition_variable& cv_sync) {
	{
		std::unique_lock<std::mutex> lock(thread_pool_control);
		cv_thread_pool.wait(lock, [&] { return active_threads < THREAD_POOL_SIZE; });
		++active_threads;
	}

	std::cout << "Encrypting thread #" << thread_id << ":..." << std::endl;

	std::vector<byte> out(read_size);
	byte* iv = iv_vector.data();
	byte* authTag = authTag_vector.data();

	int ret = 0;

	if (encrypt_mode) {
		wc_RNG_GenerateBlock(&cipherSuite->rng, iv, IV_SIZE);
		ret = wc_AesGcmEncrypt(&cipherSuite->aes, out.data(), buffer.data(), read_size, iv, IV_SIZE, authTag, AUTH_TAG_SIZE,
							   cipherSuite->authIn, AUTH_IN_SIZE);
	} else
		ret = wc_AesGcmDecrypt(&cipherSuite->aes, out.data(), buffer.data(), read_size, iv, IV_SIZE, authTag, AUTH_TAG_SIZE,
							   cipherSuite->authIn, AUTH_IN_SIZE);

	if (ret != 0) {
		std::cerr << (encrypt_mode ? "Encrypt" : "Decrypt") << " error: " << ret << std::endl;
	}

	std::cout << "Encrypted thread #" << thread_id << std::endl;

	{
		std::unique_lock<std::mutex> lock(sync_mtx);
		cv_sync.wait(lock, [&] { return mtx_count == thread_id; });
	}
	std::cout << "Writing thread #" << thread_id << std::endl;
	if (encrypt_mode) {
		outfile.write(reinterpret_cast<const char*>(iv), IV_SIZE);
		outfile.write(reinterpret_cast<const char*>(authTag), AUTH_TAG_SIZE);
	}
	outfile.write(reinterpret_cast<const char*>(out.data()), read_size);
	std::cout << "Wrote thread #" << thread_id << std::endl;
	{
		mtx_count++;
		cv_sync.notify_all();
	}

	{
		std::lock_guard<std::mutex> lock(thread_pool_control);
		--active_threads;
		cv_thread_pool.notify_all();
	}
}

void CipherSuite::performOperation(bool encrypt_mode, byte key[], const std::string& input_path,
								   const std::string& output_path) {
	t_params.encrypt_mode = encrypt_mode;
	t_params.active_threads = 0;
	t_params.threads = std::vector<std::thread>(THREAD_POOL_SIZE);
	wc_AesInit(&aes, NULL, 0);
	wc_AesGcmSetKey(&aes, key, 32);

	size_t file_size = initStreams(input_path, output_path);

	computeBlockSizes(file_size);

	runThreads(key);

	wc_AesFree(&aes);
	infile.close();
	outfile.close();
}

void CipherSuite::computeBlockSizes(int file_size) {
	std::cout << t_params.encrypt_mode << std::endl;
	if (t_params.encrypt_mode) {
		block_size = file_size / THREAD_POOL_SIZE;
		last_block_size = file_size - block_size * (THREAD_POOL_SIZE - 1);
	} else {
		block_size = (file_size - THREAD_POOL_SIZE * (IV_SIZE + AUTH_TAG_SIZE)) / THREAD_POOL_SIZE;
		last_block_size = (file_size - THREAD_POOL_SIZE * (IV_SIZE + AUTH_TAG_SIZE)) - block_size * (THREAD_POOL_SIZE - 1);
	}
}

size_t CipherSuite::initStreams(const std::string& input_path, const std::string& output_path) {
	std::filesystem::path p(input_path);

	infile.open(input_path, std::ios::binary);

	outfile.open(output_path, std::ios::binary | std::ios::trunc);

	std::cout << "Opening files" << std::endl;
	if (!infile.is_open() || !outfile.is_open()) {
		std::cerr << "Error opening files." << std::endl;
		return 0;
	}

	return std::filesystem::file_size(p);
}

void CipherSuite::runThreads(byte* key) {
	for (int i = 0; i < THREAD_POOL_SIZE; i++) {
		size_t current_block_size = (i == THREAD_POOL_SIZE - 1) ? last_block_size : block_size;

		std::vector<byte> buffer(current_block_size);
		std::array<byte, IV_SIZE> iv;
		std::array<byte, AUTH_TAG_SIZE> authTag;

		if (!t_params.encrypt_mode) {
			infile.read(reinterpret_cast<char*>(iv.data()), IV_SIZE);
			infile.read(reinterpret_cast<char*>(authTag.data()), AUTH_TAG_SIZE);
		}
		infile.read(reinterpret_cast<char*>(buffer.data()), current_block_size);

		const size_t read_size = infile.gcount();

		if (read_size == 0) break;	// No more data to read

		t_params.threads.emplace_back(operate_block, this, t_params.encrypt_mode, key, buffer, iv, authTag, read_size, i,
									  std::ref(outfile), std::ref(t_params.sync_mtx), std::ref(t_params.thread_pool_control),
									  t_params.active_threads, std::ref(t_params.mtx_count),
									  std::ref(t_params.cv_thread_pool), std::ref(t_params.cv_sync));
	}

	for (auto& t : t_params.threads) {
		if (t.joinable()) {
			t.join();
		}
	}
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