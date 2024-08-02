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
				   std::mutex& thread_pool_control, int& active_threads, int& mtx_count,
				   std::condition_variable& cv_thread_pool, std::condition_variable& cv_sync) {
	{
		std::unique_lock<std::mutex> lock(thread_pool_control);
		cv_thread_pool.wait(lock, [&] { return active_threads < THREAD_POOL_SIZE; });
		++active_threads;
	}

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

	buffer.clear();
	// std::cout << "Encrypted thread #" << thread_id << std::endl;

	{
		std::unique_lock<std::mutex> lock(sync_mtx);
		cv_sync.wait(lock, [&] { return mtx_count == thread_id; });
	}
	// std::cout << "Writing thread #" << thread_id << std::endl;
	if (encrypt_mode) {
		outfile.write(reinterpret_cast<const char*>(iv), IV_SIZE);
		outfile.write(reinterpret_cast<const char*>(authTag), AUTH_TAG_SIZE);
	}
	outfile.write(reinterpret_cast<const char*>(out.data()), read_size);
	// std::cout << "Wrote thread #" << thread_id << std::endl;
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

	initStreams(input_path, output_path);

	runThreads(key);

	wc_AesFree(&aes);
	infile.close();
	outfile.close();
}

void CipherSuite::computeBlockSize(size_t& block_size, size_t& trailing_size) {
	if (t_params.encrypt_mode) {
		block_size = file_size / t_params.threads_to_run;
		trailing_size = file_size - block_size * (t_params.threads_to_run - 1);
	} else {
		block_size = (file_size - t_params.threads_to_run * (IV_SIZE + AUTH_TAG_SIZE)) / t_params.threads_to_run;
		trailing_size =
			(file_size - t_params.threads_to_run * (IV_SIZE + AUTH_TAG_SIZE)) - block_size * (t_params.threads_to_run - 1);
	}
}

void CipherSuite::computeNumThreads() {
	if (t_params.encrypt_mode) {
		t_params.threads_to_run = std::max(10, (int)(file_size / MAX_LOAD_SIZE));
		// Guardar en el archivo para la desencriptación
		std::vector<char> buffer(sizeof(t_params.threads_to_run));
		std::memcpy(buffer.data(), &t_params.threads_to_run, sizeof(t_params.threads_to_run));
		outfile.write(buffer.data(), sizeof(t_params.threads_to_run));
	} else {
		// Leer del archivo para la desencriptación
		std::vector<char> buffer(sizeof(t_params.threads_to_run));
		infile.read(buffer.data(), sizeof(t_params.threads_to_run));
		std::memcpy(&t_params.threads_to_run, buffer.data(), sizeof(t_params.threads_to_run));
		file_size -= sizeof(t_params.threads_to_run);
	}

	std::cout << "Threads to run: " << t_params.threads_to_run << std::endl;
}

void CipherSuite::initStreams(const std::string& input_path, const std::string& output_path) {
	std::filesystem::path p(input_path);
	file_size = std::filesystem::file_size(p);

	infile.open(input_path, std::ios::binary);

	std::cout << "Opening files" << std::endl;
	outfile.open(output_path, std::ios::binary | std::ios::trunc);
	std::cout << "File size: " << file_size << std::endl;

	if (!infile.is_open() || !outfile.is_open()) {
		std::cerr << "Error opening files." << std::endl;
		return;
	}
}

void CipherSuite::runThreads(byte* key) {
	int max_concurrent_threads = 0;

	size_t block_size, trailing_size;

	computeNumThreads();
	computeBlockSize(block_size, trailing_size);

	std::cout << "Block size: " << block_size << std::endl;

	for (int i = 0; i < t_params.threads_to_run; i++) {
		if (i == t_params.threads_to_run - 1) block_size = trailing_size;

		std::vector<byte> buffer(block_size);
		std::array<byte, IV_SIZE> iv;
		std::array<byte, AUTH_TAG_SIZE> authTag;

		if (!t_params.encrypt_mode) {
			infile.read(reinterpret_cast<char*>(iv.data()), IV_SIZE);
			infile.read(reinterpret_cast<char*>(authTag.data()), AUTH_TAG_SIZE);
		}
		infile.read(reinterpret_cast<char*>(buffer.data()), block_size);

		t_params.threads.emplace_back(operate_block, this, t_params.encrypt_mode, key, buffer, iv, authTag, block_size, i,
									  std::ref(outfile), std::ref(t_params.sync_mtx), std::ref(t_params.thread_pool_control),
									  std::ref(t_params.active_threads), std::ref(t_params.mtx_count),
									  std::ref(t_params.cv_thread_pool), std::ref(t_params.cv_sync));

		max_concurrent_threads = std::max(max_concurrent_threads, t_params.active_threads);

		if (i % THREAD_POOL_SIZE == 0) {
			for (auto& t : t_params.threads) {
				if (t.joinable()) {
					t.join();
				}
			}
			t_params.threads.clear();
		}
	}

	for (auto& t : t_params.threads) {
		if (t.joinable()) {
			t.join();
		}
	}

	t_params.threads.clear();

	std::cout << "Max concurrent threads: " << max_concurrent_threads << std::endl;
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