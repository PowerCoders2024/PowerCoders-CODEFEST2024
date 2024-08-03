#include "CipherSuite.h"

#include <condition_variable>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <thread>
#include <vector>
#include <array>

/**
 * @brief Inicializa el CipherSuite.
 *
 * Esta función inicializa el conjunto de cifrado, asignando un IV (Vector de Inicialización) 
 * predefinido a la instancia del objeto CipherSuite.
 */
void CipherSuite::initializeCipherSuite() {
	std::cout << "cipher init" << std::endl;
	byte ivGen[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
	std::memcpy(this->iv, ivGen, 16);
}

/**
 * @brief Genera una clave ECC.
 *
 * @param key Estructura ecc_key donde se almacenará la clave generada.
 */
unsigned int CipherSuite::keyGenerator(ecc_key& key) {
	int ret;
	ret = wc_ecc_init(&key);
	if (ret != 0) {
		return 0;
	}
	ret = wc_ecc_set_rng(&key, &this->rng);
	if (ret != 0) {
		wc_ecc_free(&key);
		return 0;
	}
	ret = wc_ecc_make_key(&this->rng, 8, &key);
	if (ret != 0) {
		wc_ecc_free(&key);
		return 0;
	}

	return 1; // Retornar 1 si todas las llamadas fueron exitosas
}

/**
 * @brief Ejecuta la operación (cifrar o decifrar) sobre un buffer, posterior a la ejecución de la operación envía la salida a través de un stream a un archivo, esto lo hace de manera ordenada, asegurando que el archivo de salida se escribe en el mismo orden en el que se lee
 *
 * @param cipherSuite Puntero al objeto CipherSuite con los miembros necesarios para ejecutar la operación.
 * @param encrypt_mode Modo de operación (true para cifrado, false para descifrado).
 * @param key Clave utilizada para la operación de cifrado/descifrado.
 * @param buffer Buffer de los datos a operar.
 * @param iv_vector Vector de inicialización (Estructura vacía si está en el modo desencriptar).
 * @param authTag_vector Etiqueta de autenticación (Estructura vacía si está en el modo desencriptar).
 * @param read_size Tamaño del buffer proveído .
 * @param thread_id ID del hilo que realiza la operación, indica el orden en el que se va a esribir en la salida.
 * @param outfile Stream de salida para escribir los datos cifrados/descifrados.
 * @param sync_mtx Semáforo mutex para la sincronización de escritura.
 * @param thread_pool_control Semáforo mutex para el control del pool de hilos.
 * @param active_threads Número de hilos activos.
 * @param mtx_count Contador de hilos que ejecutaron y escribieron.
 * @param cv_thread_pool Variable de condición para el pool de hilos.
 * @param cv_sync Variable de condición para la sincronización de escritura.
 */
void operate_block(CipherSuite* cipherSuite, bool encrypt_mode, byte* key, std::vector<byte> buffer,
				   std::array<byte, IV_SIZE> iv_vector, std::array<byte, AUTH_TAG_SIZE> authTag_vector,
				   const size_t read_size, int thread_id, std::ofstream& outfile, std::mutex& sync_mtx,
				   std::mutex& thread_pool_control, int& active_threads, int& mtx_count,
				   std::condition_variable& cv_thread_pool, std::condition_variable& cv_sync) {
	// Bloqueo de sincronización de thread pool
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

	// Bloqueo de sincronización de salida
	{
		std::unique_lock<std::mutex> lock(sync_mtx);
		cv_sync.wait(lock, [&] { return mtx_count == thread_id; });
	}
	if (encrypt_mode) {
		outfile.write(reinterpret_cast<const char*>(iv), IV_SIZE);
		outfile.write(reinterpret_cast<const char*>(authTag), AUTH_TAG_SIZE);
	}
	outfile.write(reinterpret_cast<const char*>(out.data()), read_size);
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

/**
 * @brief Interfaz de la operación de cifrado o descifrado en un archivo.
 *
 * @param encrypt_mode Modo de operación (true para cifrado, false para descifrado).
 * @param key Clave utilizada para la operación de cifrado/descifrado.
 * @param input_path Ruta del archivo de entrada.
 * @param output_path Ruta del archivo de salida.
 */
unsigned int  CipherSuite::performOperation(bool encrypt_mode, byte key[], const std::string& input_path,
								   const std::string& output_path) {
	int ret ;
	// Inicialización de los parámetros de la operación (propios y de wolfssl)
	t_params.encrypt_mode = encrypt_mode;
	t_params.active_threads = 0;
	t_params.threads = std::vector<std::thread>(THREAD_POOL_SIZE);
	// Inicializar AES
	ret = wc_AesInit(&aes, NULL, 0);
	if (ret != 0) {
		return 0; // Error
	}
	// Configurar la clave para AES-GCM
	ret = wc_AesGcmSetKey(&aes, key, 32);
	if (ret != 0) {
		wc_AesFree(&aes);
		return 0; // Error
	}

	// Inicializar flujos de entrada y salida
	if (!initStreams(input_path, output_path)) {
		wc_AesFree(&aes);
		return 0; // Error
	}

	// Ejecutar los hilos de encriptación
	if (!runThreads(key)) {
		wc_AesFree(&aes);
		infile.close();
		outfile.close();
		return 0; // Error
	}


	wc_AesFree(&aes);
	infile.close();
	outfile.close();

	return 1; // Retornar 1 si todas las operaciones fueron exitosas

}

/**
 * @brief Calcula el tamaño de los bloques de datos y el tamaño del bloque final.
 *
 * @param block_size Referencia al tamaño del bloque.
 * @param trailing_size Referencia al tamaño del bloque final.
 */
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

/**
 * @brief Calcula el número de hilos a ejecutar, teniendo en cuenta el thread pool y el pico máximo de memoria a ejecutar concurrentemente.
 */
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

/**
 * @brief Inicializa los streams de entrada y salida para los archivos.
 *
 * @param input_path Ruta del archivo de entrada.
 * @param output_path Ruta del archivo de salida.
 */
unsigned int  CipherSuite::initStreams(const std::string& input_path, const std::string& output_path) {
	std::filesystem::path p(input_path);
	file_size = std::filesystem::file_size(p);
	infile.open(input_path, std::ios::binary);
	std::cout << "Opening files" << std::endl;
	outfile.open(output_path, std::ios::binary | std::ios::trunc);
	std::cout << "File size: " << file_size << std::endl;

	if (!infile.is_open() || !outfile.is_open()) {
		std::cerr << "Error opening files." << std::endl;
		return 0 ;
	}
	return 1 ;
}

/**
 * @brief Ejecuta los hilos para realizar la operación de cifrado/descifrado.
 *
 * @param key Clave utilizada para la operación de cifrado/descifrado.
 */
unsigned int CipherSuite::runThreads(byte* key) {
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
			// Cuando se llega al número máximo de hilos concurrentes se bloquea la creación de nuevos hilos
			// Si no se bloquea puede generar condiciones de carrera
			// TODO ... Verificar si dejando el mutex de thread pool antes de la escritura se cumple el numero de threadpools sin generar condiciones de carrera
			for (auto& t : t_params.threads) {
				if (t.joinable()) {
					t.join();
				}
			}
			t_params.threads.clear();
		}


	}

	// Espera a los hilos faltantes (Número de hilos % Thread Pool)
	for (auto& t : t_params.threads) {
		if (t.joinable()) {
			t.join();
		}
	}

	t_params.threads.clear();
	std::cout << "Max concurrent threads: " << max_concurrent_threads << std::endl;
	return 1;
}

/**
 * @brief Genera una clave PSK (Pre-Shared Key).
 *
 * @param pskKey Buffer donde se almacenará la clave PSK generada.
 * @param keySize Tamaño de la clave PSK.
 * @return int 0 si la generación de la clave PSK fue exitosa, otro valor en caso de error.
 */
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