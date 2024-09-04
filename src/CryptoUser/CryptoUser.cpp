#include "CryptoUser.h"
#include "../CipherSuite.h"
#include <wolfssl/ssl.h>

// TODO: Modificar PSK
byte CryptoUser::pskKey[16] = {0} ;
std::string CryptoUser::prime = readFile("src/pre-saved-parameters/prime2048.txt");
std::string CryptoUser::seed = readFile("src/pre-saved-parameters/seed.txt");

CryptoUser::CryptoUser() {

}

const std::string& CryptoUser::getPrime() {
    return prime;
}

const std::string& CryptoUser::getSeed() {
    return seed;
}

void CryptoUser::derivePBKDF2Key(const byte* passwordSeed, size_t passwordSeedLen, const byte* saltSeed, size_t saltSeedLen, byte* output, size_t outputLen, int iterations) {
    // Genera la clave derivada usando PBKDF2
    int ret = wc_PBKDF2(output, passwordSeed, passwordSeedLen, saltSeed, saltSeedLen, iterations, outputLen, WC_SHA256);
    if (ret != 0) {
        std::cerr << "Error en wc_PBKDF2: " << ret << std::endl;
    }
}

/**
 * @brief Cifra un mensaje.
 *
 * @param key Clave utilizada para el cifrado.
 * @param input_path Ruta del archivo de entrada.
 * @param output_path Ruta del archivo de salida.
 */
void CryptoUser::encryptMessage(byte key[], const std::string &input_path, const std::string &output_path) {
	this->cipher_suite.performOperation(true, key, input_path, output_path);
}

/**
 * @brief Descifra un mensaje.
 *
 * @param key Clave utilizada para el descifrado.
 * @param input_path Ruta del archivo de entrada.
 * @param output_path Ruta del archivo de salida.
 */
void CryptoUser::decryptMessage(byte key[], const std::string &input_path, const std::string &output_path) {
	this->cipher_suite.performOperation(false, key, input_path, output_path);
}

std::string CryptoUser::readFile(std::string filePath) {

	std::ifstream file(filePath);
	if (!file.is_open()) {
		std::cerr << "Error al abrir el archivo: " << filePath << std::endl;
	}
	std::ostringstream oss;
	oss << file.rdbuf();
	file.close();
	std::string fileContent = oss.str();
	return  fileContent;

}
