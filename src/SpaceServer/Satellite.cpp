#include "Satellite.h"

#include <iostream>
#include <string>
#include <algorithm>
#include <wolfssl/ssl.h>

Satellite::Satellite() : CryptoUser() {}

/**
 * @brief Inicializa los datos para la operación.
 **/
unsigned int Satellite::initializeSatellite()
{
	// TODO: Iniciar el initRNG para el numero aleatorio
	WC_RNG rng;
	if (wc_InitRng(&rng) != 0) {
		std::cerr << "Error al inicializar el RNG" << std::endl;
		return 1;
	}
	if (wc_RNG_GenerateBlock(&rng, randomBlock, 4) != 0) {
		std::cerr << "Error al generar números aleatorios" << std::endl;
		wc_FreeRng(&rng);
		return 1;
	}

	wc_FreeRng(&rng);

	return 0;
}

void intToByteArray(int value, byte arr[4]) {
    for (int i = 0; i < 4; ++i) {
        arr[i] = (value >> (i * 8)) & 0xFF;
    }
}

int byteArrayToInt(const byte arr[4]) {
    int value = 0;
    for (int i = 0; i < 4; ++i) {
        value |= arr[i] << (i * 8);  // Copiamos los bytes en orden little-endian
    }
    return value;
}

unsigned int Satellite::sendEncryptedParams()
{

	int secretRandom = byteArrayToInt(randomBlock);;
	std::memcpy(&secretRandom, randomBlock, sizeof(int));
	// Multiplicar numero primo grande con el random generado
	std::string multipliedPrime = multiplyLargeNumber(getPrime(), abs(secretRandom) % 10000000);


	byte* cipherLargeNumber = new byte[multipliedPrime.size()];
	std::ofstream outFile("Prueba.bin", std::ios::out | std::ios::trunc);
	outFile.close();
	
	size_t cipherLen = multipliedPrime.size();
	// Convertuir el entero cipherLen a bytes
	byte cipherBytesLen[8];
	memcpy(cipherBytesLen, &cipherLen, sizeof cipherLen);	
	writeParams("Prueba.bin", cipherBytesLen, sizeof(cipherBytesLen));
	
	
	encryptPreParams(multipliedPrime, cipherLargeNumber);
	
	writeParams("Prueba.bin", cipherLargeNumber, multipliedPrime.size()) ;

	
	
	// Convertir el hint a bytes para poder escribirlo en el archivo
	const byte* serverHintByte = reinterpret_cast<const byte*>(serverHint);
	size_t byteSize = strlen(serverHint);
	writeParams("Prueba.bin", serverHintByte, byteSize) ;
	
	
	
	return 0;
}

unsigned int Satellite::encryptPreParams(const std::string& secretRandom, byte* cipheredParams) {

	byte* plaintext = new byte[secretRandom.size()];
	std::memcpy(plaintext, secretRandom.c_str(), secretRandom.size());
	int plaintextLen = secretRandom.size()  ;

	byte iv[12];
	WC_RNG rngIv;
	wc_InitRng(&rngIv);
	wc_RNG_GenerateBlock(&rngIv, iv, 12);
	byte ciphertext[plaintextLen];
	byte authTag[16];

	Aes aes;
	if (wc_AesGcmSetKey(&aes, pskKey, sizeof(pskKey)) != 0) {
		std::cerr << "Error al establecer la clave AES-GCM" << std::endl;
		wolfSSL_Cleanup();
		return 1;
	}

	if (wc_AesGcmEncrypt(&aes, ciphertext, plaintext, plaintextLen, iv, sizeof(iv), authTag, sizeof(authTag), nullptr, 0) != 0) {
		std::cerr << "Error al encriptar los datos" << std::endl;
		wolfSSL_Cleanup();
		return 1;
	}
	writeParams("Prueba.bin",iv,12) ;
	writeParams("Prueba.bin",authTag,16);

	// Apuntar al valor de ciphertext
	std::memcpy(cipheredParams, ciphertext, plaintextLen);
	return 0;


}

// Función para multiplicar un número grande representado como una cadena por un número entero pequeño (int)
std::string  Satellite::multiplyLargeNumber(const std::string &prime, int multiplier) {
    long long carry = 0;
    std::string result;
	
    for (int i = prime.size() - 1; i >= 0; --i) {
        int digit = prime[i] - '0';
        long long product = digit * multiplier + carry;
        carry = product / 10;
        result.push_back((product % 10) + '0');
    }
	
    while (carry) {
        result.push_back((carry % 10) + '0');
        carry /= 10;
    }
	
    reverse(result.begin(), result.end());

    return result;
}

// TODO: Quitar return
unsigned int Satellite::writeParams(const std::string& filename, const byte* data, std::size_t dataSize) {

	std::ofstream outFile(filename, std::ios::binary | std::ios::app); // std::ios::app para hacer append
    if (!outFile) {
        std::cerr << "Error: No se pudo abrir el archivo para escribir: " << filename << std::endl;
        return 1;
    }

    outFile.write(reinterpret_cast<const char*>(data), dataSize);
    if (!outFile.good()) {
        std::cerr << "Error: Hubo un problema al escribir en el archivo." << std::endl;
        return 1;
    }
	std::streampos fileSize = outFile.tellp();
    outFile.close();
    // Retornar el tamaño en bytes de la última escritura
	return static_cast<unsigned int>(fileSize);
}
