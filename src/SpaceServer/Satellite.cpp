#include "Satellite.h"

#include <iostream>
#include <string>
#include <algorithm>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/aes.h>

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
	std::ofstream ouFile("prueba.bin", std::ios::out | std::ios::trunc);
	ouFile.close();

	int secretRandom = byteArrayToInt(randomBlock);
	std::memcpy(&secretRandom, randomBlock, sizeof(int));
	
	// Multiplicar numero primo grande con el random generado
	std::string big_num = multiplyLargeNumber(getPrime(), abs(secretRandom) % 10000000);
	size_t big_num_size = big_num.size();

	std::cout << "Tamano primo grande: " << big_num_size << std::endl;
	std::cout << "Numero primo grande: " << big_num << std::endl;
	
	byte* cipheredLargeNumber = new byte[big_num_size];

	// Convertuir el entero cipherLen a bytes
	std::vector<char> cipherBytesLen(sizeof(size_t));
	memcpy(cipherBytesLen.data(), &big_num_size, sizeof(size_t));	

	this->writeParams(reinterpret_cast<const byte*>(cipherBytesLen.data()), sizeof(size_t));


	encryptPreParams(big_num, cipheredLargeNumber);
	
    
	this->writeParams(cipheredLargeNumber, big_num_size);
	
	
	// Convertir el hint a bytes para poder escribirlo en el archivo
	const byte* serverHintByte = reinterpret_cast<const byte*>(serverHint);
	size_t byteSize = strlen(serverHint);
	this->writeParams(serverHintByte, byteSize) ;
	
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
	this->writeParams(iv, 12) ;
	this->writeParams(authTag, 16);

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

void Satellite::writeParams(const byte* data, std::size_t dataSize) {

	std::ofstream outFile("prueba.bin", std::ios::binary | std::ios::app); // std::ios::app para hacer append

    outFile.write(reinterpret_cast<const char*>(data), dataSize);
	std::cout << "Tamano agregado: " << dataSize << std::endl;
    
    outFile.close();
}
