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
	std::cout << "Satelite inicializado ";
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


unsigned int Satellite::sendEncryptedParams()
{
	int secretRandom;
	std::memcpy(&secretRandom, randomBlock, sizeof(int));
	std::cout << "Secret Random: " << secretRandom << std::endl;
	// TODO: No esta multiplicando bien
	std::string multipliedPrime = multiplyLargeNumber(CryptoUser::prime, abs(secretRandom));
	byte* cipherLargeNumber = new byte[multipliedPrime.size()];
	// std::cout << multipliedPrime;
	encryptPreParams(multipliedPrime, cipherLargeNumber);
	std::cout << cipherLargeNumber << std::endl;
	writeParams("Prueba.bin",cipherLargeNumber,multipliedPrime.size(), serverHint);
	readBytes("Prueba.bin",0,multipliedPrime.size());
	readBytes("Prueba.bin",multipliedPrime.size(),-1);
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

	// Apuntar al valor de ciphertext
	std::memcpy(cipheredParams, ciphertext, plaintextLen); // Copiar el contenido

	return 0;

	// TODO: Pasar a EathBase
	byte decryptedText[plaintextLen];
	// Desencriptar los datos
	if (wc_AesGcmDecrypt(&aes, decryptedText, ciphertext, plaintextLen, iv, sizeof(iv), authTag, sizeof(authTag), nullptr, 0) != 0) {
		std::cerr << "Error al desencriptar los datos" << std::endl;
		wolfSSL_Cleanup();
		return 1;
	}

	std::cerr << "DESENCRIPTADO: " << std::endl;
	// Convertir el array de bytes a un std::string
	std::string decryptedString(reinterpret_cast<char*>(decryptedText), plaintextLen);

	// Imprimir el string
	std::cout << "Decrypted text: " << decryptedString << std::endl;

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
unsigned int Satellite::writeParams( const std::string& filename, const byte* data, std::size_t dataSize, const std::string& str) {

	const byte* strData = reinterpret_cast<const byte*>(str.c_str());
	std::size_t strSize = str.size();

	std::size_t totalSize = dataSize + strSize;
	byte* buffer = new byte[totalSize];
	std::memcpy(buffer, data, dataSize);
	std::memcpy(buffer + dataSize, strData, strSize);


	std::ofstream outFile(filename, std::ios::binary | std::ios::trunc);

	if (!outFile) {
		std::cerr << "Error: No se pudo abrir el archivo para escribir: " << filename << std::endl;
		delete[] buffer;
		return 1;
	}

	outFile.write(reinterpret_cast<const char*>(buffer), totalSize);

	if (!outFile.good()) {
		std::cerr << "Error: Hubo un problema al escribir en el archivo." << std::endl;
		delete[] buffer;
		return 1;
	} else {
		std::cout << "Los datos fueron escritos exitosamente en: " << filename << std::endl;
	}

	outFile.close();
	delete[] buffer;
	return 0;
}

byte* Satellite::readBytes(std::string filename , size_t initBytes, size_t finalBytes) {

	std::ifstream inputFile(filename, std::ios::binary);
	if (finalBytes == -1 ) {
		inputFile.seekg(0, std::ios::end);
		size_t fileSize = inputFile.tellg();
		finalBytes = fileSize;
	}
	size_t numBytesToRead = finalBytes - initBytes;
	byte* buffer = new byte[numBytesToRead];

	if (!inputFile) {
		std::cerr << "Error: No se pudo abrir el archivo " << filename << std::endl;
	}

	inputFile.seekg(initBytes, std::ios::beg);
	inputFile.read(reinterpret_cast<char*>(buffer), numBytesToRead);

	size_t bytesRead = inputFile.gcount();
	if (bytesRead < numBytesToRead) {
		std::cerr << "Advertencia: Solo se leyeron " << bytesRead << " bytes en lugar de " << numBytesToRead << std::endl;
	} else {
		std::cout << "Se leyeron los bytes entre " << initBytes << " y " << finalBytes << " correctamente." << std::endl;
	}

	std::cout << "Readed : " <<  buffer << std::endl;

	return  buffer;
}