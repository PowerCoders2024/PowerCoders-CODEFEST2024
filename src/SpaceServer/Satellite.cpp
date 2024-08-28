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
	std::cout << std::endl;
	int secretRandom;
	std::memcpy(&secretRandom, randomBlock, sizeof(int));
	std::cout << "Secret Random: " << secretRandom << std::endl;
    // TODO: Leer el primo del archivo para psarlo por paramtro
	std::string multipliedPrime = multiplyLargeNumber("1", abs(secretRandom));
	encryptPreParams(multipliedPrime);


	return 0;
}
unsigned int Satellite::encryptPreParams(std::string secretRandom) {

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
		return -1;
	}

	if (wc_AesGcmEncrypt(&aes, ciphertext, plaintext, plaintextLen, iv, sizeof(iv), authTag, sizeof(authTag), nullptr, 0) != 0) {
		std::cerr << "Error al encriptar los datos" << std::endl;
		wolfSSL_Cleanup();
		return -1;
	}


	byte decryptedText[plaintextLen];


	// TODO: Pasar a EathBase
	// Desencriptar los datos
	if (wc_AesGcmDecrypt(&aes, decryptedText, ciphertext, plaintextLen, iv, sizeof(iv), authTag, sizeof(authTag), nullptr, 0) != 0) {
		std::cerr << "Error al desencriptar los datos" << std::endl;
		wolfSSL_Cleanup();
		return -1;
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

    // Multiplicar cada dígito del número grande empezando desde el final
    for (int i = prime.size() - 1; i >= 0; --i) {
        int digit = prime[i] - '0';
        long long product = digit * multiplier + carry;
        carry = product / 10;
        result.push_back((product % 10) + '0');
    }

    // Si queda un acarreo, agregarlo al principio del resultado
    while (carry) {
        result.push_back((carry % 10) + '0');
        carry /= 10;
    }

    // Invertir el resultado para que quede en el orden correcto
    reverse(result.begin(), result.end());

    return result;
}
