#include "CryptoUser.h"

#include "../CipherSuite.h"

// TODO: Iniciar valores estaticos: Primo, Semilla , Modificar PSK
byte CryptoUser::pskKey[16] = {0} ;
byte CryptoUser::prime[256] = {0} ;
byte CryptoUser::seed[32] = {0} ;

CryptoUser::CryptoUser() {
	
}

/**
 * @brief Inicializa la suite de operación 
 */
void CryptoUser::initializeCryptoUser() {
	std::cout << "Suite iniciada" << std::endl;
	this->cipher_suite.initializeCipherSuite();
	std::cout << "Claves generadas correctamente" << std::endl;
	this->cipher_suite.keyGenerator(this->priv);
}

/**
 * @brief Obtiene la clave pública ECC.
 *
 * @return ecc_key Clave pública ECC.
 */
ecc_key CryptoUser::getPub() const { return this->priv; }

/**
 * @brief Establece la clave de sesión.
 *
 * @param userPub Clave pública del usuario.
 */
void CryptoUser::setKeySession(ecc_key userPub) {
	std::cout << keySessionSz << std::endl;
	std::cout << "Shared key:" << wc_ecc_shared_secret(&priv, &userPub, this->keySession, &this->keySessionSz) << std::endl;

	// Copia a la llave de la session los ultimos 16 bytes
	memcpy(keySession + 16, pskKey, 16);
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
