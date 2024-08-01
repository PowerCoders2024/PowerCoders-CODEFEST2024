#include "EarthBase.h"

#include <wolfssl/ssl.h>

EarthBase::EarthBase() : CryptoUser() {}

void EarthBase::initializeEarthBase() {
	std::cout << "Client: Client Hello" << " Communication established -->" << std::endl;
	WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfTLS_client_method());
	if (ctx == nullptr) {
		printf("wolfSSL_CTX_new error.\n");
	}
	this->ssl = wolfSSL_new(ctx);
	if (this->ssl == nullptr) {
		printf("wolfSSL_new error.\n");
	}
}

unsigned int EarthBase::receiveServerHint(Satellite satellite) {
	std::cout << "<-- Server: Server Hello (ServerExchange Hint)" << std::endl;
	const char *idHintRetrieved = wolfSSL_get_psk_identity_hint(satellite.ssl);
	if (std::strcmp(idHintRetrieved, this->server_hint) == 0) {
		std::cout << "Client: Hint recongnized= " << idHintRetrieved << std::endl;
	} else {
		std::cerr << "Unknown device" << std::endl;
		return 0;
	}
	std::cout << " <-- Server Hello Done" << std::endl;
	// strncpy(identity, this->client_identity, id_max_len);
	// strncpy(reinterpret_cast<char *>(key), psk_key, key_max_len);
	return sizeof(this->pskKey);
}

void EarthBase::sendIdentity(Satellite satellite) {
	std::cout << "Client: Client Exchange Identity -->  " << std::endl;

	unsigned int clientVerify = satellite.verifyClientIdentity(this->ssl, this->client_identity);

	if (clientVerify > 0) {
		std::cout << "Client: Finished (client) -->" << std::endl;
		std::cout << "Autenticación PSK exitosa." << std::endl;
		std::cout << "Clave PSK  usar : ";
		for (int i = 0; i < sizeof(this->pskKey); i++) {
			printf("%02x", pskKey[i]);
		}
		printf("\n");
		// Enviar ultimo mensaje encriptado con la psk y termina
	} else {
		std::cout << "Autenticación PSK fallida.";
	}
}
