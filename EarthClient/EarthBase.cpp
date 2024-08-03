#include "EarthBase.h"

#include <wolfssl/ssl.h>

EarthBase::EarthBase() : CryptoUser() {}

unsigned int EarthBase::initializeEarthBase()
{
	std::cout << "Client: Client Hello" << " Communication established -->" << std::endl;
	WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfTLS_client_method());
	if (ctx == nullptr)
	{
		printf("wolfSSL_CTX_new error.\n");
		return 0;
	}
	this->ssl = wolfSSL_new(ctx);
	if (this->ssl == nullptr)
	{
		printf("wolfSSL_new error.\n");
		return 0;
	}
	return 1;
}

/**
 * @brief Recibe el hint del servidor.
 *
 * @param satellite Objeto Satellite para la comunicación.
 * @return unsigned int Tamaño de la clave PSK si el hint es reconocido, 0 en caso contrario.
 */
unsigned int EarthBase::receiveServerHint(Satellite &satellite)
{
	std::cout << "<-- Server: Server Hello (ServerExchange Hint)" << std::endl;
	const char *idHintRetrieved = wolfSSL_get_psk_identity_hint(satellite.ssl);
	if (std::strcmp(idHintRetrieved, this->server_hint) == 0)
	{
		std::cout << "Client: Hint recongnized= " << idHintRetrieved << std::endl;
	}
	else
	{
		std::cerr << "Unknown device" << std::endl;
		return 0;
	}
	std::cout << " <-- Server Hello Done" << std::endl;
	return sizeof(this->pskKey);
}

/**
 * @brief Envía la identidad del cliente al servidor.
 *
 * @param satellite Objeto Satellite para la comunicación.
 * @return unsigned int 1 si la autenticación PSK fue exitosa, 0 en caso contrario.
 */
unsigned int EarthBase::sendIdentity(Satellite &satellite)
{
	std::cout << "Client: Client Exchange Identity -->  " << std::endl;
	unsigned int clientVerify = satellite.verifyClientIdentity(this->ssl, this->client_identity);
	if (clientVerify > 0)
	{
		std::cout << "Client: Finished (client) -->" << std::endl;
		std::cout << "Autenticación PSK exitosa." << std::endl;
		std::cout << "Clave PSK  usar : ";
		for (int i = 0; i < sizeof(this->pskKey); i++)
		{
			printf("%02x", pskKey[i]);
		}
		printf("\n");
		// Enviar ultimo mensaje encriptado con la psk y termina
	}
	else
	{
		std::cout << "Autenticación PSK fallida.";
		return 0;
	}
	return 1;
}
