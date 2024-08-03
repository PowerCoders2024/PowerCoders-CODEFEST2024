#include "Satellite.h"

#include <wolfssl/ssl.h>

Satellite::Satellite() : CryptoUser() {}

/**
 * @brief Inicializa los datos para la operación.
 **/
unsigned int Satellite::initializeSatellite()
{
	wolfSSL_Init();
	this->ssl = nullptr;
	WOLFSSL_CTX *ctx = nullptr;

	// Crear contexto y método
	WOLFSSL_METHOD *method = wolfTLS_server_method();
	if (method == nullptr)
	{
		std::cerr << "Error iniciando el metodo WOLFSSL" << std::endl;
		return 0;
	}

	ctx = wolfSSL_CTX_new(method);
	if (ctx == nullptr)
	{
		std::cerr << "Error iniciando CTX sesion" << std::endl;
		return 0;
	}

	// Configurar el PSK identity hints
	int retMemHint = wolfSSL_CTX_use_psk_identity_hint(ctx, serverHint);
	wolfSSL_CTX_set_cipher_list(ctx, "PSK-AES128-CBC-SHA256");
	if (retMemHint == SSL_SUCCESS)
	{
		std::cout << "Hint guardado en memoria correctamente" << std::endl;
		std::cout << "Hint: " << this->serverHint << std::endl;
	}
	else
	{
		std::cerr << "El hint No se guardo en memoria" << std::endl;
		return  0;
	}

	this->ssl = wolfSSL_new(ctx);
	printf("%p", this->ssl); // Fix: Change the argument to a valid format
							 // specifier for a pointer
	if (this->ssl == nullptr)
	{
		std::cerr << "Error creando la nueva sesión SSL" << std::endl;
		wolfSSL_CTX_free(ctx);
		return 0;
	}

	return 1;
}


/**
 * @brief Verifica la identidad del cliente.
 *
 * @param ssl Estructura WOLFSSL para la comunicación.
 * @param identity Identidad del cliente.
 * @return unsigned int Tamaño de la clave PSK si la identidad es verificada, 0 en caso contrario.
 */
unsigned int Satellite::verifyClientIdentity(WOLFSSL *ssl, const char *identity)
{
	if (identity == nullptr)
	{
		return 0;
	}
	if (std::strcmp(identity, this->client_identity) == 0)
	{
		std::cout << "Server: Client ready with PSK identity." << std::endl;
		std::cout << "Identity: " << identity << std::endl;
		std::cout << "PSK key: ";
		for (int i = 0; i < sizeof(this->pskKey); i++)
		{
			printf("%02x", pskKey[i]);
		}
		printf("\n");
		return sizeof(this->pskKey);
	}
	return 0; // No coincide la identidad
}
