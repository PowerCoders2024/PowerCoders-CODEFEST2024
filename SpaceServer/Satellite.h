//
// Created by danny on 7/28/24.
//

#ifndef SATELLITE_H
#define SATELLITE_H

#include "../CryptoUser/CryptoUser.h"

#include <wolfssl/ssl.h>
class Satellite : public CryptoUser
{


public:
	WOLFSSL *ssl;
	const char *serverHint = "satellite_identity";
	const char *client_identity = "earth_identity";

	Satellite();

	// Inicializar
	unsigned int initializeSatellite();

	unsigned int verifyClientIdentity(WOLFSSL *ssl, const char *identity);
};

#endif // SATELLITE_H
