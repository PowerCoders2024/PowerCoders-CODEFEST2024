//
// Created by danny on 7/28/24.
//

#ifndef SATELLITE_H
#define SATELLITE_H

#include "../CryptoUser/CryptoUser.h"

#include <wolfssl/ssl.h>
class Satellite : public CryptoUser {
	const char *serverHint = "satellite_identity";
	const char *client_identity = "earth_identity";

public:
	WOLFSSL *ssl;

	Satellite();

	// Inicializar
	int initializeSatellite();

	unsigned int verifyClientIdentity(WOLFSSL *ssl, const char *identity);
};

#endif	// SATELLITE_H
