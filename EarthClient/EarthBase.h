#ifndef EARTHBASE_H
#define EARTHBASE_H

#include "../CryptoUser/CryptoUser.h"
#include "../SpaceServer/Satellite.h"

#include <wolfssl/ssl.h>
class EarthBase : public CryptoUser
{


public:
	WOLFSSL *ssl;
	const char *client_identity = "earth_identity";
	const char *server_hint = "satellite_identity";
	EarthBase();
	unsigned int initializeEarthBase();
	unsigned int receiveServerHint(Satellite &satellite);
	unsigned int sendIdentity(Satellite &satellite);
};

#endif // EARTHBASE_H
