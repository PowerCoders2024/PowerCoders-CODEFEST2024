#ifndef EARTHBASE_H
#define EARTHBASE_H

#include "../CryptoUser/CryptoUser.h"
#include "../SpaceServer/Satellite.h"

#include <wolfssl/ssl.h>
class EarthBase : public CryptoUser {
	const char *client_identity = "earth_identity";
	const char *server_hint = "satellite_identity";

public:
	WOLFSSL *ssl;
	EarthBase();
	void initializeEarthBase();
	unsigned int receiveServerHint(Satellite satellite);
	void sendIdentity(Satellite satellite);
};

#endif	// EARTHBASE_H
