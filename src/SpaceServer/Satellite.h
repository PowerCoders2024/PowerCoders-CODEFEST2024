//
// Created by danny on 7/28/24.
//

#ifndef SATELLITE_H
#define SATELLITE_H

#include "../CryptoUser/CryptoUser.h"

class Satellite : public CryptoUser
{
	const char *serverHint = "satellite_identity";
	const char *client_identity = "earth_identity";
	byte randomBlock[4];

public:

	Satellite();

	unsigned int initializeSatellite();
	unsigned int sendEncryptedParams();
	unsigned int encryptPreParams(std::string secretRandom );
	static std::string multiplyLargeNumber(const std::string &prime, int multiplier);
};

#endif // SATELLITE_H
