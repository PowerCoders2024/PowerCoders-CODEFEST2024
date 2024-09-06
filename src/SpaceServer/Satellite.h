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
	void writeParams(const byte* data, std::size_t dataSize);
	std::string multiplyLargeNumber(const std::string &prime, int multiplier);
	unsigned int encryptPreParams(const std::string& secretRando, byte* cipheredParams);

public:

	Satellite();
	unsigned int initializeSatellite();
	unsigned int sendEncryptedParams();
	byte randomBlock[4];
	
};

#endif // SATELLITE_H
