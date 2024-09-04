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
	static unsigned int  writeParams(const std::string& filename, const byte* data, size_t size );
	static std::string multiplyLargeNumber(const std::string &prime, int multiplier);
	static unsigned int encryptPreParams(const std::string& secretRando, byte* cipheredParams);

public:

	Satellite();
	unsigned int initializeSatellite();
	unsigned int sendEncryptedParams(size_t& sizeLargeNumber, size_t& sizeHint);
	byte randomBlock[4];
	
};

#endif // SATELLITE_H
