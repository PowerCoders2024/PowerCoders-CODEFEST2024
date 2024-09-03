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
	static unsigned int  writeParams(const std::string& filename, const byte* data, std::size_t size , const std::string& str);
	static std::string multiplyLargeNumber(const std::string &prime, int multiplier);
	static unsigned int encryptPreParams(const std::string& secretRando, byte* cipheredParams);
public:

	Satellite();
	unsigned int initializeSatellite();
	unsigned int sendEncryptedParams();
	byte* readBytes(std::string filename ,size_t initBytes, size_t finalBytes);



};

#endif // SATELLITE_H
