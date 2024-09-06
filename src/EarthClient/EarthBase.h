#ifndef EARTHBASE_H
#define EARTHBASE_H

#include "../CryptoUser/CryptoUser.h"
#include "../SpaceServer/Satellite.h"

class EarthBase : public CryptoUser
{
	const char *client_identity = "earth_identity";
	const char *server_hint = "satellite_identity";
	byte* readBytes(size_t finalBytes) ;

public:
	EarthBase(const std::string &input_path,const std::string &output_path) ;
	unsigned int initializeEarthBase();
	unsigned int receiveServerParams();
	static std::string decryptParams(byte ciphertext[], size_t plaintextLen, byte iv[12], byte authTag[16]);
	byte randomNumber[4];

};

#endif // EARTHBASE_H
