#ifndef EARTHBASE_H
#define EARTHBASE_H


#include "../CryptoUser/CryptoUser.h"
#include "../SpaceServer/Satellite.h"
#include <wolfssl/ssl.h>

class EarthBase : public CryptoUser {
    const char *client_identity = "Client_identity";
    const char *psk_key = "123456"; // Clave PSK
public:
    WOLFSSL *ssl;

    EarthBase();

    unsigned int receiveServerHint(Satellite satellite);

    void sendIdentity(Satellite satellite);

    // static void receiveServerHint(Satellite satellite);
};


#endif //EARTHBASE_H
