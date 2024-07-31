//
// Created by danny on 7/28/24.
//

#ifndef SATELLITE_H
#define SATELLITE_H
#include "../CryptoUser/CryptoUser.h"
#include <wolfssl/ssl.h>


class Satellite : public CryptoUser {
    WOLFSSL_CTX *ctx = nullptr;
    const char *serverHint = "satellite_identity";
    const char *client_identity = "earth_identity";

public:
    WOLFSSL *ssl;

    Satellite();

    //Inicializar
    int initialize();

    unsigned int verifyClientIdentity(WOLFSSL *ssl, const char *identity);

    void clear();
};

#endif //SATELLITE_H
