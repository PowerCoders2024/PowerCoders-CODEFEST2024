#ifndef SATELLITE_H
#define SATELLITE_H
#include "../CryptoUser/CryptoUser.h"
#include <wolfssl/ssl.h>


class Satellite : public CryptoUser {
    WOLFSSL_CTX *ctx = nullptr;
    const char *serverHint = "id_server";
    const char *psk_key = "123456"; // Clave PSK

public:
    WOLFSSL *ssl;

    Satellite();

    //Inicializar
    int initialize();

    unsigned int verifyClientIdentity(WOLFSSL *ssl, const char *identity,
                                      unsigned char *key, unsigned int key_max_len);
    
    void clear();
};

#endif //SATELLITE_H
