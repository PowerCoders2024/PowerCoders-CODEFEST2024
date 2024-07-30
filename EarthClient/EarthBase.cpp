//
// Created by danny on 7/28/24.
//

#include "EarthBase.h"

EarthBase::EarthBase() : CryptoUser() {
    std::cout << "Client Hello" << std::endl;
    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (ctx == nullptr) {
        printf("wolfSSL_CTX_new error.\n");
    }
    this->ssl = wolfSSL_new(ctx);
    if (this->ssl == nullptr) {
        printf("wolfSSL_new error.\n");
    }
    std::cout << "Communication established" << std::endl;
}

unsigned int EarthBase::receiveServerHint(Satellite satellite) {
    std::cout << "Server Hello (Exchange)" << std::endl;
    if (const char *idHintRetrieved = wolfSSL_get_psk_identity_hint(satellite.ssl)) {
        std::cout << "Hint retrieved: " << idHintRetrieved << std::endl;
    } else {
        std::cerr << "El hint no fue creado correctamente" << std::endl;
    }

    // strncpy(identity, this->client_identity, id_max_len);
    // strncpy(reinterpret_cast<char *>(key), psk_key, key_max_len);
    return strlen(psk_key);
}

void EarthBase::sendIdentity(Satellite satellite) {
    std::cout << "Client Exchange" << std::endl;
    unsigned char key[256]; // Buffer llave obtenida
    satellite.verifyClientIdentity(this->ssl, this->client_identity, key, sizeof(key));
    if (strncmp(reinterpret_cast<const char *>(key), this->psk_key, sizeof(key)) == 0) {
        std::cout << "Autenticación PSK exitosa." << std::endl;
        std::cout << "Clave PSK: " << key << std::endl;
        std::cout << "Finished (client)" << std::endl;
    } else {
        std::cout << "Autenticación PSK fallida.";
    }
}

