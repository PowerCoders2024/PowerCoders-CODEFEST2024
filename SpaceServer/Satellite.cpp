//
// Created by danny on 7/28/24.
//

#include "Satellite.h"

Satellite::Satellite(): CryptoUser() {
    ctx = nullptr;
    ssl = nullptr;
    initialize();
}

int Satellite::initialize() {
    wolfSSL_Init();


    // Crear contexto y método
    WOLFSSL_METHOD *method = wolfTLSv1_3_server_method();
    if (method == nullptr) {
        std::cerr << "Error iniciando el metodo WOLFSSL" << std::endl;
        return -1;
    }

    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(method);
    if (ctx == nullptr) {
        std::cerr << "Error iniciando CTX sesion" << std::endl;
        return -1;
    }

    // Configurar el PSK identity hints
    int retMemHint = wolfSSL_CTX_use_psk_identity_hint(ctx, serverHint);
    wolfSSL_CTX_set_cipher_list(ctx, "PSK-AES128-CBC-SHA256");
    if (retMemHint == SSL_SUCCESS) {
        // std::cout << "Hint guardado en memoria correctamente" << std::endl;
        // std::cout << "Hint: " << this->serverHint << std::endl;
    } else {
        std::cerr << "El hint No se guardo en memoria" << std::endl;
    }

    this->ssl = wolfSSL_new(ctx);
    if (this->ssl == nullptr) {
        std::cerr << "Error creando la nueva sesión SSL" << std::endl;
        wolfSSL_CTX_free(ctx);
        return -1;
    }

    return 0;
}

unsigned int Satellite::verifyClientIdentity(WOLFSSL *ssl, const char *identity ) {
    if (identity == nullptr) {
        return 0;
    }
    if (std::strcmp (identity , this->client_identity) == 0  ) {
        std::cout << "Server: Client ready with PSK identity." << std::endl;
        std::cout << "Identity: " << identity << std::endl;
        std::cout << "PSK key: ";
        for (int i = 0; i < sizeof(this->pskKey); i++) {
            printf("%02x", pskKey[i]);
        }
        printf("\n");
        return sizeof(this->pskKey);
    }
    return 0; // No coincide la identidad
}

// void Satellite::authenticateClient(EarthBase earth_base) {
//     char identity[256];
//     unsigned char key[256];
//     unsigned int key_len = earth_base.myPskClient(earth_base.ssl, this->serverHint, identity, sizeof(identity), key,
//                                                   sizeof(key));
//     if (key_len > 0) {
//         std::cout << "Client ready with PSK identity." << std::endl;
//         std::cout << "Identity: " << identity << std::endl;
//         std::cout << "PSK key: " << key << std::endl;
//     } else {
//         std::cerr << "Client PSK preparation failed" << std::endl;
//     }
// }

void Satellite::clear() {
    wolfSSL_free(this->ssl);
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
}


