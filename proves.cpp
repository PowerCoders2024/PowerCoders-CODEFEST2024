//
// Created by danny on 7/28/24.
//
#include <iostream>
#include "CipherSuite.h"

#include "EarthClient/EarthBase.h"
#include "SpaceServer/Satellite.h"
#include <wolfssl/wolfcrypt/pwdbased.h>
#include <wolfssl/ssl.h>


//Client - > ClientHello -> Server
//Server -> hint a cliente -> Client
// Client (hint para buscar su identidad) - > cb cliente -> Server
//Server (return client cb, usa en cb server)


int main() {
    // std::cout << "Hello, World!" << std::endl;

    // std::cout << "Hello, World!" << std::endl;
    // EarthBase earth_base;
    // Satellite satellite;
    // // Compartir las llaves publicas entre si
    // ecc_key pubEarth = earth_base.getPub();
    // ecc_key pubSat = satellite.getPub();
    // // Generar llave de sesion para cada uno
    // earth_base.setKeySession(pubSat);
    // satellite.setKeySession(pubEarth);
    // // Encryptar y desencriptar
    // byte* cipher = nullptr;
    // size_t cipher_size = 0;
    // byte* authTag = nullptr;
    // size_t authTagSz = 0;
    // byte* authIn = nullptr;
    // size_t authInSz = 0;
    // satellite.encryptMessage(satellite.keySession, "Westcol vendiendo empanadas con aji y un poco de semen",&cipher, &cipher_size, &authTag, &authTagSz,&authIn, &authInSz);
    // earth_base.decryptMessage(earth_base.keySession,cipher,cipher_size,authTag,authTagSz,authIn, authInSz);
    EarthBase earth_base;
    Satellite satellite;
    earth_base.receiveServerHint(satellite);
    earth_base.sendIdentity(satellite);

    return 0;
}

