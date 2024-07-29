//
// Created by danny on 7/28/24.
//
#include <iostream>
#include "CipherSuite.h"

#include "EarthClient/EarthBase.h"
#include "SpaceServer/Satellite.h"
#include <wolfssl/wolfcrypt/pwdbased.h>

int main() {
    std::cout << "Hello, World!" << std::endl;
    EarthBase earth_base;
    Satellite satellite;
    // Compartir las llaves publicas entre si
    ecc_key pubEarth = earth_base.getPub();
    ecc_key pubSat = satellite.getPub();
    // Generar llave de sesion para cada uno
    earth_base.setKeySession(pubSat);
    satellite.setKeySession(pubEarth);
    // Encryptar y desencriptar
    const std::string input_path = "Prueba.jpg";
    const std::string encrypted_path = "encrypted.jpg";
    const std::string decrypted_path = "decrypted.jpg";

    satellite.encryptMessage(satellite.keySession, input_path, encrypted_path);
    earth_base.decryptMessage(earth_base.keySession, encrypted_path, decrypted_path);

    return 0;
}
