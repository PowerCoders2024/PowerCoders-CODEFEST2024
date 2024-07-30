#include <iostream>
#include <fstream>
#include "CipherSuite.h"
#include "EarthClient/EarthBase.h"
#include "SpaceServer/Satellite.h"
#include <wolfssl/wolfcrypt/pwdbased.h>

int main() {
    std::cout << "Hello, World!" << std::endl;
    EarthBase earth_base;
    Satellite satellite;

    // Compartir las llaves públicas entre sí
    ecc_key pubEarth = earth_base.getPub();
    ecc_key pubSat = satellite.getPub();

    // Generar llave de sesión para cada uno
    earth_base.setKeySession(pubSat);
    satellite.setKeySession(pubEarth);

    // Encryptar y desencriptar
    byte* cipher = nullptr;
    size_t cipher_size = 0;
    byte* authTag = nullptr;
    size_t authTagSz = 0;
    byte* authIn = nullptr;
    size_t authInSz = 0;
    std::string input_file = "Prueba.png"; // Cambiar según el archivo de prueba
    std::string decrypted_file = "Prueba_decrypted.png";

    satellite.encryptMessage(satellite.keySession, input_file, &cipher, &cipher_size, &authTag, &authTagSz, &authIn, &authInSz);
    earth_base.decryptMessage(earth_base.keySession, cipher, cipher_size, authTag, authTagSz, authIn, authInSz, decrypted_file);

    // Liberar memoria
    delete[] cipher;
    delete[] authTag;
    delete[] authIn;

    return 0;
}