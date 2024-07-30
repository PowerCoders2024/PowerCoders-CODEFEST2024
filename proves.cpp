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
    std::string input_file = "original.jpg"; // Cambiar según el archivo de prueba
    std::string encrypted_file = "original_encrypted.bin";
    std::string decrypted_file = "original_decrypted.jpg";

    satellite.encryptMessage(satellite.keySession, input_file, encrypted_file);
    std::cout << "Encryption completed" << std::endl;

    earth_base.decryptMessage(earth_base.keySession, encrypted_file, decrypted_file);
    std::cout << "Decryption completed" << std::endl;

    return 0;
}
