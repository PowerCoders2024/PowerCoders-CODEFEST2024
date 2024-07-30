#include <iostream>
#include "EarthClient/EarthBase.h"
#include "SpaceServer/Satellite.h"

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
    std::string input_file = "original5.jpg"; // Cambiar según el archivo de prueba
    std::string encrypted_file = "original_encrypted5.bin";
    std::string decrypted_file = "original_decrypted5.jpg";

    satellite.encryptMessage(satellite.keySession, input_file, encrypted_file);
    std::cout << "Encryption completed" << std::endl;

    earth_base.decryptMessage(earth_base.keySession, encrypted_file, decrypted_file);
    std::cout << "Decryption completed" << std::endl;

    return 0;
}
