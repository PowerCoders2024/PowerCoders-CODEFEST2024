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
    std::string input_file = "original.png"; // Cambiar según el archivo de prueba
    std::string encrypted_file = "original_encrypted.bin";
    std::string decrypted_file = "original_decrypted.png";

    satellite.encryptMessage(satellite.keySession, input_file, &cipher, &cipher_size, &authTag, &authTagSz, &authIn, &authInSz);
    if (cipher_size > 0) {
        earth_base.decryptMessage(earth_base.keySession, cipher, cipher_size, authTag, authTagSz, authIn, authInSz, decrypted_file);
    } else {
        std::cout << "Encryption failed, cipher_size is 0." << std::endl;
    }

    // Guardar el archivo cifrado (opcional para depuración)
    if (cipher_size > 0) {
        std::ofstream encrypted_out(encrypted_file, std::ios::binary);
        encrypted_out.write(reinterpret_cast<char*>(cipher), cipher_size);
        encrypted_out.close();
    }

    // Liberar memoria
    delete[] cipher;
    delete[] authTag;
    delete[] authIn;

    return 0;
}
