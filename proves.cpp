#include <iostream>
#include <chrono>
#include <sys/resource.h>
#include "EarthClient/EarthBase.h"
#include "SpaceServer/Satellite.h"

// Función para obtener el uso máximo de memoria residente (en kilobytes)
long getPeakRSS() {
    struct rusage r_usage;
    getrusage(RUSAGE_SELF, &r_usage);
    return r_usage.ru_maxrss; // Valor en kilobytes
}

int main() {
    // Tiempo de inicio
    auto start = std::chrono::high_resolution_clock::now();

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
    std::string input_file = "imp.jpg"; 
    std::string encrypted_file = "original_encrypted.bin";
    std::string decrypted_file = "imp_decrypted.jpg";

    satellite.encryptMessage(satellite.keySession, input_file, encrypted_file);
    std::cout << "Encryption completed" << std::endl;

    earth_base.decryptMessage(earth_base.keySession, encrypted_file, decrypted_file);
    std::cout << "Decryption completed" << std::endl;

    // Tiempo de fin
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;

    // Obtener uso de memoria
    long peakRSS = getPeakRSS();

    // Mostrar resultados
    std::cout << "Elapsed time: " << elapsed.count() << " seconds" << std::endl;
    std::cout << "Peak memory usage: " << peakRSS << " KB" << std::endl;

    return 0;
}
