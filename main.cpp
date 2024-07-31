#include <iostream>
#include <string>
#include <cstdlib>
#include <fstream>
#include <chrono>
#include <sys/resource.h>
#include "EarthClient/EarthBase.h"
#include "SpaceServer/Satellite.h"

void encrypt(const std::string& input_path, const std::string& output_path);
void decrypt(const std::string& input_path, const std::string& output_path);

// Función para obtener el uso máximo de memoria residente (en kilobytes)
long getPeakRSS() {
    struct rusage r_usage;
    getrusage(RUSAGE_SELF, &r_usage);
    return r_usage.ru_maxrss; // Valor en kilobytes
}

EarthBase earth_base;
Satellite satellite; 

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Uso: " << argv[0] << " <operation> <input_path> <output_path>" << std::endl;
        return 1;
    }
    
    // Tiempo de inicio
    auto start = std::chrono::high_resolution_clock::now();

    std::string operation = argv[1];
    std::string input_path = argv[2];
    std::string output_path = argv[3];

    if (operation == "encrypt") {
        encrypt(input_path, output_path);
    } else if (operation == "decrypt") {
        decrypt(input_path, output_path);
    } else {
        std::cerr << "Operación no válida: " << operation << std::endl;
        return 1;
    }

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

void encrypt(const std::string& input_path, const std::string& output_path) {
    std::cout << "input_path=" << input_path << std::endl;
    std::cout << "output_path=" << output_path << std::endl;

    // Empieza la comunicacion
    std::cout << "Hello, World!" << std::endl;
    earth_base.initializeEarthBase();
    satellite.initializeSatellite();
    // El cliente recibe el hint del servidor
    unsigned int serverExchangeHint = earth_base.receiveServerHint(satellite);

    // Si el hint recibido es conocido, envia su identidad
    if (serverExchangeHint > 0 ) {
        // El cliente manda su identidad, y el servidor la autentica
        earth_base.sendIdentity(satellite);

        // Una vez autenticado, empieza la comparticion psk-ECCDH
        earth_base.initializeCryptoUser();
        satellite.initializeCryptoUser();

        // Compartir las llaves publicas entre si
        ecc_key pubEarth = earth_base.getPub();
        ecc_key pubSat = satellite.getPub();

        // Generar llave de sesion para cada uno
        earth_base.setKeySession(pubSat);
        satellite.setKeySession(pubEarth);

        //TODO: escribir las llaves en archivo
        const std::string filename = "shared_key.bin";
        std::ofstream file(filename, std::ios::binary);
        if (!file) {
            std::cerr << "Error opening file for writing: " << filename << std::endl;
            return;
        }

        // Exportar clave privada
        byte priv[8];
        word32 privSz = sizeof(priv);
        if (wc_ecc_export_private_only(&pubEarth, priv, &privSz) != 0) {
            std::cerr << "Failed to export private key" << std::endl;
            return;
        }

        // Exportar clave pública
        byte pub[32];
        word32 pubSz = sizeof(pub);
        if (wc_ecc_export_x963(&pubEarth, pub, &pubSz) != 0) {
            std::cerr << "Failed to export public key" << std::endl;
            return;
        }

        // Escribir el tamaño y los datos de la clave privada
        file.write(reinterpret_cast<const char*>(&privSz), sizeof(privSz));
        file.write(reinterpret_cast<const char*>(priv), privSz);

        // Escribir el tamaño y los datos de la clave pública
        file.write(reinterpret_cast<const char*>(&pubSz), sizeof(pubSz));
        file.write(reinterpret_cast<const char*>(pub), pubSz);

        if (!file) {
            std::cerr << "Error writing to file: " << filename << std::endl;
        }

        file.close();

        // Cifrar el contenido del archivo
        satellite.encryptMessage(satellite.keySession, input_path, output_path);
        std::cout << "Encryption completed" << std::endl;

    std::cout << "Encrypted image" << std::endl;
}
}

void decrypt(const std::string& input_path, const std::string& output_path) {
    std::cout << "input_path=" << input_path << std::endl;
    std::cout << "output_path=" << output_path << std::endl;
    
    //Leer file con (Shared key o Llave )
    const std::string filename = "shared_key.bin";
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "Error opening file for reading: " << filename << std::endl;
    }

    // Leer el tamaño y los datos de la clave privada
    word32 privSz;
    file.read(reinterpret_cast<char*>(&privSz), sizeof(privSz));
    byte* priv = new byte[privSz];
    file.read(reinterpret_cast<char*>(priv), privSz);

    // Leer el tamaño y los datos de la clave pública
    word32 pubSz;
    file.read(reinterpret_cast<char*>(&pubSz), sizeof(pubSz));
    byte* pub = new byte[pubSz];
    file.read(reinterpret_cast<char*>(pub), pubSz);

    // Importar clave privada
    ecc_key *pubEarth; 
    if (wc_ecc_import_private_key(priv, privSz, pub, pubSz, pubEarth) != 0) {
        std::cerr << "Failed to import private key" << std::endl;
        // delete[] priv;
        // delete[] pub;
    }

    file.close();

    earth_base.setKeySession(*pubEarth);

    earth_base.decryptMessage(earth_base.keySession, input_path, output_path);
    std::cout << "Decryption completed" << std::endl;

    std::cout << "Decrypted image" << std::endl;
}
