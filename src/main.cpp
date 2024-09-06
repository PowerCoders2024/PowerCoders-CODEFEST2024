#include <sys/resource.h>

#include <chrono>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>

#include "EarthClient/EarthBase.h"
#include "SpaceServer/Satellite.h"

void encrypt(const std::string& input_path, const std::string& output_path);
void decrypt(const std::string& input_path, const std::string& output_path);

long getPeakRSS() {
	struct rusage r_usage;
	getrusage(RUSAGE_SELF, &r_usage);
	return r_usage.ru_maxrss;  // Valor en kilobytes
}


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

static int byteArrayToInt(const byte arr[4]) {
    int value = 0;
    for (int i = 0; i < 4; ++i) {
        value |= arr[i] << (i * 8);  // Copiamos los bytes en orden little-endian
    }
    return value;
}

static void intToByteArray(int value, byte arr[4]) {
    for (int i = 0; i < 4; ++i) {
        arr[i] = (value >> (i * 8)) & 0xFF;  // Extraemos los bytes en orden little-endian
    }
}

void encrypt(const std::string& input_path, const std::string& output_path) {
	std::cout << "input_path=" << input_path << std::endl;
	std::cout << "output_path=" << output_path << std::endl;
	Satellite satellite(input_path, output_path);
	// El satelite inicializa la conexion
	satellite.initializeSatellite();
	// El satelite  prepara los parametros para que la base genere la llave secreta  derivada
	satellite.sendEncryptedParams();
	
    byte satelliteSecretKey[KEY_SIZE_256];
	int secretRandom = byteArrayToInt(satellite.randomBlock);
	byte recoveredBlock[4];
    intToByteArray(abs(secretRandom) % 10000000, recoveredBlock);

	// El satelite genera su llave secreta  derivada para cifrar la imagen
    satellite.derivePBKDF2Key(reinterpret_cast<const byte*>(Satellite::getSeed().c_str()),
                               Satellite::getSeed().size(),
                               recoveredBlock,
                               sizeof(recoveredBlock),
                               satelliteSecretKey, KEY_SIZE_256, 300);

	// Cifrar el contenido del archivo
	satellite.encryptMessage(satelliteSecretKey, input_path, output_path);
	std::cout << "Encryption completed" << std::endl;
	std::cout << "Encrypted image" << std::endl; 
	
}

void decrypt(const std::string& input_path, const std::string& output_path) {
	std::cout << "input_path=" << input_path << std::endl;
	std::cout << "output_path=" << output_path << std::endl;
	// La base  recibe los parametros para generar la llave secreta
	EarthBase earth_base(input_path, output_path);
	earth_base.receiveServerParams();
	
	byte baseSecretKey[KEY_SIZE_256];

	// La base genera su llave secreta derivada para descifrar la imagen
	int secretRandom = byteArrayToInt(earth_base.randomNumber);
	earth_base.derivePBKDF2Key(reinterpret_cast<const byte*>(EarthBase::getSeed().c_str()),
							   EarthBase::getSeed().size(),
							   earth_base.randomNumber,
							   sizeof(earth_base.randomNumber),
							   baseSecretKey, KEY_SIZE_256, 300);

	earth_base.decryptMessage(baseSecretKey, input_path, output_path);
	std::cout << "Decryption completed" << std::endl;

	std::cout << "Decrypted image" << std::endl;
	
}
