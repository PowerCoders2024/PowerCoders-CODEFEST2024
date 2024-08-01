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

// Función para obtener el uso máximo de memoria residente (en kilobytes)
long getPeakRSS() {
	struct rusage r_usage;
	getrusage(RUSAGE_SELF, &r_usage);
	return r_usage.ru_maxrss;  // Valor en kilobytes
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
	if (serverExchangeHint > 0) {
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

		// TODO: escribir las llaves en archivo
		const std::string filename = "shared_key.bin";
		std::ofstream file(filename, std::ios::binary);
		if (!file) {
			std::cerr << "Error opening file for writing: " << filename << std::endl;
			return;
		}

		// Escribir el tamaño y los datos de la clave compartida
		file.write(reinterpret_cast<const char*>(earth_base.keySession), 32);
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

	byte shared_key[32];

	std::ifstream file("shared_key.bin", std::ios::binary);
	if (!file) {
		std::cerr << "Error opening file for reading: " << "shared_key.bin" << std::endl;
		return;
	}

	// Leer el archivo en el buffer de clave compartida
	file.read(reinterpret_cast<char*>(shared_key), 32);
	if (!file) {
		std::cerr << "Error reading from file: " << "shared_key.bin" << std::endl;
	}

	// Ajustar el tamaño de la clave compartida leída
	// word32& sharedKeySize = static_cast<word32>(file.gcount());

	file.close();

	if (remove("shared_key.bin") != 0) {
		std::cerr << "Error deleting file: " << "shared_key.bin" << std::endl;
	} else {
		std::cout << "File " << "shared_key.bin" << " deleted successfully" << std::endl;
	}

	/* earth_base.setKeySession(*pubEarth); */

	earth_base.decryptMessage(shared_key, input_path, output_path);
	std::cout << "Decryption completed" << std::endl;

	std::cout << "Decrypted image" << std::endl;
}
