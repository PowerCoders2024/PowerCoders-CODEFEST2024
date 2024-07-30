#include "CipherSuite.h"
#include <fstream>
#include <sstream>

CipherSuite::CipherSuite() {
    std::cout << "cipher init" << std::endl;

    byte ivGen[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    std::memcpy(this->iv, ivGen, 16);

    wc_InitRng(&this->rng);
}

void CipherSuite::keyGenerator(ecc_key &key) {
    wc_ecc_init(&key);
    wc_ecc_set_rng(&key, &this->rng);
    wc_ecc_make_key(&this->rng, 32, &key);
}

void CipherSuite::encryptAES(byte key[], const std::string &input_path, const std::string &output_path) {
    wc_AesInit(&this->aes, NULL, 0);
    wc_AesGcmSetKey(&this->aes, key, 32);

    // Tamaño de bloque para el procesamiento
    const size_t block_size = 4096; // Puedes ajustar este tamaño según sea necesario

    // Abrir archivos de entrada y salida
    std::ifstream infile(input_path, std::ios::binary);
    std::ofstream outfile(output_path, std::ios::binary);

    if (!infile.is_open() || !outfile.is_open()) {
        std::cout << "Error opening files." << std::endl;
        return;
    }

    // Buffer para el bloque de datos
    byte buffer[block_size];
    byte cipher_block[block_size];
    size_t read_size;

    while (infile.read(reinterpret_cast<char*>(buffer), block_size) || (read_size = infile.gcount())) {
        read_size = infile.gcount();

        // Cifrar bloque
        int ret = wc_AesGcmEncrypt(&this->aes, cipher_block, buffer, read_size,
                                   this->iv, sizeof(this->iv), this->authTag, sizeof(this->authTag),
                                   this->authIn, sizeof(this->authIn));
        if (ret != 0) {
            std::cout << "Encryption error: " << ret << std::endl;
            return;
        }

        // Escribir authTag y bloque cifrado
        outfile.write(reinterpret_cast<char*>(this->authTag), sizeof(this->authTag));
        outfile.write(reinterpret_cast<char*>(cipher_block), read_size);
    }

    infile.close();
    outfile.close();
}

void CipherSuite::decryptAES(byte key[], const std::string &input_path, const std::string &output_path) {
    wc_AesInit(&this->aes, NULL, 0);
    wc_AesGcmSetKey(&this->aes, key, 32);

    // Tamaño de bloque para el procesamiento
    const size_t block_size = 4096; // Puedes ajustar este tamaño según sea necesario

    // Abrir archivos de entrada y salida
    std::ifstream infile(input_path, std::ios::binary);
    std::ofstream outfile(output_path, std::ios::binary);

    if (!infile.is_open() || !outfile.is_open()) {
        std::cout << "Error opening files." << std::endl;
        return;
    }

    // Buffer para el bloque de datos
    byte buffer[block_size];
    byte decrypted_block[block_size];
    size_t read_size;

    while (infile.read(reinterpret_cast<char*>(this->authTag), sizeof(this->authTag)) && infile.read(reinterpret_cast<char*>(buffer), block_size)) {
        read_size = infile.gcount();

        // Descifrar bloque
        int ret = wc_AesGcmDecrypt(&this->aes, decrypted_block, buffer, read_size,
                                   this->iv, sizeof(this->iv), this->authTag, sizeof(this->authTag),
                                   this->authIn, sizeof(this->authIn));
        if (ret != 0) {
            std::cout << "Decryption error: " << ret << std::endl;
            return;
        }

        // Escribir bloque descifrado
        outfile.write(reinterpret_cast<char*>(decrypted_block), read_size);
    }

    infile.close();
    outfile.close();
}
