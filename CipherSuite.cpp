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

void CipherSuite::encryptAES(byte key[], const std::string &input_path) {
    wc_AesInit(&this->aes, NULL, 0);
    wc_AesGcmSetKey(&this->aes, key, 32);

    // Leer archivo completo
    std::ifstream infile(input_path, std::ios::binary);
    if (!infile.is_open()) {
        std::cout << "Error opening input file." << std::endl;
        return;
    }
    std::ostringstream oss;
    oss << infile.rdbuf();
    std::string plain_data = oss.str();
    size_t plain_size = plain_data.size();

    // Preparar buffer para el cifrado
    this->cipher = new byte[plain_size];
    this->cipher_size = plain_size;

    // Cifrar datos completos
    int ret = wc_AesGcmEncrypt(&this->aes, this->cipher, (const byte*)plain_data.data(), plain_size,
                               this->iv, sizeof(this->iv), this->authTag, sizeof(this->authTag),
                               this->authIn, sizeof(this->authIn));
    if (ret != 0) {
        std::cout << "Encryption error: " << ret << std::endl;
        delete[] this->cipher;
        this->cipher = nullptr;
        this->cipher_size = 0;
        return;
    }

    this->authTagSz = sizeof(this->authTag);
    this->authInSz = sizeof(this->authIn);

    std::cout << "Encriptado correctamente" << std::endl;
}

void CipherSuite::decryptAES(byte key[], byte* cipher, size_t ciphSzs, byte* authTag, size_t authTagSz, byte* authIn, size_t authInSz, const std::string &output_path) {
    wc_AesInit(&this->aes, NULL, 0);
    wc_AesGcmSetKey(&this->aes, key, 32);

    // Preparar buffer para el descifrado
    byte* decrypted = new byte[ciphSzs];

    // Descifrar datos completos
    int ret = wc_AesGcmDecrypt(&this->aes, decrypted, cipher, ciphSzs, this->iv, sizeof(this->iv),
                               authTag, authTagSz, authIn, authInSz);
    if (ret != 0) {
        std::cout << "Decryption error: " << ret << std::endl;
        delete[] decrypted;
        return;
    }

    // Guardar datos descifrados en el archivo
    std::ofstream outfile(output_path, std::ios::binary);
    if (!outfile.is_open()) {
        std::cout << "Error opening output file." << std::endl;
        delete[] decrypted;
        return;
    }
    outfile.write(reinterpret_cast<char*>(decrypted), ciphSzs);
    outfile.close();

    delete[] decrypted;

    std::cout << "Desencriptado correctamente y guardado en " << output_path << std::endl;
}
