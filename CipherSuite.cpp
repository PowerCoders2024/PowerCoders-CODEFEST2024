#include "CipherSuite.h"
#include <fstream> 

CipherSuite::CipherSuite() {
    // Inicialización del constructor
    std::cout << "cipher init" << std::endl;

    byte ivGen[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
               0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    std::memcpy(this->iv, ivGen, 16);

    wc_InitRng(&this->rng);

}

void CipherSuite::keyGenerator(ecc_key& key) {
    wc_ecc_init(&key);                
    wc_ecc_set_rng(&key, &this->rng);
    wc_ecc_make_key(&this->rng, 32, &key);  

}

void CipherSuite::encryptAES(byte key[], const std::string &input_path, const std::string &output_path) {
  

    wc_AesInit(&this->aes, NULL, 0);
    wc_AesGcmSetKey(&this->aes, key, 32);

    std::ifstream infile(input_path, std::ios::binary);
    std::ofstream outfile(output_path, std::ios::binary);

    const size_t block_size = AES_BLOCK_SIZE * 50;
    byte plain[block_size];
    byte cipher[block_size];

    while (infile.read(reinterpret_cast<char*>(plain), block_size)) {
        size_t read_size = infile.gcount();
        int ret = wc_AesGcmEncrypt(&this->aes, cipher, plain, read_size, this->iv, sizeof(this->iv), this->authTag,
                         sizeof(this->authTag), this->authIn, sizeof(this->authIn));
        if (ret == 0) {
            outfile.write(reinterpret_cast<char*>(cipher), read_size);
        } else {
            std::cout << "Encryption error: " << ret << std::endl;
            break;
        }
    }
}

void CipherSuite::decryptAES(byte key[], const std::string &input_path, const std::string &output_path) {
    wc_AesInit(&this->aes, NULL, 0);
    wc_AesGcmSetKey(&this->aes, key, 32);

    std::ifstream infile(input_path, std::ios::binary);
    std::ofstream outfile(output_path, std::ios::binary);

    const size_t block_size = AES_BLOCK_SIZE * 50;
    byte cipher[block_size];
    byte decrypted[block_size];

    while (infile.read(reinterpret_cast<char*>(cipher), block_size)) {
        size_t read_size = infile.gcount();
        int ret = wc_AesGcmDecrypt(&this->aes, decrypted, cipher, read_size, this->iv, sizeof(this->iv),
                           this->authTag, sizeof(this->authTag), this->authIn, sizeof(this->authIn));
        if (ret == 0) {
            outfile.write(reinterpret_cast<char*>(decrypted), read_size);
        } else {
            std::cout << "Decryption error: " << ret << std::endl;
            break;
        }
    }
}