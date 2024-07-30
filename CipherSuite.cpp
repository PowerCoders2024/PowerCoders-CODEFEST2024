//
// Created by danny on 7/28/24.
//

#include "CipherSuite.h"

CipherSuite::CipherSuite()
{
    // Inicialización del constructor
    std::cout << "cipher init" << std::endl;

    byte ivGen[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    std::memcpy(this->iv, ivGen, 16);

    wc_InitRng(&this->rng);
}

void CipherSuite::keyGenerator(ecc_key &key)
{
    // initialize rng
    wc_ecc_init(&key); // initialize key
    wc_ecc_set_rng(&key, &this->rng);
    wc_ecc_make_key(&this->rng, 32, &key); // make public key
}

void CipherSuite::encryptAES(byte key[], unsigned char *block, size_t block_size)
{
    wc_AesInit(&this->aes, NULL, 0);
    wc_AesGcmSetKey(&this->aes, key, 32);

    // Declaracion atributos de mensaje cifrado con su respectivo tamano
    this->cipher = new byte[block_size];
    this->cipher_size = block_size;

    int ret = wc_AesGcmEncrypt(&this->aes, this->cipher, block, this->cipher_size, this->iv, sizeof(this->iv), this->authTag, sizeof(this->authTag), this->authIn, sizeof(this->authIn));

    this->authTagSz = sizeof(this->authTag);
    this->authInSz = sizeof(this->authIn);

    if (ret == 0)
    {
        std::cout << "Encriptado correctamente" << std::endl;
    }
    else
    {
        std::cout << "error encriptando: " << ret;
    }
}

void CipherSuite::decryptAES(byte key[], byte *block, size_t ciphSzs, byte *authTag, size_t authTagSz, byte *authIn, size_t authInSz)
{
    wc_AesInit(&this->aes, NULL, 0);
    wc_AesGcmSetKey(&this->aes, key, 32);

    int ret = wc_AesGcmDecrypt(&this->aes, block, block, ciphSzs, this->iv, sizeof(this->iv), authTag, authTagSz, authIn, authInSz);

    if (ret == 0)
    {
        std::cout << "Desencriptado correctamente: " << std::endl;
    }
    else
    {
        std::cout << "error desencriptando: " << ret << std::endl;
    }
}
