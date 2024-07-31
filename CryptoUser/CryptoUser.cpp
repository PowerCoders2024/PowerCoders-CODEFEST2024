//
// Created by danny on 7/28/24.
//

#include "CryptoUser.h"
#include "../CipherSuite.h"
byte CryptoUser::pskKey[16] = {0};
CryptoUser::CryptoUser() {
    // std::cout << "Claves generadas correctamente" << std::endl;
    // this->cipher_suite.keyGenerator(this->priv );
    // Generar PSK si no se ha generado aún
    if (pskKey[0] == 0) {
        this->cipher_suite.PSKKeyGenerator(pskKey, sizeof(pskKey));
    }
}

void CryptoUser::initializeCryptoUser() {
    std::cout << "Suite iniciada" << std::endl;
    this->cipher_suite.initializeCipherSuite();
    std::cout << "Claves generadas correctamente" << std::endl;
    this->cipher_suite.keyGenerator(this->priv);
}

ecc_key CryptoUser::getPub() const {
    return this->priv;
}

void CryptoUser::setKeySession(ecc_key userPub) {
    std::cout << keySessionSz << std::endl;
    std::cout << "Shared key:" << wc_ecc_shared_secret(&priv, &userPub, this->keySession, &this->keySessionSz) <<
            std::endl;
    // Copia a la llave de la session los ultimos 16 bytes
    memcpy(keySession + 16, pskKey, 16);

}

void CryptoUser::encryptMessage(byte key[], const std::string &input_path, byte **cipher, size_t *cipher_size,
                                byte **authTag,
                                size_t *authTagSz, byte **authIn, size_t *authInSz) {
    this->cipher_suite.encryptAES(key, input_path);
    *cipher = this->cipher_suite.cipher;
    *cipher_size = this->cipher_suite.cipher_size;
    *authTag = this->cipher_suite.authTag;
    *authTagSz = this->cipher_suite.authTagSz;
    *authIn = this->cipher_suite.authIn;
    *authInSz = this->cipher_suite.authInSz;
}

void CryptoUser::decryptMessage(byte key[], byte *cipher, size_t ciphSzs, byte *authTag, size_t authTagSz, byte *authIn,
                                size_t authInSz) {
    this->cipher_suite.decryptAES(key, cipher, ciphSzs, authTag, authTagSz, authIn, authInSz);
}
