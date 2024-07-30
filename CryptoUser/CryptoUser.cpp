#include "CryptoUser.h"
#include "../CipherSuite.h"

CryptoUser::CryptoUser() {
    std::cout << "Claves generadas correctamente" << std::endl;
    this->cipher_suite.keyGenerator(this->priv);
}

ecc_key CryptoUser::getPub() const {
    return this->priv;
}

void CryptoUser::setKeySession(ecc_key userPub) {
    std::cout << "Shared key: " << wc_ecc_shared_secret(&priv, &userPub, this->keySession, &this->keySessionSz) << std::endl;
}

void CryptoUser::encryptMessage(byte key[], const std::string &input_path, const std::string &output_path) {
    this->cipher_suite.encryptAES(key, input_path, output_path);
}

void CryptoUser::decryptMessage(byte key[], const std::string &input_path, const std::string &output_path) {
    this->cipher_suite.decryptAES(key, input_path, output_path);
}
