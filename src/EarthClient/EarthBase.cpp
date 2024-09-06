#include "EarthBase.h"
#include <wolfssl/ssl.h>
#include <iostream>
#include <string>
#include <algorithm>
#include <wolfssl/wolfcrypt/aes.h>

std::string divideLargeNumber(const std::string &product, const std::string &primeStr);
EarthBase::EarthBase(const std::string &input_path,const std::string &output_path) : CryptoUser(input_path, output_path) {}

unsigned int EarthBase::initializeEarthBase()
{
	std::cout << "Base iniciada";
	return 1;
}

static void intToByteArray(int value, byte arr[4]) {
    for (int i = 0; i < 4; ++i) {
        arr[i] = (value >> (i * 8)) & 0xFF;  
    }
}

/**
 * @brief Recibe el hint del servidor.
 *
 * @return unsigned int Tamaño de la clave PSK si el hint es reconocido, 0 en caso contrario.
 */
unsigned int EarthBase::receiveServerParams()
{
    
    // Step 0: Leer el tamaño del primo grande
    byte* readLargeNumberLen = readBytes(sizeof(size_t));
    
    size_t largeNumberLen;
    std::memcpy(&largeNumberLen, reinterpret_cast<const char*>(readLargeNumberLen), sizeof(size_t));

    
    // Step 1: Leer parametros para desecriptar el primo grande
    byte* iv = readBytes(12);
    byte* authTag = readBytes(16);
    

    // Step 2: Leer el primo grande cifrado
    byte* cipheredLargeNumber = readBytes(largeNumberLen);
    
    
    // Step 3: Leer el hint del servidor
    byte* serverHint = readBytes(18);
    
    
    std::string decipherLargeNumber = decryptParams(cipheredLargeNumber, largeNumberLen, iv, authTag);

    std::string randomNumberStr = divideLargeNumber(decipherLargeNumber, getPrime());

    
    

    int recoveredSecret = std::stoi(randomNumberStr);
    intToByteArray(recoveredSecret, randomNumber);

	return 0;
}


std::string EarthBase::decryptParams(byte ciphertext[], size_t plaintextLen, byte iv[12], byte authTag[16]) {

    Aes aes;
    if (wc_AesGcmSetKey(&aes, pskKey, sizeof(pskKey)) != 0) {
        std::cerr << "Error al establecer la clave AES-GCM" << std::endl;
        wolfSSL_Cleanup();
    }
    byte decryptedText[plaintextLen];
    if (int pr = wc_AesGcmDecrypt(&aes, decryptedText, ciphertext, plaintextLen, iv, 12, authTag, 16, nullptr, 0) != 0) {
        std::cerr << "Error al desencriptar los datos: " << pr << std::endl;
        
        wolfSSL_Cleanup();

    }
    std::string decryptedString(reinterpret_cast<char*>(decryptedText), plaintextLen);

    return decryptedString;

}

byte* EarthBase::readBytes(size_t size) {
    
    byte* buffer = new byte[size];

    
    this->cipher_suite->infile.read(reinterpret_cast<char*>(buffer), size);
    this->cipher_suite->file_size -= size;

    return  buffer;
}


bool isGreaterOrEqual(const std::string &a, const std::string &b) {
    if (a.size() != b.size())
        return a.size() > b.size();
    return a >= b;
}


std::string subtractLargeNumbers(const std::string &a, const std::string &b) {
    std::string result;
    int carry = 0;
    int diff;

    for (int i = 0; i < a.size(); i++) {
        int digitA = a[a.size() - 1 - i] - '0';
        int digitB = (i < b.size() ? b[b.size() - 1 - i] - '0' : 0);
        
        diff = digitA - digitB - carry;
        if (diff < 0) {
            diff += 10;
            carry = 1;
        } else {
            carry = 0;
        }
        result.push_back(diff + '0');
    }
    
    while (result.size() > 1 && result.back() == '0') {
        result.pop_back();
    }

    std::reverse(result.begin(), result.end());
    return result;
}


std::string divideLargeNumber(const std::string &product, const std::string &primeStr) {
    std::string result;
    std::string current = "";

    for (char digit : product) {
        current += digit;

        current.erase(0, std::min(current.find_first_not_of('0'), current.size() - 1));

        int quotient = 0;
        while (isGreaterOrEqual(current, primeStr)) {
            current = subtractLargeNumbers(current, primeStr);
            quotient++;
        }

        result.push_back(quotient + '0');
    }
    
    result.erase(0, std::min(result.find_first_not_of('0'), result.size() - 1));

    return result.empty() ? "0" : result;
}



